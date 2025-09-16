/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (c) 2004-2007 Silicon Graphics, Inc.  All Rights Reserved.
 * Copyright 2009, 2014 Cray Inc. All Rights Reserved
 * Copyright 2016-2020 Arm Inc. All Rights Reserved
 * Copyright (c) 2016-2018 Nathan Hjelm <hjelmn@cs.unm.edu>
 */

/*
 * Cross Partition Memory (XPMEM) PFN support.
 */

#include <linux/efi.h>
#include <linux/pagemap.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include "xpmem_internal.h"
#include "xpmem_private.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h>
#endif

/* #of pages rounded up that vaddr and size occupy */
#undef num_of_pages
#define num_of_pages(v, s) \
		(((offset_in_page(v) + (s)) + (PAGE_SIZE - 1)) >> PAGE_SHIFT)

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,17,0)
#if defined(RHEL_RELEASE_CODE)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,14,0) && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(9,1)
  /* */
#endif
#else
#define pde_data(inode) PDE_DATA(inode)
#endif
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
#define pde_data(inode) ((PDE(inode)->data))
#endif

#if CONFIG_HUGETLB_PAGE

#if (defined(CONFIG_ARM64) || defined(CONFIG_ARM))
#define pmd_is_huge(p) pmd_sect(p)
#if (defined(pud_sect))
#define pud_is_huge(p) pud_sect(p)
#else
#define pud_is_huge(p) (0)
#endif
#elif defined(CONFIG_X86)
#define pmd_is_huge(p) pmd_leaf(p)
#define pud_is_huge(p) pud_leaf(p)
#elif defined(CONFIG_PPC)
#define pmd_is_huge(p) pmd_large(p)
#define pud_is_huge(p) ((pud_val(p) & 0x3) != 0x0)
#else
#error Unsuported architecture
#endif

#ifndef task_is_stopped
#define task_is_stopped(task) ((task)->state == TASK_STOPPED)
#endif

/*
 * Take the provided ptl, and make sure the pte it protects didn't go away
 * on us.  If it did, unlock and return NULL.   Otherwise, populate ptlp
 * and return the locked pte.
 */
static pte_t *
xpmem_pte_lock(pte_t *pte, spinlock_t *ptl, spinlock_t **ptlp)
{
	pte_t *ret = NULL;
	spin_lock(ptl);

	if (pte_none(*pte)) {
		spin_unlock(ptl);
	} else if (pte_present(*pte)) {
		*ptlp = ptl;
		ret = pte;
	/*
	 * Any caller who requested the lock does NOT want to get back
	 * a non-present PTE, and they shouldn't be able to.  BUG.
	 */
	} else
		DBUG_ON(!pte_present(*pte));

	return ret;
}

/* Just a wrapper for spin_unlock, to keep the code looking consistent */

static void
xpmem_pte_unlock(spinlock_t *ptl)
{
	spin_unlock(ptl);
}

static pte_t *
xpmem_trans_hugepage_pte(struct mm_struct *mm, u64 vaddr, u64 *offset)
{
	struct vm_area_struct *vma;
	u64 address;
	pte_t *pte = NULL;
	u64 page_size = HPAGE_PMD_SIZE;

	vma = find_vma(mm, vaddr);
	if (!vma)
		return NULL;

	address = vaddr & HPAGE_PMD_MASK;

	if (offset)
		*offset = (vaddr & (page_size - 1)) & PAGE_MASK;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))
	pte = p_huge_pte_offset(mm, address, page_size);
#else
	pte = p_huge_pte_offset(mm, address);
#endif

	if (!pte || pte_none(*pte))
		return NULL;

	return pte;
}

static pte_t *
xpmem_hugetlb_pte(struct mm_struct *mm, u64 vaddr, u64 *offset, spinlock_t **ptlp)
{
	struct vm_area_struct *vma;
	u64 address;
	pte_t *pte;

	vma = find_vma(mm, vaddr);
	if (!vma)
		return NULL;

	if (likely(is_vm_hugetlb_page(vma))) {
		struct hstate *hs = hstate_vma(vma);
		address = vaddr & huge_page_mask(hs);

		if (offset)
			*offset = (vaddr & (huge_page_size(hs) - 1)) & PAGE_MASK;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)) || defined(CONFIG_CRAY_MRT)
		pte = p_huge_pte_offset(mm, address, huge_page_size(hs));
#else
		pte = p_huge_pte_offset(mm, address);
#endif

		if (!pte || pte_none(*pte))
			return NULL;

		/* Take the ptl and give the caller a pointer if they asked for it */
		if (ptlp)
			return xpmem_pte_lock(pte, huge_pte_lock(hs, mm, pte), ptlp);

		return pte;
	}

	/*
	 * We should never enter this area since xpmem_hugetlb_pte() is only
	 * called if {pgd,pud,pmd}_large() is true
	 */
	BUG();
}
#endif

/*
 * Given an address space and a virtual address return a pointer to its
 * pte if one is present.
 *
 * offset - Location to store the PTE offset in a huge page.
 * size   - Used to store the level at which an invalid entry was found
 *          in the page table.  This is only used by xpmem_unpin_pages.
 * ptlp	  - Location to store the page table lock pointer for the PTE,
 *          if a PTE is found.  If a ptl pointer is requested, this
 *          function will return with the ptl locked.
 *
 * This function was consolidated together from the former xpmem_vaddr_to_pte_offset
 * and xpmem_vaddr_to_pte_size functions, and had locking introduced into it
 * to fix some race conditions that could occur between xpmem_fault_handler and
 * various other bits of kernel functionality, most notably, page migration.
 * The largest part of the problem was that we were reading things out of the
 * page tables without locking the PTE pages beforehand, which meant that we
 * could accidentally grab a NULL PFN in some situations, because the PFN we
 * were trying to read had temporarily been unmapped from the source process's
 * page table.
 */
static pte_t *
xpmem_vaddr_to_pte(struct mm_struct *mm, u64 vaddr, u64 *offset, u64 *size, spinlock_t **ptlp)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
	p4d_t *p4d;
#endif

	if (offset)
		/* if vaddr is not in a huge page it will always be at
		 * offset 0 in the page. */
		*offset = 0;

	pgd = pgd_offset(mm, vaddr);
	if (!pgd_present(*pgd)) {
		if (size)
			*size = PGDIR_SIZE;
		return NULL;
	}
	/* NTH: there is no pgd_large in kernel 3.13. from what I have read
	 * the pte is never folded into the pgd. */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
	/* 4.12+ has another level to the page tables */
	p4d = p4d_offset(pgd, vaddr);
	if (!p4d_present(*p4d)) {
		if (size)
			*size = P4D_SIZE;
		return NULL;
        }

	pud = pud_offset(p4d, vaddr);
#else
	pud = pud_offset(pgd, vaddr);
#endif
	if (!pud_present(*pud)) {
		if (size)
			*size = PUD_SIZE;
		return NULL;
	}
#if CONFIG_HUGETLB_PAGE
	else if (pud_is_huge(*pud)) {
		/* pte folded into the pmd which is folded into the pud */
		return xpmem_hugetlb_pte(mm, vaddr, offset, ptlp);
	}
#endif

	pmd = pmd_offset(pud, vaddr);
	if (!pmd_present(*pmd)) {
		if (size)
			*size = PMD_SIZE;
		return NULL;
	}
#if CONFIG_HUGETLB_PAGE
	else if (pmd_is_huge(*pmd)) {
		if (!pmd_trans_huge(*pmd)) {
			return xpmem_hugetlb_pte(mm, vaddr, offset, ptlp);
		} else {
			spinlock_t *slptr = pmd_lock(mm,pmd);

			if (pmd_trans_huge(*pmd)) {
				pte = xpmem_trans_hugepage_pte(mm, vaddr, offset);
				if (pte && ptlp) {
					*ptlp = slptr;
					return pte;
				}
				spin_unlock(slptr);
				return pte;
			} else {
#ifdef CONFIG_ARCH_ENABLE_THP_MIGRATION
				if (is_pmd_migration_entry(*pmd)) {
					spin_unlock(slptr);
					return NULL;
				}
#endif
				spin_unlock(slptr);
			}
		}
	}
#endif

#if defined(RHEL_RELEASE_CODE)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,14,0) && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(9,4)
	pte = pte_offset_kernel(pmd, vaddr);
#else
	pte = pte_offset_map(pmd, vaddr);
#endif
#else /* non-RHEL */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	pte = pte_offset_kernel(pmd, vaddr);
#else
	pte = pte_offset_map(pmd, vaddr);
#endif
#endif
	if (!pte || pte_none(*pte)) {
		if (size)
			*size = PAGE_SIZE;
		return NULL;
	}

	if (ptlp)
		return xpmem_pte_lock(pte, pte_lockptr(mm, pmd), ptlp);

	return pte;
}

/*
 * Fault in and pin a single page for the specified task and mm.
 */
static int
xpmem_pin_page(struct xpmem_thread_group *tg, struct task_struct *src_task,
		struct mm_struct *src_mm, u64 vaddr, unsigned long *pfn)
{
	int ret;
	struct page *page;
	struct vm_area_struct *vma;
	cpumask_t saved_mask = CPU_MASK_NONE;
	int foll_write;

	vma = find_vma(src_mm, vaddr);
	if (!vma || vma->vm_start > vaddr)
		return -ENOENT;

	/* don't pin pages in address ranges attached from other thread groups */
	if (xpmem_is_vm_ops_set(vma))
		return -ENOENT;

	/*
	 * get_user_pages() may have to allocate pages on behalf of
	 * the source thread group. If so, we want to ensure that pages
	 * are allocated near the source thread group and not the current
	 * thread calling get_user_pages(). Since this does not happen when
	 * the policy is node-local (the most common default policy),
	 * we might have to temporarily switch cpus to get the page
	 * placed where we want it.
	 *
	 */
	if (xpmem_vaddr_to_pte(src_mm, vaddr, NULL, NULL, NULL) == NULL &&
	    cpu_to_node(task_cpu(current)) != cpu_to_node(task_cpu(src_task))) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
		saved_mask = current->cpus_mask;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
                saved_mask = current->cpus_mask;
#else
		saved_mask = current->cpus_allowed;
#endif
		set_cpus_allowed_ptr(current, cpumask_of(task_cpu(src_task)));
	}

	/* Map with write permissions only if source VMA is writeable */
	foll_write = (vma->vm_flags & VM_WRITE) ? FOLL_WRITE : 0;

#if defined(RHEL_RELEASE_CODE)
#if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(9,6) 
#define RHEL_USE_GUP_6 1
#endif
#endif

	/* get_user_pages()/get_user_pages_remote() faults and pins the page */
#if   LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0) || defined(RHEL_USE_GUP_6)
	ret = get_user_pages_remote (src_mm, vaddr, 1, foll_write, &page, NULL);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
	ret = get_user_pages_remote (src_mm, vaddr, 1, foll_write, &page, NULL,
				     NULL);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	ret = get_user_pages_remote (src_task, src_mm, vaddr, 1, foll_write,
				     &page, NULL, NULL);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
	ret = get_user_pages_remote (src_task, src_mm, vaddr, 1, foll_write,
				     &page, NULL);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
	ret = get_user_pages_remote (src_task, src_mm, vaddr, 1, foll_write, 0,
				     &page, NULL);
#else
	ret = get_user_pages (src_task, src_mm, vaddr, 1, foll_write, 0, &page,
			      NULL);
#endif
	if (!cpumask_empty(&saved_mask))
		set_cpus_allowed_ptr(current, &saved_mask);

	if (ret == 1) {
		*pfn = page_to_pfn(page);
		atomic_inc(&tg->n_pinned);
		atomic_inc(&xpmem_my_part->n_pinned);
		ret = 0;
	}

	return ret;
}

/*
 * Unpin all pages in the given range for the specified mm.
 */
void
xpmem_unpin_pages(struct xpmem_segment *seg, struct mm_struct *mm,
			u64 vaddr, size_t size)
{
	int n_pgs = num_of_pages(vaddr, size);
	int n_pgs_unpinned = 0;
	struct page *page;
	u64 pfn, vsize = 0;
	pte_t *pte = NULL;
	spinlock_t *ptl;

	XPMEM_DEBUG("vaddr=%llx, size=%lx, n_pgs=%d", vaddr, size, n_pgs);

	/* Round down to the nearest page aligned address */
	vaddr &= PAGE_MASK;

	while (n_pgs > 0) {
		pte = xpmem_vaddr_to_pte(mm, vaddr, NULL, &vsize, &ptl);

		if (pte) {
			DBUG_ON(!pte_present(*pte));
			pfn = pte_pfn(*pte);
			XPMEM_DEBUG("pfn=%llx, vaddr=%llx, n_pgs=%d",
					pfn, vaddr, n_pgs);
			page = virt_to_page(__va(pfn << PAGE_SHIFT));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
			put_page(page);
#else
			page_cache_release(page);
#endif
			n_pgs_unpinned++;
			vaddr += PAGE_SIZE;
			n_pgs--;

			xpmem_pte_unlock(ptl);
		} else {
			/*
			 * vsize holds the memory size we know isn't mapped,
			 * based on which level of the page tables had an
			 * invalid entry. We round up to the nearest address
			 * that could have valid pages and find how many pages
			 * we skipped.
			 */
			vsize = ((vaddr + vsize) & (~(vsize - 1)));
			n_pgs -= (vsize - vaddr)/PAGE_SIZE;
			vaddr = vsize;
		}
	}

	atomic_sub(n_pgs_unpinned, &seg->tg->n_pinned);
	atomic_add(n_pgs_unpinned, &xpmem_my_part->n_unpinned);
}

/*
 * Given a virtual address and XPMEM segment, pin the page.
 */
int
xpmem_ensure_valid_PFN(struct xpmem_segment *seg, u64 vaddr, unsigned long *pfn)
{
  int ret;
	struct xpmem_thread_group *seg_tg = seg->tg;

	/* the seg may have been marked for destruction while we were down() */
        if (seg->flags & XPMEM_FLAG_DESTROYING)
		return -ENOENT;

	/* pin PFN */
	ret = xpmem_pin_page(seg_tg, seg_tg->group_leader, seg_tg->mm, vaddr, pfn);

	return ret;
}

/*
 * Return the PFN for a given virtual address.
 */
u64
xpmem_vaddr_to_PFN(struct mm_struct *mm, u64 vaddr)
{
	pte_t *pte;
	u64 pfn, offset;
	spinlock_t *ptl;

	pte = xpmem_vaddr_to_pte(mm, vaddr, &offset, NULL, &ptl);
	if (pte == NULL)
		return 0;
	DBUG_ON(!pte_present(*pte));

	pfn = pte_pfn(*pte) + (offset >> PAGE_SHIFT);
	xpmem_pte_unlock(ptl);

	return pfn;
}

/*
 * Recall all PFNs belonging to the specified segment that have been
 * accessed by other thread groups.
 */
static void
xpmem_recall_PFNs(struct xpmem_segment *seg)
{
	DBUG_ON(atomic_read(&seg->refcnt) <= 0);
	DBUG_ON(atomic_read(&seg->tg->refcnt) <= 0);

	spin_lock(&seg->lock);
	if (seg->flags & (XPMEM_FLAG_DESTROYING | XPMEM_FLAG_RECALLINGPFNS)) {
		spin_unlock(&seg->lock);

		xpmem_wait_for_seg_destroyed(seg);
		return;
	}
	seg->flags |= XPMEM_FLAG_RECALLINGPFNS;
	spin_unlock(&seg->lock);

	xpmem_seg_down_write(seg);

	/* unpin pages and clear PTEs for each attachment to this segment */
	xpmem_clear_PTEs(seg);

	spin_lock(&seg->lock);
	seg->flags &= ~XPMEM_FLAG_RECALLINGPFNS;
	spin_unlock(&seg->lock);

	xpmem_seg_up_write(seg);
}

/*
 * Recall all PFNs belonging to the specified thread group's XPMEM segments
 * that have been accessed by other thread groups.
 */
static void
xpmem_recall_PFNs_of_tg(struct xpmem_thread_group *seg_tg)
{
	struct xpmem_segment *seg;

	read_lock(&seg_tg->seg_list_lock);
	list_for_each_entry(seg, &seg_tg->seg_list, seg_list) {
		if (!(seg->flags & XPMEM_FLAG_DESTROYING)) {
			xpmem_seg_ref(seg);
			read_unlock(&seg_tg->seg_list_lock);

			xpmem_recall_PFNs(seg);

			read_lock(&seg_tg->seg_list_lock);
			if (list_empty(&seg->seg_list)) {
				/* seg was deleted from seg_tg->seg_list */
				xpmem_seg_deref(seg);
				seg = list_entry(&seg_tg->seg_list,
						 struct xpmem_segment,
						 seg_list);
			} else
				xpmem_seg_deref(seg);
		}
	}
	read_unlock(&seg_tg->seg_list_lock);
}

int
xpmem_block_recall_PFNs(struct xpmem_thread_group *tg, int wait)
{
	int value, returned_value;

	while (1) {
		if (waitqueue_active(&tg->allow_recall_PFNs_wq))
			goto wait;

		value = atomic_read(&tg->n_recall_PFNs);
		while (1) {
			if (unlikely(value > 0))
				break;

			returned_value = atomic_cmpxchg(&tg->n_recall_PFNs,
							value, value - 1);
			if (likely(returned_value == value))
				break;

			value = returned_value;
		}

		if (value <= 0)
			return 0;
wait:
		if (!wait)
			return -EAGAIN;

		wait_event(tg->block_recall_PFNs_wq,
			   (atomic_read(&tg->n_recall_PFNs) <= 0));
	}
}

void
xpmem_unblock_recall_PFNs(struct xpmem_thread_group *tg)
{
	if (atomic_inc_return(&tg->n_recall_PFNs) == 0)
			wake_up(&tg->allow_recall_PFNs_wq);
}

static void
xpmem_disallow_blocking_recall_PFNs(struct xpmem_thread_group *tg)
{
	int value, returned_value;

	while (1) {
		value = atomic_read(&tg->n_recall_PFNs);
		while (1) {
			if (unlikely(value < 0))
				break;
			returned_value = atomic_cmpxchg(&tg->n_recall_PFNs,
							value, value + 1);
			if (likely(returned_value == value))
				break;
			value = returned_value;
		}

		if (value >= 0)
			return;

		wait_event(tg->allow_recall_PFNs_wq,
			  (atomic_read(&tg->n_recall_PFNs) >= 0));
	}
}

static void
xpmem_allow_blocking_recall_PFNs(struct xpmem_thread_group *tg)
{
	if (atomic_dec_return(&tg->n_recall_PFNs) == 0)
		wake_up(&tg->block_recall_PFNs_wq);
}

int
xpmem_fork_begin(void)
{
	struct xpmem_thread_group *tg;

	tg = xpmem_tg_ref_by_tgid(current->tgid);
	if (IS_ERR(tg))
		return PTR_ERR(tg);

	xpmem_disallow_blocking_recall_PFNs(tg);

	mutex_lock(&tg->recall_PFNs_mutex);
	xpmem_recall_PFNs_of_tg(tg);
	mutex_unlock(&tg->recall_PFNs_mutex);

	xpmem_tg_deref(tg);
	return 0;
}

int
xpmem_fork_end(void)
{
	struct xpmem_thread_group *tg;

	tg = xpmem_tg_ref_by_tgid(current->tgid);
	if (IS_ERR(tg))
		return PTR_ERR(tg);

	xpmem_allow_blocking_recall_PFNs(tg);

	xpmem_tg_deref(tg);
	return 0;
}

struct proc_dir_entry *xpmem_unpin_procfs_dir;

static int
xpmem_is_thread_group_stopped(struct xpmem_thread_group *tg)
{
	struct task_struct *task = tg->group_leader;

	rcu_read_lock();
	do {
		if (!(task->flags & PF_EXITING) &&
		    !task_is_stopped(task)) {
			rcu_read_unlock();
			return 0;
		}
		task = next_thread(task);
	} while (task != tg->group_leader);
	rcu_read_unlock();
	return 1;
}

static ssize_t
xpmem_unpin_procfs_write(struct file *file, const char *buffer,
			 size_t count, loff_t *ppos)
{
	struct seq_file *seq = (struct seq_file *)file->private_data;
	pid_t tgid = (unsigned long)seq->private;
	struct xpmem_thread_group *tg;

	tg = xpmem_tg_ref_by_tgid(tgid);
	if (IS_ERR(tg))
		return -ESRCH;

	if (!xpmem_is_thread_group_stopped(tg)) {
		xpmem_tg_deref(tg);
		return -EPERM;
	}

	xpmem_disallow_blocking_recall_PFNs(tg);

	mutex_lock(&tg->recall_PFNs_mutex);
	xpmem_recall_PFNs_of_tg(tg);
	mutex_unlock(&tg->recall_PFNs_mutex);

	xpmem_allow_blocking_recall_PFNs(tg);

	xpmem_tg_deref(tg);
	return count;
}

static int
xpmem_unpin_procfs_show(struct seq_file *seq, void *offset)
{
	pid_t tgid = (unsigned long)seq->private;
	struct xpmem_thread_group *tg;

	if (tgid == 0) {
		seq_printf(seq, "all pages pinned by XPMEM: %d\n"
				"all pages unpinned by XPMEM: %d\n",
				 atomic_read(&xpmem_my_part->n_pinned),
				 atomic_read(&xpmem_my_part->n_unpinned));
	} else {
		tg = xpmem_tg_ref_by_tgid(tgid);
		if (!IS_ERR(tg)) {
			seq_printf(seq, "pages pinned by XPMEM: %d\n",
				   atomic_read(&tg->n_pinned));
			xpmem_tg_deref(tg);
		}
	}

	return 0;
}

static int
xpmem_unpin_procfs_open(struct inode *inode, struct file *file)
{
	return single_open(file, xpmem_unpin_procfs_show, pde_data(inode));
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
struct file_operations xpmem_unpin_procfs_ops = {
	.owner		= THIS_MODULE,
	.llseek		= seq_lseek,
	.read		= seq_read,
	.write		= xpmem_unpin_procfs_write,
	.open		= xpmem_unpin_procfs_open,
	.release	= single_release,
};
#else
const struct proc_ops xpmem_unpin_procfs_ops = {
	.proc_lseek		= seq_lseek,
	.proc_read		= seq_read,
	.proc_write		= xpmem_unpin_procfs_write,
	.proc_open		= xpmem_unpin_procfs_open,
	.proc_release		= single_release,
};
#endif
