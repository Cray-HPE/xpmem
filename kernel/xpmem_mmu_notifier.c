/*
 * XPMEM mmu notifier related operations and callback function definitions.
 *
 * Copyright (c) 2010,2012 Cray, Inc.
 * Copyright (c) 2014-2015 Los Alamos National Security, LLC. All rights
 *                         reserved.
 * Copyright (c) 2016      Nathan Hjelm <hjelmn@cs.unm.edu>
 * Copyright Hewlett Packard Enterprise Development LP. All Rights Reserved.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License. See the file "COPYING" in the main directory of this archive for
 * more details.
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/cdev.h>
#include <linux/percpu.h>

#include <asm/tlbflush.h>
#include <asm/uaccess.h>

#include "xpmem_internal.h"
#include "xpmem_private.h"

static inline void
xpmem_invalidate_PTEs_range(struct xpmem_thread_group *seg_tg,
			    unsigned long start, unsigned long end)
{
	struct xpmem_segment *seg;
	u64 seg_start, seg_end;

	read_lock(&seg_tg->seg_list_lock);
	list_for_each_entry(seg, &seg_tg->seg_list, seg_list) {
		if (!(seg->flags & XPMEM_FLAG_DESTROYING)) {
			seg_start = seg->vaddr;
			seg_end = seg->vaddr + seg->size;

			if (start <= seg_end && end >= seg_start) {
				XPMEM_DEBUG("start=%lx, end=%lx", start, end);
				xpmem_seg_ref(seg);
				read_unlock(&seg_tg->seg_list_lock);

				xpmem_clear_PTEs_range(seg, start, end, 1);

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
	}
	read_unlock(&seg_tg->seg_list_lock);
}

/*
 * MMU notifier callout for invalidating a range of pages.
 *
 * XPMEM only uses the invalidate_range_end() portion. That is, when all pages
 * in the range have been unmapped and the pages have been freed by the VM.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
static void
xpmem_invalidate_range(struct mmu_notifier *mn, struct mm_struct *mm,
		       unsigned long start, unsigned long end)
{
#else
static void
xpmem_invalidate_range(struct mmu_notifier *mn,
	               const struct mmu_notifier_range *mnr)
{
	struct mm_struct *mm = mnr->mm;
	unsigned long start  = mnr->start;
	unsigned long end    = mnr->end;
#endif
	unsigned long curr;
	struct xpmem_thread_group *seg_tg;
	struct vm_area_struct *vma;
	struct vma_iterator vmi;

	seg_tg = container_of(mn, struct xpmem_thread_group, mmu_not);

	XPMEM_DEBUG("xpmem_invalidate_range (%p, %p, %lu, %lu)", mn, mm,
		    start, end);

	/*
	 * This invalidate callout came from a destination address space
	 * and we can return because we have already done all the necessary
	 * invalidate operations.
	 */
	if (seg_tg->tgid != current->tgid)
		return;

	if (offset_in_page(start) != 0)
		start -= offset_in_page(start);
	if (offset_in_page(end) != 0)
		end += PAGE_SIZE - offset_in_page(end);

	/* NTH: Changes to the tlb code should have removed the need for gathering
	 * the mmu here. There is not any state that needs to be restored */
	curr = start;
	while (curr < end) {
		bool found = false;
		unsigned long vma_start, vma_end;

		rcu_read_lock();
		vma_iter_init(&vmi, mm, curr);
		for_each_vma_range(vmi, vma, end) {
			if (!xpmem_is_vm_ops_set(vma))
				continue;

			vma_start = vma->vm_start;
			vma_end = vma->vm_end;
			found = true;
			break;
		}
		rcu_read_unlock();

		if (!found) {
			xpmem_invalidate_PTEs_range(seg_tg, curr, end);
			break;
		}

		if (curr < min(vma_start, end))
			xpmem_invalidate_PTEs_range(seg_tg, curr, min(vma_start, end));
		curr = min(vma_end, end);
	}
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
/*
 * MMU notifier callout for invalidating a single page.
 */
static void
xpmem_invalidate_page(struct mmu_notifier *mn, struct mm_struct *mm,
		      unsigned long start)
{
	if (offset_in_page(start) != 0)
		start -= offset_in_page(start);
	xpmem_invalidate_range(mn, mm, start, start + PAGE_SIZE);
}
#endif

/*
 * xpmem_tg_set_destroying()
 *
 * Set XPMEM_FLAGS_DESTROYING in tg->flags if it's not already set.
 *
 * Returns 1 if we set it, 0 if it was already set.
 */
static int
xpmem_tg_set_destroying(struct xpmem_thread_group *tg)
{
	int ret;

	spin_lock(&tg->lock);
	if (tg->flags & XPMEM_FLAG_DESTROYING) {
		ret = 0;
	} else {
		tg->flags |= XPMEM_FLAG_DESTROYING;
		ret = 1;
	}
	spin_unlock(&tg->lock);

	return ret;
}

/*
 * MMU notifier callout for releasing a mm_struct.  Remove all traces of
 * XPMEM from the address space, using the same logic that would apply if
 * /dev/xpmem was closed.
 */
static void
xpmem_mmu_release(struct mmu_notifier *mn, struct mm_struct *mm)
{
	struct xpmem_thread_group *tg;
	int i;

	/*
	 * Some other process may be the last to release the mm, so
	 * validate it against the value stored in the tg before continuing.
	 */
	tg = container_of(mn, struct xpmem_thread_group, mmu_not);
	xpmem_tg_ref(tg);
	if (tg->mm == mm) {
		/*
		 * Normal case, process is removing its own address
		 * space.
		 */
		int call_teardown;
		XPMEM_DEBUG("PID %d (%s): self: tg->mm=%p",
			current->tgid, current->comm, tg->mm);
		call_teardown = xpmem_tg_set_destroying(tg);
		if (call_teardown)
			xpmem_teardown(tg);
		return;
	} else {
		/* Abnormal case, must continue with code below. */
		xpmem_tg_deref(tg);
	}

	/*
	 * Although it is highly unlikely, an "outside" process could have
	 * obtained a reference to the mm_struct and been the last to call
	 * mmput().  In this case we need to search all of the tgs to see
	 * if one still matches with the mm passed to us from the MMU notifier
	 * release callout.  If a match is found, that means the mmput()
	 * occurred before the owning process has closed /dev/xpmem and
	 * we need to call xpmem_teardown() on behalf of the owning process
	 * since the mm_struct mappings are being destroyed.
	 */
	for (i = 0; i < XPMEM_TG_HASHTABLE_SIZE; i++) {
		read_lock(&xpmem_my_part->tg_hashtable[i].lock);
		list_for_each_entry(tg, &xpmem_my_part->tg_hashtable[i].list,
				    tg_hashlist) {
			if (tg->mm == mm) {
				int call_teardown;
				call_teardown = xpmem_tg_set_destroying(tg);
				if (!call_teardown)
					continue;

				xpmem_tg_ref(tg);
				read_unlock(&xpmem_my_part->tg_hashtable[i].lock);
				XPMEM_DEBUG("PID %d (%s): not self: tg->mm=%p",
					current->tgid, current->comm,  tg->mm);
				xpmem_teardown(tg);
				return;
			}
		}
		read_unlock(&xpmem_my_part->tg_hashtable[i].lock);
	}
}

static const struct mmu_notifier_ops xpmem_mmuops = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
	.invalidate_page	= xpmem_invalidate_page,
#endif
	.invalidate_range_end	= xpmem_invalidate_range,
	.release		= xpmem_mmu_release,
};

/*
 * Initialize MMU notifier related fields in the XPMEM segment, and register
 * for MMU callbacks.
 */
int
xpmem_mmu_notifier_init(struct xpmem_thread_group *tg)
{
	int ret;

	if (!tg) {
		return -EFAULT;
	}

	if (!tg->mmu_initialized) {
		tg->mmu_not.ops = &xpmem_mmuops;
		tg->mmu_unregister_called = 0;
		XPMEM_DEBUG("tg->mm=%p", tg->mm);
		ret = mmu_notifier_register(&tg->mmu_not, tg->mm);
		if (ret)
			return ret;

		tg->mmu_initialized = 1;
	}

	return 0;
}

/*
 * Unlink MMU notifier callbacks
 */
bool
xpmem_mmu_notifier_unlink(struct xpmem_thread_group *tg)
{
	spin_lock(&tg->lock);
	if (!tg->mmu_initialized || tg->mmu_unregister_called) {
		spin_unlock(&tg->lock);
		return false;
	}
	tg->mmu_unregister_called = 1;
	spin_unlock(&tg->lock);

	XPMEM_DEBUG("tg->mm=%p", tg->mm);
	mmu_notifier_unregister(&tg->mmu_not, tg->mm);

	return true;
}
