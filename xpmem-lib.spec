%global debug_package %{nil}

%define _prefix /opt/xpmem

Summary: XPMEM: Cross-partition memory
Name: xpmem
Version: 0.2
Release: 0
License: GPLv2
Group: System Environment/Libraries
Packager: Nathan Hjelm
Source: xpmem-%{version}.tar.bz2
BuildRoot: %{_tmppath}/%{name}-%{version}-build
Requires: xpmem-kmod
Provides: xpmem xpmem-devel

%description
XPMEM is a Linux kernel module that enables a process to map the
memory of another process into its virtual address space. Source code
can be obtained by cloning the Git repository, original Mercurial
repository or by downloading a tarball from the link above.

%prep
%setup -n xpmem-%{version}

%build
./configure --prefix=%{_prefix} --libdir=%{_libdir} --disable-kernel-module
make

%install
make DESTDIR=$RPM_BUILD_ROOT install

%__mkdir_p %{buildroot}/etc/ld.so.conf.d
echo %{_libdir} > %{buildroot}/etc/ld.so.conf.d/xpmem.conf

%files
%defattr(-, root, root)
%dir /etc/ld.so.conf.d
/etc/ld.so.conf.d/xpmem.conf
%dir %{_prefix}
%{_prefix}

%post
/sbin/ldconfig

%postun
/sbin/ldconfig
