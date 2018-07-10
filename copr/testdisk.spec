Summary:	Tool to check and undelete partition, PhotoRec recovers lost files
Summary(pl.UTF8):	Narzędzie sprawdzające i odzyskujące partycje
Summary(fr.UTF8):	Outil pour vérifier et restaurer des partitions
Summary(ru_RU.UTF8): Программа для проверки и восстановления разделов диска
Name:		testdisk
Version:	7.1
Release:	0%{?dist}
License:	GPLv2+
Group:		Applications/System
Source0:	https://www.cgsecurity.org/testdisk-%{version}.tar.bz2
URL:		https://www.cgsecurity.org/wiki/TestDisk
BuildRequires:	libtool autoconf automake
BuildRequires:	desktop-file-utils
BuildRequires:	e2fsprogs-devel
BuildRequires:	libewf-devel
BuildRequires:	libjpeg-devel
BuildRequires:	ncurses-devel >= 5.2
BuildRequires:	ntfs-3g-devel
BuildRequires:	zlib-devel
%if  0%{?rhel} != 5
BuildRequires:	libuuid-devel
BuildRequires:  qt5-linguist
BuildRequires:	qt5-qtbase-devel
%endif
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
%{!?_pkgdocdir: %global _pkgdocdir %{_docdir}/%{name}-%{version}}

%description
Tool to check and undelete partition. Works with FAT12, FAT16, FAT32,
NTFS, ext2, ext3, ext4, btrfs, BeFS, CramFS, HFS, JFS, Linux Raid, Linux
Swap, LVM, LVM2, NSS, ReiserFS, UFS, XFS.
PhotoRec is a signature based file recovery utility. It handles more than
440 file formats including JPG, MSOffice, OpenOffice documents.

%description -l pl.UTF8
Narzędzie sprawdzające i odzyskujące partycje. Pracuje z partycjami:
FAT12, FAT16, FAT32, NTFS, ext2, ext3, ext4, btrfs, BeFS, CramFS, HFS, JFS,
Linux Raid, Linux Swap, LVM, LVM2, NSS, ReiserFS, UFS, XFS.
PhotoRec is a signature based file recovery utility. It handles more than
440 file formats including JPG, MSOffice, OpenOffice documents.

%description -l fr.UTF8
TestDisk vérifie et récupère les partitions. Fonctionne avec
FAT12, FAT16, FAT32, NTFS, ext2, ext3, ext4, btrfs, BeFS, CramFS, HFS, JFS,
Linux Raid, Linux Swap, LVM, LVM2, NSS, ReiserFS, UFS, XFS.
PhotoRec utilise un mécanisme de signature pour récupérer des fichiers
perdus. Il reconnait plus de 440 formats de fichiers dont les JPEG, les
documents MSOffice ou OpenOffice.

%description -l ru_RU.UTF8
Программа для проверки и восстановления разделов диска.
Поддерживает следующие типы разделов:
FAT12, FAT16, FAT32, NTFS, ext2, ext3, ext4, btrfs, BeFS, CramFS, HFS, JFS,
Linux Raid, Linux Swap, LVM, LVM2, NSS, ReiserFS, UFS, XFS.
PhotoRec is a signature based file recovery utility. It handles more than
440 file formats including JPG, MSOffice, OpenOffice documents.

%if  0%{?rhel} != 5
%package -n qphotorec
Summary:	Signature based file carver. Recover lost files
Group:		Applications/System

%description -n qphotorec
QPhotoRec is a Qt version of PhotoRec. It is a signature based file recovery
utility. It handles more than 440 file formats including JPG, MSOffice,
OpenOffice documents.

%endif

%prep
%setup -q

%build
autoreconf -vif -I config -W all
%if  0%{?rhel} == 5
%configure
%else
%configure --docdir=%{_pkgdocdir}
%endif
make %{?_smp_mflags}
%install
rm -rf %{buildroot}
make DESTDIR="%{buildroot}" install

%clean
rm -rf %{buildroot}

%if  0%{?rhel} != 5
%check
desktop-file-validate %{buildroot}/%{_datadir}/applications/qphotorec.desktop

%post -n qphotorec
/bin/touch --no-create %{_datadir}/icons/hicolor &>/dev/null || :

%postun -n qphotorec
if [ $1 -eq 0 ] ; then
    /bin/touch --no-create %{_datadir}/icons/hicolor &>/dev/null
    /usr/bin/gtk-update-icon-cache %{_datadir}/icons/hicolor &>/dev/null || :
fi

%posttrans -n qphotorec
/usr/bin/gtk-update-icon-cache %{_datadir}/icons/hicolor &>/dev/null || :

%endif

%files
%if  0%{?rhel} == 5
%doc /usr/share/doc/testdisk/AUTHORS
%doc /usr/share/doc/testdisk/ChangeLog
%doc /usr/share/doc/testdisk/NEWS
%doc /usr/share/doc/testdisk/README.md
%doc /usr/share/doc/testdisk/THANKS
%doc /usr/share/doc/testdisk/documentation.html
%else
%license COPYING
%doc AUTHORS ChangeLog NEWS README.md THANKS
%doc documentation.html
%endif
%attr(755,root,root) %{_bindir}/fidentify
%attr(755,root,root) %{_bindir}/photorec
%attr(755,root,root) %{_bindir}/testdisk
%{_mandir}/man8/fidentify.8*
%{_mandir}/man8/photorec.8*
%{_mandir}/man8/testdisk.8*
%{_mandir}/zh_CN/man8/fidentify.8*
%{_mandir}/zh_CN/man8/photorec.8*
%{_mandir}/zh_CN/man8/testdisk.8*

%if  0%{?rhel} != 5
%files -n qphotorec
%attr(755,root,root) %{_bindir}/qphotorec
%{_mandir}/man8/qphotorec.8*
%{_mandir}/zh_CN/man8/qphotorec.8*
%{_datadir}/applications/qphotorec.desktop
%{_datadir}/icons/hicolor/48x48/apps/qphotorec.png
%{_datadir}/icons/hicolor/scalable/apps/qphotorec.svg
%endif

%changelog
* Sun Jan 24 2016 Christophe Grenier <grenier@cgsecurity.org> 7.1-0
- spec file for fedora copr integration
