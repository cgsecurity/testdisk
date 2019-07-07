%{?cygwin_package_header}

#% define is_wip 1
%{?is_wip:%define ver_wip -WIP}

Name:		cygwin-testdisk
Version:	7.1
Release:	0%{?dist}
Summary:	TestDisk checks and undeletes partitions, PhotoRec recovers lost files
Summary(pl.UTF8):	Narzędzie sprawdzające i odzyskujące partycje
Summary(fr.UTF8):	Outil pour vérifier et restaurer des partitions
Summary(ru_RU.UTF8): Программа для проверки и восстановления разделов диска
License:	GPLv2+
Group:		Applications/System
URL:		https://www.cgsecurity.org/wiki/TestDisk
Source0:	https://www.cgsecurity.org/testdisk-%{version}%{?ver_wip}.tar.bz2

BuildArch:	noarch
BuildRequires:	libtool autoconf automake

BuildRequires:	cygwin32-filesystem >= 9
BuildRequires:	cygwin32-binutils
BuildRequires:	cygwin32-e2fsprogs
BuildRequires:	cygwin32-gcc
BuildRequires:	cygwin32-libiconv
BuildRequires:	cygwin32-libewf
BuildRequires:	cygwin32-libjpeg-turbo
BuildRequires:	cygwin32-ntfsprogs
BuildRequires:	cygwin32-ncurses
BuildRequires:	cygwin32-zlib
BuildRequires:  cygwin32-pkg-config

BuildRequires:	cygwin64-binutils
BuildRequires:	cygwin64-filesystem >= 9
BuildRequires:	cygwin64-e2fsprogs
BuildRequires:	cygwin64-gcc
BuildRequires:	cygwin64-libewf
BuildRequires:	cygwin64-libjpeg-turbo
BuildRequires:	cygwin64-ntfsprogs
BuildRequires:	cygwin64-ncurses
BuildRequires:	cygwin64-libiconv
BuildRequires:	cygwin64-zlib
BuildRequires:  cygwin64-pkg-config

%description
Cygwin compiled testdisk.

%package -n cygwin32-testdisk
Summary:       Cygwin compiled testdisk for the Win32 target.

%description -n cygwin32-testdisk
Tool to check and undelete partition. Works with FAT12, FAT16, FAT32,
NTFS, ext2, ext3, ext4, BeFS, CramFS, HFS, JFS, Linux Raid, Linux Swap,
LVM, LVM2, NSS, ReiserFS, UFS, XFS
PhotoRec is a signature based file recovery utility. It handles more than
200 file formats including JPG, MSOffice, OpenOffice documents.

%description -n cygwin32-testdisk -l pl.UTF8
Narzędzie sprawdzające i odzyskujące partycje. Pracuje z partycjami:
FAT12, FAT16, FAT32, NTFS, ext2, ext3, ext4, BeFS, CramFS, HFS, JFS,
Linux Raid, Linux Swap, LVM, LVM2, NSS, ReiserFS, UFS, XFS
PhotoRec is a signature based file recovery utility. It handles more than
200 file formats including JPG, MSOffice, OpenOffice documents.

%description -n cygwin32-testdisk -l fr.UTF8
TestDisk vérifie et récupère les partitions. Fonctionne avec
FAT12, FAT16, FAT32, NTFS, ext2, ext3, ext4, BeFS, CramFS, HFS, JFS,
Linux Raid, Linux Swap, LVM, LVM2, NSS, ReiserFS, UFS, XFS
PhotoRec utilise un mécanisme de signature pour récupérer des fichiers perdus.
Il gère plus d'une centaine de formats de fichiers dont les JPEG,
les documents MSOffice ou OpenOffice.

%description -n cygwin32-testdisk -l ru_RU.UTF8
Программа для проверки и восстановления разделов диска.
Поддерживает следующие типы разделов:
FAT12, FAT16, FAT32, NTFS, ext2, ext3, ext4, BeFS, CramFS, HFS, JFS,
Linux Raid, Linux Swap, LVM, LVM2, NSS, ReiserFS, UFS, XFS
PhotoRec is a signature based file recovery utility. It handles more than
200 file formats including JPG, MSOffice, OpenOffice documents.

%package -n cygwin64-testdisk
Summary:       Cygwin compiled testdisk for the Win64 target.

%description -n cygwin64-testdisk
Tool to check and undelete partition. Works with FAT12, FAT16, FAT32,
NTFS, ext2, ext3, ext4, BeFS, CramFS, HFS, JFS, Linux Raid, Linux Swap,
LVM, LVM2, NSS, ReiserFS, UFS, XFS
PhotoRec is a signature based file recovery utility. It handles more than
200 file formats including JPG, MSOffice, OpenOffice documents.

%description -n cygwin64-testdisk -l pl.UTF8
Narzędzie sprawdzające i odzyskujące partycje. Pracuje z partycjami:
FAT12, FAT16, FAT32, NTFS, ext2, ext3, ext4, BeFS, CramFS, HFS, JFS,
Linux Raid, Linux Swap, LVM, LVM2, NSS, ReiserFS, UFS, XFS
PhotoRec is a signature based file recovery utility. It handles more than
200 file formats including JPG, MSOffice, OpenOffice documents.

%description -n cygwin64-testdisk -l fr.UTF8
TestDisk vérifie et récupère les partitions. Fonctionne avec
FAT12, FAT16, FAT32, NTFS, ext2, ext3, ext4, BeFS, CramFS, HFS, JFS,
Linux Raid, Linux Swap, LVM, LVM2, NSS, ReiserFS, UFS, XFS
PhotoRec utilise un mécanisme de signature pour récupérer des fichiers perdus.
Il gère plus d'une centaine de formats de fichiers dont les JPEG,
les documents MSOffice ou OpenOffice.

%description -n cygwin64-testdisk -l ru_RU.UTF8
Программа для проверки и восстановления разделов диска.
Поддерживает следующие типы разделов:
FAT12, FAT16, FAT32, NTFS, ext2, ext3, ext4, BeFS, CramFS, HFS, JFS,
Linux Raid, Linux Swap, LVM, LVM2, NSS, ReiserFS, UFS, XFS
PhotoRec is a signature based file recovery utility. It handles more than
200 file formats including JPG, MSOffice, OpenOffice documents.

%{?cygwin_debug_package}

%prep
%setup -q -n testdisk-%{version}%{?ver_wip}

%build
autoreconf -vif -I config -W all
%cygwin_configure --enable-missing-uuid-ok
%cygwin_make %{?_smp_mflags}
%install
rm -rf $RPM_BUILD_ROOT
%cygwin_make install DESTDIR=$RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT

%files -n cygwin32-testdisk
%{cygwin32_docdir}/testdisk/AUTHORS
%{cygwin32_docdir}/testdisk/ChangeLog
%{cygwin32_docdir}/testdisk/NEWS
%{cygwin32_docdir}/testdisk/README.md
%{cygwin32_docdir}/testdisk/THANKS
%{cygwin32_docdir}/testdisk/documentation.html
%{cygwin32_mandir}/man8/*-fidentify.8*
%{cygwin32_mandir}/man8/*-photorec.8*
%{cygwin32_mandir}/man8/*-testdisk.8*
%{cygwin32_mandir}/zh_CN/man8/*-fidentify.8*
%{cygwin32_mandir}/zh_CN/man8/*-photorec.8*
%{cygwin32_mandir}/zh_CN/man8/*-testdisk.8*
%attr(755,root,root) %{cygwin32_bindir}/*-fidentify.exe
%attr(755,root,root) %{cygwin32_bindir}/*-photorec.exe
%attr(755,root,root) %{cygwin32_bindir}/*-testdisk.exe

%files -n cygwin64-testdisk
%{cygwin64_docdir}/testdisk/AUTHORS
%{cygwin64_docdir}/testdisk/ChangeLog
%{cygwin64_docdir}/testdisk/NEWS
%{cygwin64_docdir}/testdisk/README.md
%{cygwin64_docdir}/testdisk/THANKS
%{cygwin64_docdir}/testdisk/documentation.html
%{cygwin64_mandir}/man8/*-fidentify.8*
%{cygwin64_mandir}/man8/*-photorec.8*
%{cygwin64_mandir}/man8/*-testdisk.8*
%{cygwin64_mandir}/zh_CN/man8/*-fidentify.8*
%{cygwin64_mandir}/zh_CN/man8/*-photorec.8*
%{cygwin64_mandir}/zh_CN/man8/*-testdisk.8*
%attr(755,root,root) %{cygwin64_bindir}/*-fidentify.exe
%attr(755,root,root) %{cygwin64_bindir}/*-photorec.exe
%attr(755,root,root) %{cygwin64_bindir}/*-testdisk.exe

%changelog
* Mon Aug 15 2016 Christophe GRENIER <grenier@cgsecurity.org> - 7.1-0
- First spec file under cygwin
