%{?mingw_package_header}

#% define is_wip 1
%{?is_wip:%define ver_wip -WIP}

Name:		mingw-testdisk
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
BuildRequires: libtool autoconf automake

BuildRequires:	mingw32-filesystem >= 95
BuildRequires:	mingw32-binutils
BuildRequires:	mingw32-gcc
BuildRequires:	mingw32-gcc-c++
BuildRequires:	mingw32-gettext
BuildRequires:	mingw32-libewf
BuildRequires:	mingw32-libjpeg-turbo
BuildRequires:	mingw32-libjpeg-turbo-static
BuildRequires:	mingw32-ntfsprogs
BuildRequires:	mingw32-openssl
BuildRequires:	mingw32-pdcurses
BuildRequires:	mingw32-qt5-qtbase-devel
BuildRequires:	mingw32-win-iconv
BuildRequires:	mingw32-zlib

BuildRequires:	mingw64-binutils
BuildRequires:	mingw64-filesystem >= 95
BuildRequires:	mingw64-gcc
BuildRequires:	mingw64-gcc-c++
BuildRequires:	mingw64-gettext
BuildRequires:	mingw64-libewf
BuildRequires:	mingw64-libjpeg-turbo
BuildRequires:	mingw64-ntfsprogs
BuildRequires:	mingw64-openssl
BuildRequires:	mingw64-pdcurses
BuildRequires:	mingw64-qt5-qtbase-devel
BuildRequires:	mingw64-win-iconv
BuildRequires:	mingw64-zlib

%description
MinGW compiled testdisk.

%package -n mingw32-testdisk
Summary:       MinGW compiled testdisk for the Win32 target.

%description -n mingw32-testdisk
Tool to check and undelete partition. Works with FAT12, FAT16, FAT32,
NTFS, ext2, ext3, ext4, BeFS, CramFS, HFS, JFS, Linux Raid, Linux Swap,
LVM, LVM2, NSS, ReiserFS, UFS, XFS
PhotoRec is a signature based file recovery utility. It handles more than
200 file formats including JPG, MSOffice, OpenOffice documents.

%description -n mingw32-testdisk -l pl.UTF8
Narzędzie sprawdzające i odzyskujące partycje. Pracuje z partycjami:
FAT12, FAT16, FAT32, NTFS, ext2, ext3, ext4, BeFS, CramFS, HFS, JFS,
Linux Raid, Linux Swap, LVM, LVM2, NSS, ReiserFS, UFS, XFS
PhotoRec is a signature based file recovery utility. It handles more than
200 file formats including JPG, MSOffice, OpenOffice documents.

%description -n mingw32-testdisk -l fr.UTF8
TestDisk vérifie et récupère les partitions. Fonctionne avec
FAT12, FAT16, FAT32, NTFS, ext2, ext3, ext4, BeFS, CramFS, HFS, JFS,
Linux Raid, Linux Swap, LVM, LVM2, NSS, ReiserFS, UFS, XFS
PhotoRec utilise un mécanisme de signature pour récupérer des fichiers perdus.
Il gère plus d'une centaine de formats de fichiers dont les JPEG,
les documents MSOffice ou OpenOffice.

%description -n mingw32-testdisk -l ru_RU.UTF8
Программа для проверки и восстановления разделов диска.
Поддерживает следующие типы разделов:
FAT12, FAT16, FAT32, NTFS, ext2, ext3, ext4, BeFS, CramFS, HFS, JFS,
Linux Raid, Linux Swap, LVM, LVM2, NSS, ReiserFS, UFS, XFS
PhotoRec is a signature based file recovery utility. It handles more than
200 file formats including JPG, MSOffice, OpenOffice documents.

%package -n mingw64-testdisk
Summary:       MinGW compiled testdisk for the Win64 target.

%description -n mingw64-testdisk
Tool to check and undelete partition. Works with FAT12, FAT16, FAT32,
NTFS, ext2, ext3, ext4, BeFS, CramFS, HFS, JFS, Linux Raid, Linux Swap,
LVM, LVM2, NSS, ReiserFS, UFS, XFS
PhotoRec is a signature based file recovery utility. It handles more than
200 file formats including JPG, MSOffice, OpenOffice documents.

%description -n mingw64-testdisk -l pl.UTF8
Narzędzie sprawdzające i odzyskujące partycje. Pracuje z partycjami:
FAT12, FAT16, FAT32, NTFS, ext2, ext3, ext4, BeFS, CramFS, HFS, JFS,
Linux Raid, Linux Swap, LVM, LVM2, NSS, ReiserFS, UFS, XFS
PhotoRec is a signature based file recovery utility. It handles more than
200 file formats including JPG, MSOffice, OpenOffice documents.

%description -n mingw64-testdisk -l fr.UTF8
TestDisk vérifie et récupère les partitions. Fonctionne avec
FAT12, FAT16, FAT32, NTFS, ext2, ext3, ext4, BeFS, CramFS, HFS, JFS,
Linux Raid, Linux Swap, LVM, LVM2, NSS, ReiserFS, UFS, XFS
PhotoRec utilise un mécanisme de signature pour récupérer des fichiers perdus.
Il gère plus d'une centaine de formats de fichiers dont les JPEG,
les documents MSOffice ou OpenOffice.

%description -n mingw64-testdisk -l ru_RU.UTF8
Программа для проверки и восстановления разделов диска.
Поддерживает следующие типы разделов:
FAT12, FAT16, FAT32, NTFS, ext2, ext3, ext4, BeFS, CramFS, HFS, JFS,
Linux Raid, Linux Swap, LVM, LVM2, NSS, ReiserFS, UFS, XFS
PhotoRec is a signature based file recovery utility. It handles more than
200 file formats including JPG, MSOffice, OpenOffice documents.

%{?mingw_debug_package}

%prep
%setup -q -n testdisk-%{version}%{?ver_wip}

%build
autoreconf -vif -I config -W all
%mingw_configure --enable-missing-uuid-ok
%mingw_make %{?_smp_mflags}
%install
rm -rf $RPM_BUILD_ROOT
%mingw_make install DESTDIR=$RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT

%files -n mingw32-testdisk
%{mingw32_docdir}/testdisk/AUTHORS
%{mingw32_docdir}/testdisk/ChangeLog
%{mingw32_docdir}/testdisk/NEWS
%{mingw32_docdir}/testdisk/README.md
%{mingw32_docdir}/testdisk/THANKS
%{mingw32_docdir}/testdisk/documentation.html
%{mingw32_mandir}/man8/*-fidentify.8*
%{mingw32_mandir}/man8/*-photorec.8*
%{mingw32_mandir}/man8/*-qphotorec.8*
%{mingw32_mandir}/man8/*-testdisk.8*
%{mingw32_mandir}/zh_CN/man8/*-fidentify.8*
%{mingw32_mandir}/zh_CN/man8/*-photorec.8*
%{mingw32_mandir}/zh_CN/man8/*-qphotorec.8*
%{mingw32_mandir}/zh_CN/man8/*-testdisk.8*
%{mingw32_datadir}/applications/qphotorec.desktop
%{mingw32_datadir}/icons/hicolor/48x48/apps/qphotorec.png
%{mingw32_datadir}/icons/hicolor/scalable/apps/qphotorec.svg
%attr(755,root,root) %{mingw32_bindir}/*-fidentify.exe
%attr(755,root,root) %{mingw32_bindir}/*-photorec.exe
%attr(755,root,root) %{mingw32_bindir}/*-qphotorec.exe
%attr(755,root,root) %{mingw32_bindir}/*-testdisk.exe

%files -n mingw64-testdisk
%{mingw64_docdir}/testdisk/AUTHORS
%{mingw64_docdir}/testdisk/ChangeLog
%{mingw64_docdir}/testdisk/NEWS
%{mingw64_docdir}/testdisk/README.md
%{mingw64_docdir}/testdisk/THANKS
%{mingw64_docdir}/testdisk/documentation.html
%{mingw64_mandir}/man8/*-fidentify.8*
%{mingw64_mandir}/man8/*-photorec.8*
%{mingw64_mandir}/man8/*-qphotorec.8*
%{mingw64_mandir}/man8/*-testdisk.8*
%{mingw64_mandir}/zh_CN/man8/*-fidentify.8*
%{mingw64_mandir}/zh_CN/man8/*-photorec.8*
%{mingw64_mandir}/zh_CN/man8/*-qphotorec.8*
%{mingw64_mandir}/zh_CN/man8/*-testdisk.8*
%{mingw64_datadir}/applications/qphotorec.desktop
%{mingw64_datadir}/icons/hicolor/48x48/apps/qphotorec.png
%{mingw64_datadir}/icons/hicolor/scalable/apps/qphotorec.svg
%attr(755,root,root) %{mingw64_bindir}/*-fidentify.exe
%attr(755,root,root) %{mingw64_bindir}/*-photorec.exe
%attr(755,root,root) %{mingw64_bindir}/*-qphotorec.exe
%attr(755,root,root) %{mingw64_bindir}/*-testdisk.exe

%changelog
* Thu Jul 17 2008 Christophe Grenier <grenier@cgsecurity.org> 6.10-1
- 6.10

* Sun Jan 4 2004 Christophe Grenier <grenier@cgsecurity.org> 5.0
- 5.0

* Wed Oct 1 2003 Christophe Grenier <grenier@cgsecurity.org> 4.5
- 4.5

* Wed Apr 23 2003 Christophe Grenier <grenier@cgsecurity.org> 4.4-2

* Sat Mar 29 2003 Pascal Terjan <CMoi@tuxfamily.org> 4.4-1mdk
- 4.4

* Fri Dec 27 2002 Olivier Thauvin <thauvin@aerov.jussieu.fr> 4.2-2mdk
- rebuild for rpm and glibc

* Sun Oct 06 2002 Olivier Thauvin <thauvin@aerov.jussieu.fr> 4.2-1mdk
- 4.2

* Mon Sep 02 2002 Olivier Thauvin <thauvin@aerov.jussieu.fr> 4.1-1mdk 
- By Pascal Terjan <pascal.terjan@free.fr>
	- first mdk release, adapted from PLD.
	- gz to bz2 compression.
- fix %%tmppath
- %%make instead %%{__make}
