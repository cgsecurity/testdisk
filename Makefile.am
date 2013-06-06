
SUBDIRS = src

EXTRA_DIST = AUTHORS COPYING ChangeLog INFO INSTALL NEWS README THANKS compile.sh \
	progsreiserfs-journal.patch progsreiserfs-file-read.patch \
	darwin/readme_mac_powerpc.txt darwin/readme_mac_intel.txt \
	doc_src/testdisk.8.in doc_src/photorec.8.in doc_src/fidentify.8.in documentation.html \
	dos/readme.txt \
	ico/photorec.ico ico/testdisk.ico \
	linux/testdisk.spec.in \
	src/icon_ph.rc src/icon_qph.rc src/icon_tst.rc \
	src/photorec_64x64.png \
	src/gnome/README \
	src/gnome/application-exit.png  \
	src/gnome/drive-harddisk.png \
	src/gnome/folder.png \
	src/gnome/go-next.png \
	src/gnome/go-previous.png \
	src/gnome/application-x-cd-image.png \
	win/readme.txt win/photorec_win.exe.manifest win/qphotorec_win.exe.manifest \
	win/testdisk_win.exe.manifest \
	Android.mk jni/Android.mk

AUTOMAKE_OPTIONS = gnits

man_MANS		= doc_src/testdisk.8 doc_src/photorec.8 doc_src/fidentify.8

install-data-hook:
	$(mkinstalldirs) $(DESTDIR)$(datadir)/doc/$(PACKAGE)-$(VERSION)
	$(INSTALL_DATA) $(top_srcdir)/AUTHORS $(top_srcdir)/ChangeLog $(top_srcdir)/NEWS $(top_srcdir)/README $(top_srcdir)/THANKS $(top_srcdir)/documentation.html $(DESTDIR)$(datadir)/doc/$(PACKAGE)-$(VERSION)/

uninstall-hook:
	rm -rf $(DESTDIR)$(datadir)/doc/$(PACKAGE)-$(VERSION)

static:
	rm -f src/testdisk src/testdisk.exe src/photorec src/photorec.exe src/fidentify src/fidentify.exe src/qphotorec src/qphotorec.exe
	$(MAKE) LDFLAGS="$(LDFLAGS) -static" LIBS="$(PTHREAD_LIBS) $(LIBS)" CFLAGS="$(PTHREAD_CFLAGS) $(CFLAGS)" CXXFLAGS="$(PTHREAD_CFLAGS) $(CXXFLAGS)"

smallstatic:
	$(MAKE) static
	(cd src && $(MAKE) small) || exit 1;

extras:
	(cd src && $(MAKE) extras) || exit 1;

extrasstatic:
#	rm -f src/fidentify src/fidentify.exe
	$(MAKE) LDFLAGS="$(LDFLAGS) -static" LIBS="$(PTHREAD_LIBS) $(LIBS)" CFLAGS="$(PTHREAD_CFLAGS) $(CFLAGS)" CXXFLAGS="$(PTHREAD_CFLAGS) $(CXXFLAGS)" extras

DISTCLEANFILES = *~ core
