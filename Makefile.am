
SUBDIRS = src

EXTRA_DIST = AUTHORS COPYING ChangeLog INFO INSTALL NEWS README THANKS compile.sh progsreiserfs-journal.patch \
	darwin/readme_mac_powerpc.txt darwin/readme_mac_intel.txt \
	doc_src/testdisk.8.in doc_src/photorec.8.in doc \
	dos/readme.txt \
	ico/photorec.ico ico/testdisk.ico \
	linux/testdisk.spec.in \
	src/icon_ph.rc src/icon_tst.rc \
	win/readme.txt win/photorec_win.exe.manifest win/testdisk_win.exe.manifest

AUTOMAKE_OPTIONS = gnits

man_MANS		= doc_src/testdisk.8 doc_src/photorec.8

install-data-hook:
	$(mkinstalldirs) $(DESTDIR)$(datadir)/doc/$(PACKAGE)-$(VERSION)
	$(mkinstalldirs) $(DESTDIR)$(datadir)/doc/$(PACKAGE)-$(VERSION)/html
	$(INSTALL_DATA) $(top_srcdir)/AUTHORS $(top_srcdir)/ChangeLog $(top_srcdir)/NEWS $(top_srcdir)/README $(top_srcdir)/THANKS $(DESTDIR)$(datadir)/doc/$(PACKAGE)-$(VERSION)/
	$(INSTALL_DATA) $(top_srcdir)/doc/* $(DESTDIR)$(datadir)/doc/$(PACKAGE)-$(VERSION)/html

uninstall-hook:
	rm -rf $(DESTDIR)$(datadir)/doc/$(PACKAGE)-$(VERSION)

static:
	rm -f src/testdisk src/testdisk.exe src/photorec src/photorec.exe src/fidentify src/fidentify.exe
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
