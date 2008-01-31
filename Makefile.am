
SUBDIRS = src

EXTRA_DIST = AUTHORS COPYING ChangeLog INFO INSTALL NEWS README THANKS compile.sh progsreiserfs-journal.patch \
	darwin/readme.txt \
	doc_src/testdisk.1.in doc_src/photorec.1.in doc \
	dos/readme.txt \
	linux/testdisk.spec.in \
	src/icon_ph.rc src/icon_tst.rc \
	win/readme.txt

AUTOMAKE_OPTIONS = gnits

man_MANS		= doc_src/testdisk.1 doc_src/photorec.1

#dist-hook: linux/testdisk.spec
#	cp linux/testdisk.spec $(distdir)

#libtool: $(LIBTOOL_DEPS)
#	$(SHELL) ./config.status --recheck

install-data-hook:
	$(mkinstalldirs) $(DESTDIR)$(datadir)/doc/$(PACKAGE)-$(VERSION)
	$(mkinstalldirs) $(DESTDIR)$(datadir)/doc/$(PACKAGE)-$(VERSION)/html
	$(INSTALL_DATA) $(top_srcdir)/AUTHORS $(top_srcdir)/ChangeLog $(top_srcdir)/NEWS $(top_srcdir)/README $(top_srcdir)/THANKS $(DESTDIR)$(datadir)/doc/$(PACKAGE)-$(VERSION)/
	$(INSTALL_DATA) $(top_srcdir)/doc/*.html $(DESTDIR)$(datadir)/doc/$(PACKAGE)-$(VERSION)/html
	$(INSTALL_DATA) $(top_srcdir)/doc/*.gif $(DESTDIR)$(datadir)/doc/$(PACKAGE)-$(VERSION)/html
	$(INSTALL_DATA) $(top_srcdir)/doc/*.png $(DESTDIR)$(datadir)/doc/$(PACKAGE)-$(VERSION)/html

uninstall-hook:
	rm -rf $(DESTDIR)$(datadir)/doc/$(PACKAGE)-$(VERSION)

static:
	rm -f src/testdisk src/photorec src/testdisk.exe src/photorec.exe
	$(MAKE) LDFLAGS="$(LDFLAGS) -static"

smallstatic:
	$(MAKE) static
	(cd src && $(MAKE) small) || exit 1;

DISTCLEANFILES = *~ core
