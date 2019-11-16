.PRECIOUS: session_%.framac
FRAMA_C_FLAGS=-machdep x86_64 \
	  -warn-left-shift-negative \
	  -warn-right-shift-negative \
	  -warn-signed-downcast \
	  -warn-signed-overflow \
	  -warn-unsigned-downcast \
	  -warn-unsigned-overflow \
	  -rte \
	  -eva \
	  -eva-slevel 6 \
	  -eva-warn-undefined-pointer-comparison none \
	  -eva-ignore-recursive-calls \
	  -then \
	  -wp \
	  -wp-dynamic \
	  -wp-steps 100000 -wp-depth 100000 \
	  -wp-split -wp-literals \
	  -wp-timeout 20 -pp-annot \
	  -kernel-msg-key pp

SUBDIRS = icons man src
docdir ?= $(datadir)/doc/$(PACKAGE)

EXTRA_DIST = AUTHORS COPYING ChangeLog INFO INSTALL NEWS README.md README_dev_photorec.txt THANKS compile.sh \
	progsreiserfs-journal.patch progsreiserfs-file-read.patch \
	darwin/readme_mac_powerpc.txt darwin/readme_mac_intel.txt \
	documentation.html \
	dos/readme.txt \
	linux/testdisk.spec.in \
	linux/qphotorec.desktop \
	src/icon_ph.rc src/icon_qph.rc src/icon_tst.rc \
	src/photorec_64x64.png \
	src/gnome/README \
	src/gnome/application-exit.png  \
	src/gnome/application-x-cd-image.png \
	src/gnome/drive-harddisk.png \
	src/gnome/folder.png \
	src/gnome/go-next.png \
	src/gnome/go-previous.png \
	src/gnome/help-about.png \
	src/gnome/image-x-generic.png \
	src/lang/qphotorec.ca.ts \
	src/lang/qphotorec.es.ts \
	src/lang/qphotorec.fr.ts \
	src/lang/qphotorec.it.ts \
	src/lang/qphotorec.pt.ts \
	src/lang/qphotorec.ru.ts \
	src/lang/qphotorec.zh_TW.ts \
	win/readme.txt win/photorec_win.exe.manifest win/qphotorec_win.exe.manifest \
	win/testdisk_win.exe.manifest \
	Android.mk jni/Android.mk \
	.travis.yml

install-data-hook:
	$(mkinstalldirs) $(DESTDIR)$(docdir)
	$(INSTALL_DATA) $(top_srcdir)/AUTHORS $(top_srcdir)/ChangeLog $(top_srcdir)/NEWS $(top_srcdir)/README.md $(top_srcdir)/THANKS $(top_srcdir)/documentation.html $(DESTDIR)$(docdir)
if USEQT
	$(mkinstalldirs) $(DESTDIR)$(datadir)/applications
	$(INSTALL_DATA) $(top_srcdir)/linux/qphotorec.desktop $(DESTDIR)$(datadir)/applications
endif

uninstall-hook:
	rm -rf $(DESTDIR)$(docdir)
if USEQT
	rm -f $(DESTDIR)$(datadir)/applications/qphotorec.desktop
endif

static:
	rm -f src/testdisk src/testdisk.exe src/photorec src/photorec.exe src/fidentify src/fidentify.exe src/qphotorec src/qphotorec.exe
	$(MAKE) LDFLAGS="$(LDFLAGS) -static" LIBS="$(PTHREAD_LIBS) $(LIBS)" CFLAGS="$(PTHREAD_CFLAGS) $(CFLAGS)" CXXFLAGS="$(PTHREAD_CFLAGS) $(CXXFLAGS)"

smallstatic:
	$(MAKE) static
	(cd src && $(MAKE) small) || exit 1;

extras:
	(cd src && $(MAKE) extras) || exit 1;

extrasstatic:
	$(MAKE) LDFLAGS="$(LDFLAGS) -static" LIBS="$(PTHREAD_LIBS) $(LIBS)" CFLAGS="$(PTHREAD_CFLAGS) $(CFLAGS)" CXXFLAGS="$(PTHREAD_CFLAGS) $(CXXFLAGS)" extras

session_doc.framac: src/file_doc.c src/common.c src/filegen.c src/log.c src/setdate.c
	gcc -W -Wall -DMAIN_doc -DHAVE_CONFIG_H -O -o demo -I. $^
	frama-c $^ -cpp-extra-args="-DMAIN_doc -DHAVE_CONFIG_H -D__x86_64__" $(FRAMA_C_FLAGS) -save $@

session_id3.framac: src/file_mp3.c src/common.c src/filegen.c src/log.c
	gcc -W -Wall -DMAIN_id3 -DHAVE_CONFIG_H -O -o demo -I. $^
	frama-c $^ -cpp-extra-args="-DMAIN_id3 -DHAVE_CONFIG_H -D__x86_64__" $(FRAMA_C_FLAGS) -save $@

session_jpg.framac: src/file_jpg.c src/file_tiff.c src/file_tiff_be.c src/file_tiff_le.c src/common.c src/filegen.c src/log.c src/suspend_no.c src/setdate.c
	gcc -W -Wall -DMAIN_jpg -DHAVE_CONFIG_H -O -o demo -I. $^ -ljpeg
	frama-c $^ -cpp-extra-args="-DMAIN_jpg -DHAVE_CONFIG_H -D__x86_64__ -I/usr/include -I $(frama-c -print-path)/libc" $(FRAMA_C_FLAGS) -save $@

session_tiff_be.framac: src/file_tiff.c src/file_tiff_be.c src/file_tiff_le.c src/common.c src/filegen.c src/log.c
	gcc -W -Wall -DMAIN_tiff_le -DHAVE_CONFIG_H -O -o demo -I. $^
	frama-c $^ -cpp-extra-args="-DMAIN_tiff_be -DHAVE_CONFIG_H -D__x86_64__" $(FRAMA_C_FLAGS) -save $@

session_tiff_le.framac: src/file_tiff.c src/file_tiff_be.c src/file_tiff_le.c src/common.c src/filegen.c src/log.c
	gcc -W -Wall -DMAIN_tiff_le -DHAVE_CONFIG_H -O -o demo -I. $^
	frama-c $^ -cpp-extra-args="-DMAIN_tiff_le -DHAVE_CONFIG_H -D__x86_64__" $(FRAMA_C_FLAGS) -save $@

session_%.framac: src/file_%.c src/common.c src/filegen.c src/log.c
	gcc -W -Wall -DMAIN_$* -DHAVE_CONFIG_H -O -o demo -I. $^
	frama-c $^ -cpp-extra-args="-DMAIN_$* -DHAVE_CONFIG_H -D__x86_64__" $(FRAMA_C_FLAGS) -save $@

frama-c-%: session_%.framac
	frama-c-gui -load $^

cppcheck:
	cppcheck --quiet --enable=all -DHAVE_CONFIG_H -I$(builddir) -I/usr/include $(srcdir)/src

DISTCLEANFILES = *~ core
