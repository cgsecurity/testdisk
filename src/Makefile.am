.rc.o:
	$(WINDRES) --include-dir $(srcdir) $< $@ 

if USEICON
ICON_TESTDISK=icon_tst.rc ../icons/testdisk.ico ../win/testdisk_win.exe.manifest
ICON_PHOTOREC=icon_ph.rc ../icons/photorec.ico ../win/photorec_win.exe.manifest
ICON_QPHOTOREC=icon_qph.rc ../icons/photorec.ico ../win/qphotorec_win.exe.manifest
endif

if USEQT
  QPHOTOREC=qphotorec
endif

bin_PROGRAMS		= testdisk photorec fidentify $(QPHOTOREC)
EXTRA_PROGRAMS		= photorecf

base_C			= autoset.c common.c crc.c ewf.c fnctdsk.c hdaccess.c hdcache.c hdwin32.c hidden.c hpa_dco.c intrf.c iso.c list_sort.c log.c log_part.c misc.c msdos.c parti386.c partgpt.c parthumax.c partmac.c partsun.c partnone.c partxbox.c io_redir.c ntfs_io.c ntfs_utl.c partauto.c sudo.c unicode.c win32.c
base_H			= alignio.h autoset.h common.h crc.h ewf.h fnctdsk.h hdaccess.h hdwin32.h hidden.h guid_cmp.h guid_cpy.h hdcache.h hpa_dco.h intrf.h iso.h iso9660.h lang.h list.h list_sort.h log.h log_part.h misc.h types.h io_redir.h msdos.h ntfs_utl.h parti386.h partgpt.h parthumax.h partmac.h partsun.h partxbox.h partauto.h sudo.h unicode.h win32.h

fs_C			= analyse.c bfs.c bsd.c btrfs.c cramfs.c exfat.c fat.c fat_common.c fatx.c ext2.c ext2_common.c jfs.c gfs2.c hfs.c hfsp.c hpfs.c luks.c lvm.c md.c netware.c ntfs.c rfs.c savehdr.c sun.c swap.c sysv.c ufs.c vmfs.c wbfs.c xfs.c zfs.c
fs_H			= analyse.h bfs.h bsd.h btrfs.h cramfs.h exfat.h fat.h fat_common.h fatx.h ext2.h ext2_common.h jfs_superblock.h jfs.h gfs2.h hfs.h hfsp.h hpfs.h luks.h lvm.h md.h netware.h ntfs.h rfs.h savehdr.h sun.h swap.h sysv.h ufs.h vmfs.h wbfs.h xfs.h zfs.h

testdisk_ncurses_C	= addpart.c addpartn.c adv.c askloc.c chgarch.c chgarchn.c chgtype.c chgtypen.c dimage.c dirn.c dirpart.c diskacc.c diskcapa.c edit.c ext2_sb.c ext2_sbn.c fat1x.c fat32.c fat_adv.c fat_cluster.c fatn.c geometry.c geometryn.c godmode.c hiddenn.c intrface.c intrfn.c nodisk.c ntfs_adv.c ntfs_fix.c ntfs_udl.c parti386n.c partgptn.c partmacn.c partsunn.c partxboxn.c tanalyse.c tbanner.c tdelete.c tdiskop.c tdisksel.c testdisk.c texfat.c thfs.c tload.c tlog.c tmbrcode.c tntfs.c toptions.c tpartwr.c 
testdisk_ncurses_H	= addpart.h addpartn.h adv.h askloc.h chgarch.h chgarchn.h chgtype.h chgtypen.h dimage.h dirn.h dirpart.h diskacc.h diskcapa.h edit.h ext2_sb.h ext2_sbn.h fat1x.h fat32.h fat_adv.h fat_cluster.h fatn.h geometry.h geometryn.h godmode.h hiddenn.h intrface.h intrfn.h nodisk.h ntfs_fix.h ntfs_udl.h partgptn.h parti386n.h partmacn.h partsunn.h partxboxn.h tanalyse.h tdelete.h tdiskop.h tdisksel.h texfat.h thfs.h tload.h tlog.h tmbrcode.h tntfs.h toptions.h tpartwr.h 

testdisk_SOURCES	= $(base_C) $(base_H) $(fs_C) $(fs_H) $(testdisk_ncurses_C) $(testdisk_ncurses_H) dir.c dir.h exfat_dir.c exfat_dir.h ext2_dir.c ext2_dir.h ext2_inc.h fat_dir.c fat_dir.h ntfs_dir.c ntfs_dir.h ntfs_inc.h partgptw.c rfs_dir.c rfs_dir.h setdate.c setdate.h $(ICON_TESTDISK) next.c next.h

file_C			= filegen.c \
			  file_list.c \
			  file_1cd.c \
			  file_3dm.c \
			  file_7z.c \
			  file_DB.c \
			  file_a.c \
			  file_ab.c \
			  file_abcdp.c \
			  file_abr.c \
			  file_acb.c \
			  file_ace.c \
			  file_ado.c \
			  file_ahn.c \
			  file_aif.c \
			  file_all.c \
			  file_als.c \
			  file_amd.c \
			  file_amr.c \
			  file_apa.c \
			  file_ape.c \
			  file_apple.c \
			  file_ari.c \
			  file_arj.c \
			  file_asf.c \
			  file_asl.c \
			  file_asm.c \
			  file_atd.c \
			  file_au.c \
			  file_axx.c \
			  file_bac.c \
			  file_berkeley.c \
			  file_bim.c \
			  file_binvox.c \
			  file_bkf.c \
			  file_bld.c \
			  file_bmp.c \
			  file_bz2.c \
			  file_cab.c \
			  file_caf.c \
			  file_cam.c \
			  file_catdrawing.c \
			  file_cdt.c \
			  file_chm.c \
			  file_class.c \
			  file_cm.c \
			  file_compress.c \
			  file_cow.c \
			  file_crw.c \
			  file_csh.c \
			  file_ctg.c \
			  file_cwk.c \
			  file_d2s.c \
			  file_dad.c \
			  file_dar.c \
			  file_dat.c \
			  file_dbf.c \
			  file_dbn.c \
			  file_dcm.c \
			  file_ddf.c \
			  file_dex.c \
			  file_dim.c \
			  file_dir.c \
			  file_djv.c \
			  file_dmp.c \
			  file_doc.c \
			  file_dpx.c \
			  file_drw.c \
			  file_ds2.c \
			  file_dsc.c \
			  file_dss.c \
			  file_dta.c \
			  file_dump.c \
			  file_dv.c \
			  file_dwg.c \
			  file_dxf.c \
			  file_e01.c \
			  file_edb.c \
			  file_ecryptfs.c \
			  file_elf.c \
			  file_emf.c \
			  file_evt.c \
			  file_exe.c \
			  file_exs.c \
			  file_ext.c \
			  file_ext2.c \
			  file_fat.c \
			  file_fbf.c \
			  file_fbk.c \
			  file_fcp.c \
			  file_fcs.c \
			  file_fdb.c \
			  file_fds.c \
			  file_fh10.c \
			  file_fh5.c \
			  file_filevault.c \
			  file_fits.c \
			  file_flac.c \
			  file_flp.c \
			  file_flv.c \
			  file_fob.c \
			  file_fp5.c \
			  file_fp7.c \
			  file_freeway.c \
			  file_frm.c \
			  file_fs.c \
			  file_fwd.c \
			  file_gam.c \
			  file_gct.c \
			  file_gho.c \
			  file_gif.c \
			  file_gm6.c \
			  file_gp5.c \
			  file_gpg.c \
			  file_gz.c \
			  file_hdf.c \
			  file_hds.c \
			  file_hfsp.c \
			  file_hr9.c \
			  file_http.c \
			  file_icc.c \
			  file_ico.c \
			  file_ifo.c \
			  file_imb.c \
			  file_indd.c \
			  file_info.c \
			  file_iso.c \
			  file_it.c \
			  file_itu.c \
			  file_jpg.c \
			  file_kdb.c \
			  file_kdbx.c \
			  file_ldf.c \
			  file_lit.c \
			  file_lnk.c \
			  file_logic.c \
			  file_lso.c \
			  file_luks.c \
			  file_lxo.c \
			  file_lzh.c \
			  file_lzo.c \
			  file_m2ts.c \
			  file_mat.c \
			  file_max.c \
			  file_mb.c \
			  file_mcd.c \
			  file_mdb.c \
			  file_mdf.c \
			  file_mfa.c \
			  file_mfg.c \
			  file_mft.c \
			  file_mid.c \
			  file_mig.c \
			  file_mk5.c \
			  file_mkv.c \
			  file_mlv.c \
			  file_mobi.c \
			  file_mov.c \
			  file_mp3.c \
			  file_mpg.c \
			  file_mrw.c \
			  file_mus.c \
			  file_mxf.c \
			  file_myo.c \
			  file_mysql.c \
			  file_nds.c \
			  file_nes.c \
			  file_njx.c \
			  file_nk2.c \
			  file_nsf.c \
			  file_oci.c \
			  file_ogg.c \
			  file_one.c \
			  file_orf.c \
			  file_paf.c \
			  file_pap.c \
			  file_par2.c \
			  file_pcap.c \
			  file_pct.c \
			  file_pcx.c \
			  file_pdf.c \
			  file_pds.c \
			  file_pfx.c \
			  file_plt.c \
			  file_png.c \
			  file_pnm.c \
			  file_prc.c \
			  file_prt.c \
			  file_ps.c \
			  file_psb.c \
			  file_psd.c \
			  file_psf.c \
			  file_psp.c \
			  file_pst.c \
			  file_ptb.c \
			  file_ptf.c \
			  file_pyc.c \
			  file_pzf.c \
			  file_pzh.c \
			  file_qbb.c \
			  file_qdf.c \
			  file_qkt.c \
			  file_qxd.c \
			  file_r3d.c \
			  file_ra.c \
			  file_raf.c \
			  file_rar.c \
			  file_raw.c \
			  file_rdc.c \
			  file_reg.c \
			  file_res.c \
			  file_rfp.c \
			  file_riff.c \
			  file_rlv.c \
			  file_rm.c \
			  file_rns.c \
			  file_rpm.c \
			  file_rw2.c \
			  file_rx2.c \
			  file_save.c \
			  file_ses.c \
			  file_shn.c \
			  file_sib.c \
			  file_sig.c \
			  file_sit.c \
			  file_skd.c \
			  file_skp.c \
			  file_sp3.c \
			  file_spe.c \
			  file_spf.c \
			  file_spss.c \
			  file_sql.c \
			  file_sqm.c \
			  file_stl.c \
			  file_stu.c \
			  file_swf.c \
			  file_tar.c \
			  file_tax.c \
			  file_tib.c \
			  file_tiff.c \
			  file_tivo.c \
			  file_torrent.c \
			  file_tph.c \
			  file_tpl.c \
			  file_ttf.c \
			  file_txt.c \
			  file_tz.c \
			  file_v2i.c \
			  file_vault.c \
			  file_vdi.c \
			  file_veg.c \
			  file_vfb.c \
			  file_vmdk.c \
			  file_vmg.c \
			  file_wallet.c \
			  file_wdp.c \
			  file_wim.c \
			  file_win.c \
			  file_wks.c \
			  file_wmf.c \
			  file_wnk.c \
			  file_woff.c \
			  file_wpb.c \
			  file_wpd.c \
			  file_wtv.c \
			  file_wv.c \
			  file_x3f.c \
			  file_xcf.c \
			  file_xfi.c \
			  file_xm.c \
			  file_xsv.c \
			  file_xpt.c \
			  file_xv.c \
			  file_xz.c \
			  file_z2d.c \
			  file_zip.c

file_H			= ext2.h ext2_common.h filegen.h file_jpg.h file_sp3.h file_tar.h file_tiff.h file_txt.h ole.h pe.h suspend.h

photorec_C		= photorec.c phcfg.c addpart.c chgarch.c dir.c exfatp.c ext2grp.c ext2_dir.c ext2p.c fat_dir.c fatp.c file_found.c geometry.c ntfs_dir.c ntfsp.c pdisksel.c phcli.c poptions.c sessionp.c setdate.c dfxml.c

photorec_H		= photorec.h phcfg.h addpart.h chgarch.h dir.h exfatp.h ext2grp.h ext2p.h ext2_dir.h ext2_inc.h fat_dir.h fatp.h file_found.h geometry.h memmem.h ntfs_dir.h ntfsp.h ntfs_inc.h pdisksel.h phcli.h poptions.h sessionp.h setdate.h dfxml.h

photorec_ncurses_C	= addpartn.c askloc.c chgarchn.c chgtype.c chgtypen.c fat_cluster.c fat_unformat.c geometryn.c hiddenn.c intrfn.c nodisk.c parti386n.c partgptn.c partmacn.c partsunn.c partxboxn.c pbanner.c pblocksize.c pdiskseln.c pfree_whole.c phbf.c phbs.c phnc.c phrecn.c ppartseln.c psearchn.c
photorec_ncurses_H	= addpartn.h askloc.h chgarchn.h chgtype.h chgtypen.h fat_cluster.h fat_unformat.h geometryn.h hiddenn.h intrfn.h nodisk.h parti386n.h partgptn.h partmacn.h partsunn.h partxboxn.h pblocksize.h pdiskseln.h pfree_whole.h pnext.h phbf.h phbs.h phnc.h phrecn.h ppartseln.h psearch.h psearchn.h

photorec_SOURCES	= phmain.c $(photorec_C) $(photorec_H) $(photorec_ncurses_C) $(photorec_ncurses_H) $(file_C) $(file_H) $(base_C) $(base_H) partgptro.c $(fs_C) $(fs_H) $(ICON_PHOTOREC) suspend_no.c

photorecf_SOURCES	= phmain.c $(photorec_C) $(photorec_H) $(photorec_ncurses_C) $(photorec_ncurses_H) $(file_C) $(file_H) $(base_C) $(base_H) partgptro.c $(fs_C) $(fs_H) $(ICON_PHOTOREC) suspend.c

qphotorec_SOURCES	= qmainrec.cpp qphotorec.cpp qphotorec.h qphotorec.qrc qphbs.cpp qpsearch.cpp psearch.h chgtype.c chgtype.h $(photorec_C) $(photorec_H) $(file_C) $(file_H) $(base_C) $(base_H) partgptro.c $(fs_C) $(fs_H) $(ICON_QPHOTOREC) suspend_no.c

nodist_qphotorec_SOURCES = moc_qphotorec.cpp rcc_qphotorec.cpp

fidentify_SOURCES	= fidentify.c common.c common.h misc.c misc.h phcfg.c phcfg.h setdate.c setdate.h $(file_C) $(file_H) log.c log.h crc.c crc.h ext2_common.c fat_common.c fat_common.h suspend_no.c

CLEANFILES = $(nodist_qphotorec_SOURCES)
DISTCLEANFILES = *~ core

small: $(sbin_PROGRAMS) $(bin_PROGRAMS)
	$(STRIP) -s $(sbin_PROGRAMS) $(bin_PROGRAMS)

extras: $(EXTRA_PROGRAMS)

moc_qphotorec.cpp: qphotorec.h
	$(MOC) $< -o $@

rcc_qphotorec.cpp: qphotorec.qrc
	$(RCC) $< -o $@

Android.mk: Makefile.am
	androgenizer \
	-:PROJECT photorec \
	-:REL_TOP $(top_srcdir) -:ABS_TOP $(abs_top_srcdir) \
	-:EXECUTABLE photorec \
	-:SOURCES $(photorec_SOURCES) \
	-:CFLAGS $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CFLAGS) $(CFLAGS) \
	-:LDFLAGS $(photorec_LDADD) $(LIBS) \
	\
	-:PROJECT testdisk \
	-:REL_TOP $(top_srcdir) -:ABS_TOP $(abs_top_srcdir) \
	-:EXECUTABLE testdisk \
	-:SOURCES $(testdisk_SOURCES) \
	-:CFLAGS $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CFLAGS) $(CFLAGS) \
	-:LDFLAGS $(testdisk_LDADD) $(LIBS) \
> $@
