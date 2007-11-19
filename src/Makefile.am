.rc.o:
	$(WINDRES) --include-dir $(srcdir) $< $@ 

if USEICON
ICON_TESTDISK=icon_tst.rc ../doc/favicon.ico
ICON_PHOTOREC=icon_ph.rc ../doc/photorec.ico
endif


sbin_PROGRAMS		= testdisk photorec
#diskcp

base_C			= common.c crc.c ewf.c fnctdsk.c hdaccess.c hdcache.c intrf.c log.c parti386.c partgpt.c partmac.c partsun.c partnone.c partxbox.c chgtype.c io_redir.c ntfs_io.c ntfs_utl.c partauto.c unicode.c
base_H			= common.h crc.h ewf.h fnctdsk.h hdaccess.h guid_cmp.h guid_cpy.h hdcache.h intrf.h intrfn.h lang.h log.h types.h chgtype.h io_redir.h ntfs_utl.h partgpt.h partmac.h partnone.h partxbox.h partauto.h unicode.h

fs_C			= analyse.c bfs.c bsd.c cramfs.c fat.c fatx.c ext2.c jfs.c hfs.c hfsp.c luks.c lvm.c md.c netware.c ntfs.c rfs.c savehdr.c sun.c swap.c sysv.c ufs.c xfs.c 
fs_H			= analyse.h bfs.h bsd.h cramfs.h fat.h fatx.h ext2.h jfs_superblock.h jfs.h hfs.h hfsp.h luks.h lvm.h md.h netware.h ntfs.h rfs.h savehdr.h sun.h swap.h sysv.h ufs.h xfs.h 

testdisk_SOURCES	= testdisk.c $(base_C) $(base_H) $(fs_C) $(fs_H) testdisk.h adv.c adv.h dir.c dir.h dirpart.c dirpart.h edit.c edit.h ext2_dir.c ext2_dir.h ext2_inc.h fat_adv.c fat_dir.c fat_dir.h geometry.c godmode.c godmode.h intrface.c intrface.h ntfs_adv.c ntfs_dir.c ntfs_dir.h ntfs_fix.c ntfs_inc.h rfs_dir.c rfs_dir.h $(ICON_TESTDISK) next.c next.h
#ntfs_udl.c ntfs_udl.h


photorec_SOURCES	= photorec.c photorec.h phrecn.c phrecn.h dir.c dir.h ext2p.c ext2p.h ext2_dir.c ext2_dir.h ext2_inc.h fat_dir.c fat_dir.h fatp.c fatp.h filegen.c filegen.h file_7z.c file_a.c file_ab.c file_ace.c file_aif.c file_all.c file_asf.c file_au.c file_bkf.c file_bld.c file_bmp.c file_bz2.c file_cab.c file_cam.c file_cm.c file_crw.c file_ctg.c file_cwk.c file_dat.c file_dbf.c file_dir.c file_djv.c file_doc.c file_dpx.c file_dsc.c file_dta.c file_dv.c file_dwg.c file_elf.c file_evt.c file_exe.c pe.h file_ext.c file_fh10.c file_fh5.c file_flac.c file_flv.c file_fs.c file_gif.c file_gz.c file_imb.c file_indd.c file_dump.c file_itu.c file_jpg.c file_jpg.h file_kdb.c file_max.c file_mdb.c file_mdf.c file_mid.c file_mkv.c file_mov.c file_mp3.c file_mpg.c file_mrw.c file_mus.c file_mysql.c file_njx.c file_ogg.c file_orf.c file_pap.c file_pcx.c file_pdf.c file_png.c file_prc.c file_ps.c file_psd.c file_pst.c file_ptb.c file_qbb.c file_qdf.c file_qxd.c file_ra.c file_raf.c file_rar.c file_raw.c file_rdc.c file_reg.c file_riff.c file_rm.c file_rns.c file_rpm.c file_sit.c file_skp.c file_spe.c file_spss.c file_stu.c file_swf.c file_tar.c file_tib.c file_tiff.c file_txt.c file_vmdk.c file_wpd.c file_wmf.c file_x3f.c file_xcf.c file_xm.c file_zip.c geometry.c list.c list.h ole.h ntfs_dir.c ntfs_dir.h ntfsp.c ntfsp.h ntfs_inc.h sessionp.c sessionp.h $(base_C) $(base_H) $(fs_C) $(fs_H) $(ICON_PHOTOREC)

#diskcp_SOURCES	= diskcp.c types.h

DISTCLEANFILES = *~ core

small: $(sbin_PROGRAMS) $(bin_PROGRAMS)
	$(STRIP) -s $(sbin_PROGRAMS) $(bin_PROGRAMS)

