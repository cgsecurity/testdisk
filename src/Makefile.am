.rc.o:
	$(WINDRES) --include-dir $(srcdir) $< $@ 

if USEICON
ICON_TESTDISK=icon_tst.rc ../ico/testdisk.ico
ICON_PHOTOREC=icon_ph.rc ../ico/photorec.ico
endif


sbin_PROGRAMS		= testdisk photorec
#diskcp

base_C			= common.c crc.c ewf.c fnctdsk.c hdaccess.c hdcache.c hdwin32.c hidden.c hpa_dco.c intrf.c log.c misc.c msdos.c parti386.c partgpt.c partmac.c partsun.c partnone.c partxbox.c chgtype.c io_redir.c ntfs_io.c ntfs_utl.c partauto.c sudo.c unicode.c win32.c
base_H			= alignio.h common.h crc.h ewf.h fnctdsk.h hdaccess.h hdwin32.h hidden.h guid_cmp.h guid_cpy.h hdcache.h hpa_dco.h intrf.h intrfn.h lang.h log.h misc.h types.h chgtype.h io_redir.h msdos.h ntfs_utl.h partgpt.h partmac.h partnone.h partxbox.h partauto.h sudo.h unicode.h win32.h

fs_C			= analyse.c bfs.c bsd.c cramfs.c fat.c fatx.c ext2.c jfs.c hfs.c hfsp.c luks.c lvm.c md.c netware.c ntfs.c rfs.c savehdr.c sun.c swap.c sysv.c ufs.c xfs.c 
fs_H			= analyse.h bfs.h bsd.h cramfs.h fat.h fatx.h ext2.h jfs_superblock.h jfs.h hfs.h hfsp.h luks.h lvm.h md.h netware.h ntfs.h rfs.h savehdr.h sun.h swap.h sysv.h ufs.h xfs.h 

testdisk_SOURCES	= testdisk.c $(base_C) $(base_H) $(fs_C) $(fs_H) testdisk.h adv.c adv.h dir.c dir.h dirpart.c dirpart.h diskacc.c diskacc.h edit.c edit.h ext2_dir.c ext2_dir.h ext2_inc.h ext2_sb.c ext2_sb.h fat1x.c fat1x.h fat32.c fat32.h fat_adv.c fat_adv.h fat_dir.c fat_dir.h geometry.c godmode.c godmode.h intrface.c diskcapa.c diskcapa.h intrface.h ntfs_adv.c ntfs_dir.c ntfs_dir.h ntfs_fix.c ntfs_inc.h rfs_dir.c rfs_dir.h $(ICON_TESTDISK) next.c next.h dimage.c dimage.h ntfs_udl.c ntfs_udl.h tanalyse.c tanalyse.h tdelete.c tdelete.h tdisksel.c tdisksel.h tdiskop.c tdiskop.h thfs.c thfs.h tload.c tload.h tlog.c tlog.h tmbrcode.c tmbrcode.h tntfs.c tntfs.h toptions.c toptions.h tpartwr.c tpartwr.h

photorec_SOURCES	= photorec.c photorec.h phcfg.c phcfg.h phrecn.c phrecn.h dir.c dir.h ext2grp.c ext2grp.h ext2p.c ext2p.h ext2_dir.c ext2_dir.h ext2_inc.h fat_dir.c fat_dir.h fatp.c fatp.h filegen.c filegen.h file_7z.c file_a.c file_ab.c file_abcdp.c file_ace.c file_ahn.c file_aif.c file_all.c file_als.c file_amd.c file_amr.c file_arj.c file_asf.c file_asm.c file_atd.c file_au.c file_bkf.c file_bld.c file_bmp.c file_bz2.c file_cab.c file_cam.c file_chm.c file_cm.c file_compress.c file_crw.c file_ctg.c file_cwk.c file_dat.c file_dbf.c file_dim.c file_dir.c file_djv.c file_doc.c file_dpx.c file_drw.c file_ds2.c file_dsc.c file_dss.c file_dta.c file_dump.c file_dv.c file_dwg.c file_elf.c file_emf.c file_evt.c file_exe.c pe.h file_ext.c file_fcp.c file_fcs.c file_fbk.c file_fdb.c file_fh10.c file_fh5.c file_fits.c file_flac.c file_flv.c file_fob.c file_frm.c file_fs.c file_gho.c file_gif.c file_gpg.c file_gz.c file_ifo.c file_imb.c file_indd.c file_iso.c file_itu.c file_jpg.c file_jpg.h file_kdb.c file_lnk.c file_m2ts.c file_max.c file_mb.c file_mcd.c file_mdb.c file_mdf.c file_mfg.c file_mid.c file_mkv.c file_mov.c file_mp3.c file_mpg.c file_mrw.c file_mus.c file_mysql.c file_njx.c file_ogg.c file_one.c file_orf.c file_paf.c file_pap.c file_pcap.c file_pct.c file_pcx.c file_pdf.c file_pfx.c file_png.c file_prc.c file_prt.c file_ps.c file_psd.c file_psp.c file_pst.c file_ptb.c file_qbb.c file_qdf.c file_qxd.c file_ra.c file_raf.c file_rar.c file_raw.c file_rdc.c file_reg.c file_res.c file_riff.c file_rm.c file_rns.c file_rpm.c file_sib.c file_sit.c file_skp.c file_sp3.c file_sp3.h file_spe.c file_spss.c file_sql.c file_sqm.c file_stl.c file_stu.c file_swf.c file_tar.c file_tar.h file_tax.c file_tib.c file_tiff.c file_tph.c file_txt.c file_veg.c file_vmdk.c file_wks.c file_wmf.c file_wnk.c file_wpd.c file_wv.c file_x3f.c file_xcf.c file_xm.c file_xsv.c file_zip.c memmem.h geometry.c list.c list.h ole.h ntfs_dir.c ntfs_dir.h ntfsp.c ntfsp.h ntfs_inc.h pblocksize.c pblocksize.h pdisksel.c pdisksel.h pfree_whole.c pfree_whole.h ppartsel.c ppartsel.h sessionp.c sessionp.h $(base_C) $(base_H) $(fs_C) $(fs_H) $(ICON_PHOTOREC)

#diskcp_SOURCES	= diskcp.c types.h

DISTCLEANFILES = *~ core

small: $(sbin_PROGRAMS) $(bin_PROGRAMS)
	$(STRIP) -s $(sbin_PROGRAMS) $(bin_PROGRAMS)

