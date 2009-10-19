.rc.o:
	$(WINDRES) --include-dir $(srcdir) $< $@ 

if USEICON
ICON_TESTDISK=icon_tst.rc ../ico/testdisk.ico
ICON_PHOTOREC=icon_ph.rc ../ico/photorec.ico
endif

if USEQT
  QPHOTOREC=qphotorec
endif

sbin_PROGRAMS		= testdisk photorec fidentify $(QPHOTOREC)
EXTRA_PROGRAMS		= 

base_C			= autoset.c common.c crc.c ewf.c fnctdsk.c hdaccess.c hdcache.c hdwin32.c hidden.c hpa_dco.c intrf.c iso.c log.c log_part.c misc.c msdos.c parti386.c partgpt.c partmac.c partsun.c partnone.c partxbox.c io_redir.c ntfs_io.c ntfs_utl.c partauto.c sudo.c unicode.c win32.c
base_H			= alignio.h autoset.h common.h crc.h ewf.h fnctdsk.h hdaccess.h hdwin32.h hidden.h guid_cmp.h guid_cpy.h hdcache.h hpa_dco.h intrf.h iso.h iso9660.h lang.h log.h log_part.h misc.h types.h io_redir.h msdos.h ntfs_utl.h parti386.h partgpt.h partmac.h partsun.h partxbox.h partauto.h sudo.h unicode.h win32.h

fs_C			= analyse.c bfs.c bsd.c cramfs.c exfat.c fat.c fatx.c ext2.c jfs.c hfs.c hfsp.c hpfs.c luks.c lvm.c md.c netware.c ntfs.c rfs.c savehdr.c sun.c swap.c sysv.c ufs.c xfs.c zfs.c
fs_H			= analyse.h bfs.h bsd.h cramfs.h exfat.h fat.h fatx.h ext2.h jfs_superblock.h jfs.h hfs.h hfsp.h hpfs.h luks.h lvm.h md.h netware.h ntfs.h rfs.h savehdr.h sun.h swap.h sysv.h ufs.h xfs.h zfs.h

testdisk_ncurses_C	= addpart.c adv.c askloc.c chgtype.c chgtypen.c dimage.c dirn.c dirpart.c diskacc.c diskcapa.c edit.c ext2_sb.c ext2_sbn.c fat1x.c fat32.c fat_adv.c fat_cluster.c fatn.c geometry.c godmode.c hiddenn.c intrface.c intrfn.c nodisk.c ntfs_adv.c ntfs_fix.c ntfs_udl.c parti386n.c partgptn.c partmacn.c partsunn.c partxboxn.c tanalyse.c tbanner.c tdelete.c tdiskop.c tdisksel.c testdisk.c thfs.c tload.c tlog.c tmbrcode.c tntfs.c toptions.c tpartwr.c 
testdisk_ncurses_H	= addpart.h adv.h askloc.h chgtype.h chgtypen.h dimage.h dirn.h dirpart.h diskacc.h diskcapa.h edit.h ext2_sb.h ext2_sbn.h fat1x.h fat32.h fat_adv.h fat_cluster.h fatn.h geometry.h godmode.h hiddenn.h intrface.h intrfn.h nodisk.h ntfs_udl.h partgptn.h parti386n.h partmacn.h partsunn.h partxboxn.h tanalyse.h tdelete.h tdiskop.h tdisksel.h thfs.h tload.h tlog.h tmbrcode.h tntfs.h toptions.h tpartwr.h 

testdisk_SOURCES	= $(base_C) $(base_H) $(fs_C) $(fs_H) $(testdisk_ncurses_C) $(testdisk_ncurses_H) dir.c dir.h ext2_dir.c ext2_dir.h ext2_inc.h fat_dir.c fat_dir.h ntfs_dir.c ntfs_dir.h ntfs_inc.h partgptw.c rfs_dir.c rfs_dir.h setdate.c setdate.h $(ICON_TESTDISK) next.c next.h

file_C			= filegen.c \
			  file_list.c \
			  file_1cd.c \
			  file_7z.c \
			  file_DB.c \
			  file_a.c \
			  file_ab.c \
			  file_abcdp.c \
			  file_ace.c \
			  file_ahn.c \
			  file_aif.c \
			  file_all.c \
			  file_als.c \
			  file_amd.c \
			  file_amr.c \
			  file_apa.c \
			  file_ape.c \
			  file_apple.c \
			  file_arj.c \
			  file_asf.c \
			  file_asm.c \
			  file_atd.c \
			  file_au.c \
			  file_bac.c \
			  file_bkf.c \
			  file_bld.c \
			  file_bmp.c \
			  file_bz2.c \
			  file_cab.c \
			  file_cam.c \
			  file_chm.c \
			  file_class.c \
			  file_cm.c \
			  file_compress.c \
			  file_cow.c \
			  file_crw.c \
			  file_ctg.c \
			  file_cwk.c \
			  file_d2s.c \
			  file_dat.c \
			  file_dbf.c \
			  file_dim.c \
			  file_dir.c \
			  file_djv.c \
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
			  file_elf.c \
			  file_emf.c \
			  file_evt.c \
			  file_exe.c \
			  file_ext.c \
			  file_fat.c \
			  file_fbk.c \
			  file_fcp.c \
			  file_fcs.c \
			  file_fdb.c \
			  file_fh10.c \
			  file_fh5.c \
			  file_fits.c \
			  file_flac.c \
			  file_flp.c \
			  file_flv.c \
			  file_fob.c \
			  file_fp5.c \
			  file_fp7.c \
			  file_frm.c \
			  file_fs.c \
			  file_gho.c \
			  file_gif.c \
			  file_gp5.c \
			  file_gpg.c \
			  file_gz.c \
			  file_hds.c \
			  file_hr9.c \
			  file_ico.c \
			  file_ifo.c \
			  file_imb.c \
			  file_indd.c \
			  file_iso.c \
			  file_itu.c \
			  file_jpg.c \
			  file_kdb.c \
			  file_ldf.c \
			  file_lnk.c \
			  file_logic.c \
			  file_m2ts.c \
			  file_max.c \
			  file_mb.c \
			  file_mcd.c \
			  file_mdb.c \
			  file_mdf.c \
			  file_mfa.c \
			  file_mfg.c \
			  file_mid.c \
			  file_mk5.c \
			  file_mkv.c \
			  file_mov.c \
			  file_mp3.c \
			  file_mpg.c \
			  file_mrw.c \
			  file_mus.c \
			  file_mxf.c \
			  file_mysql.c \
			  file_njx.c \
			  file_nk2.c \
			  file_ogg.c \
			  file_one.c \
			  file_orf.c \
			  file_paf.c \
			  file_pap.c \
			  file_pcap.c \
			  file_pct.c \
			  file_pcx.c \
			  file_pdf.c \
			  file_pfx.c \
			  file_png.c \
			  file_prc.c \
			  file_prt.c \
			  file_ps.c \
			  file_psd.c \
			  file_psp.c \
			  file_pst.c \
			  file_ptb.c \
			  file_pyc.c \
			  file_pzf.c \
			  file_qbb.c \
			  file_qdf.c \
			  file_qxd.c \
			  file_r3d.c \
			  file_ra.c \
			  file_raf.c \
			  file_rar.c \
			  file_raw.c \
			  file_rdc.c \
			  file_reg.c \
			  file_res.c \
			  file_riff.c \
			  file_rm.c \
			  file_rns.c \
			  file_rpm.c \
			  file_rw2.c \
			  file_ses.c \
			  file_sib.c \
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
			  file_tph.c \
			  file_ttf.c \
			  file_txt.c \
			  file_tz.c \
			  file_veg.c \
			  file_vmdk.c \
			  file_wdp.c \
			  file_wks.c \
			  file_wmf.c \
			  file_wnk.c \
			  file_wpd.c \
			  file_wv.c \
			  file_x3f.c \
			  file_xcf.c \
			  file_xm.c \
			  file_xsv.c \
			  file_xpt.c \
			  file_xv.c \
			  file_zip.c 

file_H			= list.h file_jpg.h file_tar.h file_sp3.h file_tiff.h filegen.h pe.h ole.h ext2.h

photorec_C		= photorec.c phcfg.c dir.c ext2grp.c ext2_dir.c ext2p.c fat_dir.c fatp.c file_found.c list.c ntfs_dir.c ntfsp.c sessionp.c setdate.c

photorec_H		= photorec.h phcfg.h dir.h ext2grp.h ext2p.h ext2_dir.h ext2_inc.h fat_dir.h fatp.h file_found.h memmem.h ntfs_dir.h ntfsp.h ntfs_inc.h sessionp.h setdate.h

photorec_ncurses_C	= addpart.c askloc.c chgtype.c chgtypen.c fat_cluster.c fat_unformat.c geometry.c hiddenn.c intrfn.c nodisk.c parti386n.c partgptn.c partmacn.c partsunn.c partxboxn.c pbanner.c pblocksize.c pdisksel.c pfree_whole.c phbf.c phbs.c phnc.c phrecn.c ppartsel.c
photorec_ncurses_H	= addpart.h askloc.h chgtype.h chgtypen.h fat_cluster.h fat_unformat.h geometry.h hiddenn.h intrfn.h nodisk.h parti386n.h partgptn.h partmacn.h partsunn.h partxboxn.h pblocksize.h pdisksel.h pfree_whole.h pnext.h phbf.h phbs.h phnc.h phrecn.h ppartsel.h

photorec_SOURCES	= phmain.c $(photorec_C) $(photorec_H) $(photorec_ncurses_C) $(photorec_ncurses_H) $(file_C) $(file_H) $(base_C) $(base_H) partgptro.c $(fs_C) $(fs_H) $(ICON_PHOTOREC)

qphotorec_SOURCES	= qmainrec.cpp qphotorec.cpp qphotorec.h chgtype.c chgtype.h $(photorec_C) $(photorec_H) $(file_C) $(file_H) $(base_C) $(base_H) partgptro.c $(fs_C) $(fs_H) $(ICON_PHOTOREC)

fidentify_SOURCES	= fidentify.c common.c common.h phcfg.c phcfg.h setdate.c setdate.h $(file_C) $(file_H) log.c log.h crc.c crc.h fat_common.c

DISTCLEANFILES = *~ core

small: $(sbin_PROGRAMS) $(bin_PROGRAMS)
	$(STRIP) -s $(sbin_PROGRAMS) $(bin_PROGRAMS)

extras: $(EXTRA_PROGRAMS)

