.PRECIOUS: session_%.framac session_fidentify-%.framac session_photorec-%.framac
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
	  -wp-steps 100000 \
	  -wp-split -wp-literals \
	  -wp-timeout 2 -pp-annot \
	  -kernel-msg-key pp

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
EXTRA_PROGRAMS		= photorecf fuzzerfidentify

smallbase_C		= common.c crc.c ext2_common.c fat_common.c log.c misc.c setdate.c
smallbase_H		= common.h crc.h ext2_common.h fat_common.h log.h misc.h setdate.h
base_C			= $(smallbase_C) apfs_common.c autoset.c ewf.c fnctdsk.c hdaccess.c hdcache.c hdwin32.c hidden.c hpa_dco.c intrf.c iso.c list_sort.c log_part.c msdos.c parti386.c partgpt.c parthumax.c partmac.c partsun.c partnone.c partxbox.c ntfs_io.c ntfs_utl.c partauto.c sudo.c unicode.c win32.c
base_H			= $(smallbase_H) apfs_common.h alignio.h autoset.h ewf.h fnctdsk.h hdaccess.h hdwin32.h hidden.h guid_cmp.h guid_cpy.h hdcache.h hpa_dco.h intrf.h iso.h iso9660.h lang.h list.h list_add_sorted.h list_add_sorted_uniq.h list_sort.h log_part.h types.h msdos.h ntfs_utl.h parti386.h partgpt.h parthumax.h partmac.h partsun.h partxbox.h partauto.h sudo.h unicode.h win32.h

fs_C			= analyse.c apfs.c bfs.c bsd.c btrfs.c cramfs.c exfat.c ext2.c fat.c fatx.c f2fs.c jfs.c gfs2.c hfs.c hfsp.c hpfs.c luks.c lvm.c md.c netware.c ntfs.c refs.c rfs.c savehdr.c sun.c swap.c sysv.c ufs.c vmfs.c wbfs.c xfs.c zfs.c
fs_H			= analyse.h apfs.h bfs.h bsd.h btrfs.h cramfs.h exfat.h ext2.h fat.h fatx.h f2fs.h f2fs_fs.h jfs_superblock.h jfs.h gfs2.h hfs.h hfsp.h hpfs.h hfsp_struct.h luks.h luks_struct.h lvm.h md.h netware.h ntfs.h ntfs_struct.h refs.h rfs.h savehdr.h sun.h swap.h sysv.h ufs.h vmfs.h wbfs.h xfs.h xfs_struct.h zfs.h

testdisk_ncurses_C	= addpart.c addpartn.c adv.c askloc.c chgarch.c chgarchn.c chgtype.c chgtypen.c dimage.c dirn.c dirpart.c diskacc.c diskcapa.c edit.c ext2_sb.c ext2_sbn.c fat1x.c fat32.c fat_adv.c fat_cluster.c fatn.c geometry.c geometryn.c godmode.c hiddenn.c intrface.c intrfn.c io_redir.c nodisk.c ntfs_adv.c ntfs_fix.c ntfs_udl.c parti386n.c partgptn.c partmacn.c partsunn.c partxboxn.c tanalyse.c tbanner.c tdelete.c tdiskop.c tdisksel.c testdisk.c texfat.c thfs.c tload.c tlog.c tmbrcode.c tntfs.c toptions.c tpartwr.c
testdisk_ncurses_H	= addpart.h addpartn.h adv.h askloc.h chgarch.h chgarchn.h chgtype.h chgtypen.h dimage.h dirn.h dirpart.h diskacc.h diskcapa.h edit.h exfat.h ext2_sb.h ext2_sbn.h fat1x.h fat32.h fat_adv.h fat_cluster.h fatn.h geometry.h geometryn.h godmode.h hiddenn.h intrface.h intrfn.h io_redir.h nodisk.h ntfs_adv.h ntfs_fix.h ntfs_udl.h partgptn.h parti386n.h partmacn.h partsunn.h partxboxn.h tanalyse.h tdelete.h tdiskop.h tdisksel.h texfat.h thfs.h tload.h tlog.h tmbrcode.h tntfs.h toptions.h tpartwr.h

testdisk_SOURCES	= $(base_C) $(base_H) $(fs_C) $(fs_H) $(testdisk_ncurses_C) $(testdisk_ncurses_H) dir.c dir.h dir_common.h exfat_dir.c exfat_dir.h ext2_dir.c ext2_dir.h ext2_inc.h fat_dir.c fat_dir.h ntfs_dir.c ntfs_dir.h ntfs_inc.h partgptw.c rfs_dir.c rfs_dir.h $(ICON_TESTDISK) next.c next.h

file_C			= filegen.c \
			  file_list.c \
			  file_1cd.c \
			  file_3dm.c \
			  file_3ds.c \
			  file_7z.c \
			  file_DB.c \
			  file_a.c \
			  file_ab.c \
			  file_abr.c \
			  file_acb.c \
			  file_ace.c \
			  file_ado.c \
			  file_afdesign.c \
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
			  file_axp.c \
			  file_axx.c \
			  file_bac.c \
			  file_bdm.c \
			  file_berkeley.c \
			  file_bfa.c \
			  file_bim.c \
			  file_bin.c \
			  file_binvox.c \
			  file_bkf.c \
			  file_bld.c \
			  file_bmp.c \
			  file_bpg.c \
			  file_bvr.c \
			  file_bz2.c \
			  file_c4d.c \
			  file_cab.c \
			  file_caf.c \
			  file_cam.c \
			  file_catdrawing.c \
			  file_cdt.c \
			  file_che.c \
			  file_chm.c \
			  file_class.c \
			  file_clip.c \
			  file_cm.c \
			  file_compress.c \
			  file_cow.c \
			  file_cpi.c \
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
			  file_dovecot.c \
			  file_dpx.c \
			  file_drw.c \
			  file_drw2.c \
			  file_ds2.c \
			  file_ds_store.c \
			  file_dsc.c \
			  file_dss.c \
			  file_dst.c \
			  file_dta.c \
			  file_dump.c \
			  file_dv.c \
			  file_dvi.c \
			  file_dvr.c \
			  file_dwg.c \
			  file_dxf.c \
			  file_e01.c \
			  file_edb.c \
			  file_ecryptfs.c \
			  file_elf.c \
			  file_emf.c \
			  file_ess.c \
			  file_evt.c \
			  file_evtx.c \
			  file_exe.c \
			  file_exr.c \
			  file_exs.c \
			  file_ext.c \
			  file_ext2.c \
			  file_fat.c \
			  file_fbf.c \
			  file_fbk.c \
			  file_fbx.c \
			  file_fcp.c \
			  file_fcs.c \
			  file_fdb.c \
			  file_fds.c \
			  file_fh10.c \
			  file_fh5.c \
			  file_filevault.c \
			  file_fits.c \
			  file_fit.c \
			  file_flac.c \
			  file_flp.c \
			  file_flv.c \
			  file_fm.c \
			  file_fob.c \
			  file_fos.c \
			  file_fp5.c \
			  file_fp7.c \
			  file_freeway.c \
			  file_frm.c \
			  file_fs.c \
			  file_fwd.c \
			  file_fxp.c \
			  file_gam.c \
			  file_gct.c \
			  file_gho.c \
			  file_gi.c \
			  file_gif.c \
			  file_gm6.c \
			  file_gp2.c \
			  file_gp5.c \
			  file_gpg.c \
			  file_gpx.c \
			  file_gsm.c \
			  file_gz.c \
			  file_hdf.c \
			  file_hdf5.c \
			  file_hdr.c \
			  file_hds.c \
			  file_hfsp.c \
			  file_hm.c \
			  file_hr9.c \
			  file_http.c \
			  file_ibd.c \
			  file_icc.c \
			  file_icns.c \
			  file_ico.c \
			  file_ifo.c \
			  file_idx.c \
			  file_imb.c \
			  file_indd.c \
			  file_info.c \
			  file_iso.c \
			  file_it.c \
			  file_itu.c \
			  file_jks.c \
			  file_jpg.c \
			  file_jsonlz4.c \
			  file_kdb.c \
			  file_kdbx.c \
			  file_key.c \
			  file_ldf.c \
			  file_lit.c \
			  file_lnk.c \
			  file_logic.c \
			  file_lso.c \
			  file_luks.c \
			  file_lxo.c \
			  file_lz.c \
			  file_lzh.c \
			  file_lzo.c \
			  file_m2ts.c \
			  file_mat.c \
			  file_max.c \
			  file_mb.c \
			  file_mcd.c \
			  file_mdb.c \
			  file_mdf.c \
			  file_mdp.c \
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
			  file_mpl.c \
			  file_mrw.c \
			  file_msa.c \
			  file_mus.c \
			  file_mxf.c \
			  file_myo.c \
			  file_mysql.c \
			  file_nd2.c \
			  file_nds.c \
			  file_nes.c \
			  file_njx.c \
			  file_nk2.c \
			  file_nsf.c \
			  file_oci.c \
			  file_ogg.c \
			  file_one.c \
			  file_orf.c \
			  file_pa.c \
			  file_paf.c \
			  file_pap.c \
			  file_par2.c \
			  file_pcap.c \
			  file_pcb.c \
			  file_pct.c \
			  file_pcx.c \
			  file_pdb.c \
			  file_pdf.c \
			  file_pds.c \
			  file_pf.c \
			  file_pfx.c \
			  file_pgdump.c \
			  file_plist.c \
			  file_plr.c \
			  file_plt.c \
			  file_png.c \
			  file_pnm.c \
			  file_prc.c \
			  file_prd.c \
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
			  file_sdsk.c \
			  file_sdw.c \
			  file_ses.c \
			  file_sgcta.c \
			  file_shn.c \
			  file_shp.c \
			  file_sib.c \
			  file_sig.c \
			  file_sit.c \
			  file_skd.c \
			  file_skp.c \
			  file_snag.c \
			  file_sp3.c \
			  file_spe.c \
			  file_spf.c \
			  file_spss.c \
			  file_sql.c \
			  file_sqm.c \
			  file_steuer2014.c \
			  file_stl.c \
			  file_stu.c \
			  file_studio.c \
			  file_swf.c \
			  file_tar.c \
			  file_tax.c \
			  file_tg.c \
			  file_tib.c \
			  file_tiff.c \
			  file_tiff_be.c \
			  file_tiff_le.c \
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
			  file_vdj.c \
			  file_veg.c \
			  file_vfb.c \
			  file_vib.c \
			  file_vmdk.c \
			  file_vmg.c \
			  file_wad.c \
			  file_wallet.c \
			  file_wdp.c \
			  file_wee.c \
			  file_wim.c \
			  file_win.c \
			  file_wks.c \
			  file_wld.c \
			  file_wmf.c \
			  file_wnk.c \
			  file_woff.c \
			  file_wpb.c \
			  file_wpd.c \
			  file_wtv.c \
			  file_wv.c \
			  file_x3f.c \
			  file_x3i.c \
			  file_x4a.c \
			  file_xar.c \
			  file_xcf.c \
			  file_xfi.c \
			  file_xfs.c \
			  file_xm.c \
			  file_xml.c \
			  file_xsv.c \
			  file_xpt.c \
			  file_xv.c \
			  file_xz.c \
			  file_z2d.c \
			  file_zcode.c \
			  file_zip.c \
			  file_zpr.c \
			  utfsize.c

file_H			= ext2.h hfsp_struct.h filegen.h file_doc.h file_jpg.h file_gz.h file_riff.h file_sp3.h file_tar.h file_tiff.h luks_struct.h ntfs_struct.h ole.h pe.h suspend.h utfsize.h xfs_struct.h

photorec_C		= photorec.c phcfg.c addpart.c chgarch.c chgtype.c dir.c exfatp.c ext2grp.c ext2_dir.c ext2p.c fat_dir.c fatp.c file_found.c geometry.c ntfs_dir.c ntfsp.c pdisksel.c poptions.c sessionp.c dfxml.c partgptro.c

photorec_H		= photorec.h phcfg.h addpart.h chgarch.h chgtype.h dfxml.h dir_common.h dir.h exfatp.h ext2grp.h ext2p.h ext2_dir.h ext2_inc.h fat_dir.h fatp.h file_found.h geometry.h memmem.h ntfs_dir.h ntfsp.h ntfs_inc.h pdisksel.h photorec_check_header.h poptions.h psearch.h sessionp.h

photorec_ncurses_C	= phmain.c addpartn.c askloc.c chgarchn.c chgtypen.c fat_cluster.c fat_unformat.c geometryn.c hiddenn.c intrfn.c nodisk.c parti386n.c partgptn.c partmacn.c partsunn.c partxboxn.c pbanner.c pblocksize.c pdiskseln.c pfree_whole.c phbf.c phbs.c phcli.c phnc.c phrecn.c ppartseln.c psearchn.c
photorec_ncurses_H	= addpartn.h askloc.h chgarchn.h chgtypen.h fat_cluster.h fat_unformat.h geometryn.h hiddenn.h intrfn.h nodisk.h parti386n.h partgptn.h partmacn.h partsunn.h partxboxn.h pblocksize.h pdiskseln.h pfree_whole.h pnext.h phbf.h phbs.h phcli.h phnc.h phrecn.h ppartseln.h psearchn.h

QT_TS = \
  lang/qphotorec.ca.ts \
  lang/qphotorec.cs.ts \
  lang/qphotorec.el.ts \
  lang/qphotorec.es.ts \
  lang/qphotorec.fi.ts \
  lang/qphotorec.fr.ts \
  lang/qphotorec.it.ts \
  lang/qphotorec.ja.ts \
  lang/qphotorec.pl.ts \
  lang/qphotorec.pt.ts \
  lang/qphotorec.ru.ts \
  lang/qphotorec.sv_SE.ts \
  lang/qphotorec.tr.ts \
  lang/qphotorec.zh_CN.ts \
  lang/qphotorec.zh_TW.ts

photorec_C_SOURCES	= $(photorec_C) $(file_C) $(base_C) $(fs_C) $(photorec_ncurses_C) suspend_no.c
photorec_H_SOURCES	= $(photorec_H) $(file_H) $(base_H) $(fs_H) $(photorec_ncurses_H) $(ICON_PHOTOREC)
photorec_SOURCES	= $(photorec_C_SOURCES) $(photorec_H_SOURCES)

photorecf_C_SOURCES	= $(photorec_C) $(file_C) $(base_C) $(fs_C) $(photorec_ncurses_C) suspend.c
photorecf_H_SOURCES	= $(photorec_H_SOURCES)
photorecf_SOURCES	= $(photorecf_C_SOURCES) $(photorecf_H_SOURCES)

qphotorec_C_SOURCES	= $(photorec_C) $(file_C) $(base_C) $(fs_C) suspend_no.c qmainrec.cpp qphotorec.cpp qphbs.cpp qpsearch.cpp
qphotorec_H_SOURCES	= $(photorec_H) $(file_H) $(base_H) $(fs_H) $(ICON_QPHOTOREC) qphotorec.h qphotorec.qrc qphotorec_locale.qrc $(QT_TS)
qphotorec_SOURCES	= $(qphotorec_C_SOURCES) $(qphotorec_H_SOURCES)

nodist_qphotorec_SOURCES = moc_qphotorec.cpp rcc_qphotorec.cpp rcc_qphotorec_locale.cpp

fidentify_C_SOURCES	= $(file_C) $(smallbase_C) suspend_no.c fidentify.c
fidentify_H_SOURCES	= $(file_H) $(smallbase_H)
fidentify_SOURCES	= $(fidentify_C_SOURCES) $(fidentify_H_SOURCES)

fuzzerfidentify_C_SOURCES	= $(file_C) $(smallbase_C) suspend_no.c fuzzerfidentify.cpp
fuzzerfidentify_H_SOURCES	= $(fidentify_H_SOURCES)
fuzzerfidentify_SOURCES		= $(fuzzerfidentify_C_SOURCES) $(fuzzerfidentify_H_SOURCES)


QT_QM=$(QT_TS:.ts=.qm)
SECONDARY: $(QT_QM)

CLEANFILES = $(nodist_qphotorec_SOURCES)
DISTCLEANFILES = *~ core

small: $(sbin_PROGRAMS) $(bin_PROGRAMS)
	$(STRIP) -s $(sbin_PROGRAMS) $(bin_PROGRAMS)

extras: $(EXTRA_PROGRAMS)

frama-c-%: session_%.framac
	frama-c-gui -load $^

session_doc.framac: file_doc.c common.c filegen.c log.c setdate.c
	$(CC) $(CFLAGS) -DMAIN_doc -DHAVE_CONFIG_H -DSINGLE_FORMAT -DSINGLE_FORMAT_doc -I.. $^ -o demo_doc
	frama-c $^ -cpp-extra-args="-DMAIN_doc -DHAVE_CONFIG_H -DSINGLE_FORMAT -DSINGLE_FORMAT_doc -D__x86_64__ -I.." $(FRAMA_C_FLAGS) -save $@

session_jpg.framac: file_jpg.c file_tiff.c file_tiff_be.c file_tiff_le.c common.c filegen.c log.c suspend_no.c setdate.c
	$(CC) $(CFLAGS) -DMAIN_jpg -DHAVE_CONFIG_H -DSINGLE_FORMAT -DSINGLE_FORMAT_jpg -I.. $^ -ljpeg -o demo_jpg
	frama-c $^ -cpp-extra-args="-DMAIN_jpg -DHAVE_CONFIG_H -DSINGLE_FORMAT -DSINGLE_FORMAT_jpg -D__x86_64__ -I/usr/include  -I.. -I $(frama-c -print-path)/libc" $(FRAMA_C_FLAGS) -save $@

session_swf.framac: file_swf.c common.c filegen.c log.c
	$(CC) $(CFLAGS) -DMAIN_swf -DHAVE_CONFIG_H -DSINGLE_FORMAT -DSINGLE_FORMAT_swf -I.. $^ -lz -o demo_swf
	frama-c $^ -cpp-extra-args="-DMAIN_swf -DHAVE_CONFIG_H -DSINGLE_FORMAT -DSINGLE_FORMAT_swf -D__x86_64__ -I.." $(FRAMA_C_FLAGS) -save $@

session_tiff_be.framac: file_tiff.c file_tiff_be.c file_tiff_le.c common.c filegen.c log.c
	$(CC) $(CFLAGS) -DMAIN_tiff_le -DHAVE_CONFIG_H -DSINGLE_FORMAT -DSINGLE_FORMAT_tiff -I.. $^ -o demo_tiff_be
	frama-c $^ -cpp-extra-args="-DMAIN_tiff_be -DHAVE_CONFIG_H -DSINGLE_FORMAT -DSINGLE_FORMAT_tiff -D__x86_64__ -I.." $(FRAMA_C_FLAGS) -save $@

session_tiff_le.framac: file_tiff.c file_tiff_be.c file_tiff_le.c common.c filegen.c log.c
	$(CC) $(CFLAGS) -DMAIN_tiff_le -DHAVE_CONFIG_H -DSINGLE_FORMAT -DSINGLE_FORMAT_tiff -I.. $^ -o demo_tiff_le
	frama-c $^ -cpp-extra-args="-DMAIN_tiff_le -DHAVE_CONFIG_H -DSINGLE_FORMAT -DSINGLE_FORMAT_tiff -D__x86_64__ -I.." $(FRAMA_C_FLAGS) -save $@

session_txt.framac: file_txt.c common.c filegen.c log.c utfsize.c
	$(CC) $(CFLAGS) -DMAIN_txt -DHAVE_CONFIG_H -DSINGLE_FORMAT -DSINGLE_FORMAT_txt -I.. $^ -o demo_txt
	frama-c $^ -cpp-extra-args="-DMAIN_txt -DHAVE_CONFIG_H -DSINGLE_FORMAT -DSINGLE_FORMAT_txt -D__x86_64__ -I.." $(FRAMA_C_FLAGS) -save $@

session_%.framac: file_%.c common.c filegen.c log.c
	$(CC) $(CFLAGS) -DMAIN_$* -DHAVE_CONFIG_H -DSINGLE_FORMAT -DSINGLE_FORMAT_$* -I.. $^ -o demo_$*
	frama-c $^ -cpp-extra-args="-DMAIN_$* -DHAVE_CONFIG_H -DSINGLE_FORMAT -DSINGLE_FORMAT_$* -D__x86_64__ -I.." $(FRAMA_C_FLAGS) -save $@

session_fidentify-%.framac: $(fidentify_C_SOURCES)
	$(CC) $(CFLAGS) -DDISABLED_FOR_FRAMAC -DHAVE_CONFIG_H -DSINGLE_FORMAT -DSINGLE_FORMAT_$* -I.. $^ -o fidentify_$*
	frama-c $^ -cpp-extra-args="-DDISABLED_FOR_FRAMAC -DHAVE_CONFIG_H -DSINGLE_FORMAT -DSINGLE_FORMAT_$* -D__x86_64__ -I.." $(FRAMA_C_FLAGS) -save $@

session_fidentify.framac: $(fidentify_C_SOURCES)
	$(CC) $(CFLAGS) -DDISABLED_FOR_FRAMAC -DHAVE_CONFIG_H -I.. $^ -o demo_fidentify
	frama-c $^ -cpp-extra-args="-DDISABLED_FOR_FRAMAC -DHAVE_CONFIG_H -D__x86_64__ -I.." $(FRAMA_C_FLAGS) -save $@

session_photorec-%.framac: $(photorec_C_SOURCES)
	$(CC) $(CFLAGS) -DDISABLED_FOR_FRAMAC -DHAVE_CONFIG_H -DSINGLE_FORMAT -DSINGLE_FORMAT_$* -DSINGLE_PARTITION_TYPE -I.. $^ -o photorec_$*
	frama-c $^ -cpp-extra-args="-DDISABLED_FOR_FRAMAC -DHAVE_CONFIG_H -DSINGLE_FORMAT -DSINGLE_FORMAT_$* -DSINGLE_PARTITION_TYPE -D__x86_64__ -I.." $(FRAMA_C_FLAGS) -save $@

session_photorec.framac: $(photorec_C_SOURCES)
	$(CC) $(CFLAGS) -DDISABLED_FOR_FRAMAC -DHAVE_CONFIG_H -I.. $^ -o demo_photorec
	frama-c $^ -cpp-extra-args="-DDISABLED_FOR_FRAMAC -DHAVE_CONFIG_H -D__x86_64__ -I.." $(FRAMA_C_FLAGS) -save $@

moc_qphotorec.cpp: qphotorec.h
	$(AM_V_GEN) QT_SELECT=$(QT_SELECT) $(MOC) $< -o $@

rcc_qphotorec.cpp: qphotorec.qrc
	$(AM_V_GEN) QT_SELECT=$(QT_SELECT) $(RCC) $< -o $@ -name qphotorec

rcc_qphotorec_locale.cpp: qphotorec_locale.qrc $(QT_QM)
	$(LN_S) $< $(@D) || exit 0
	$(AM_V_GEN) QT_SELECT=$(QT_SELECT) $(RCC) $(@D)/$(<F) -o $@ -name qphotorec_locale

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

%.qm: %.ts
	$(MKDIR_P) $(@D)
	$(AM_V_GEN) QT_SELECT=$(QT_SELECT) $(LRELEASE) -silent $< -qm $@
