# src/CMakeLists.txt — build targets for testdisk, photorec, fidentify
# Source lists mirror src/Makefile.am variable definitions exactly.

# ── smallbase: minimal shared utilities ──────────────────────────────────────
set(smallbase_C
    common.c crc.c ext2_common.c fat_common.c log.c misc.c setdate.c
)

# ── base: full disk/partition layer ──────────────────────────────────────────
set(base_C
    ${smallbase_C}
    apfs_common.c autoset.c ewf.c fnctdsk.c hdaccess.c hdcache.c
    hdwin32.c hidden.c hpa_dco.c intrf.c iso.c list_sort.c log_part.c
    msdos.c parti386.c partgpt.c parthumax.c partmac.c partsun.c
    partnone.c partxbox.c ntfs_io.c ntfs_utl.c partauto.c sudo.c
    unicode.c win32.c
)

# ── fs: filesystem analysers ──────────────────────────────────────────────────
set(fs_C
    analyse.c apfs.c bfs.c bsd.c btrfs.c cramfs.c exfat.c ext2.c
    fat.c fatx.c f2fs.c jfs.c gfs2.c hfs.c hfsp.c hpfs.c luks.c
    lvm.c md.c netware.c ntfs.c refs.c rfs.c savehdr.c sun.c swap.c
    sysv.c ufs.c vmfs.c wbfs.c xfs.c zfs.c
)

# ── testdisk ncurses UI ───────────────────────────────────────────────────────
set(testdisk_ncurses_C
    addpart.c addpartn.c adv.c askloc.c chgarch.c chgarchn.c chgtype.c
    chgtypen.c dimage.c dirn.c dirpart.c diskacc.c diskcapa.c edit.c
    ext2_sb.c ext2_sbn.c fat1x.c fat32.c fat_adv.c fat_cluster.c fatn.c
    geometry.c geometryn.c godmode.c hiddenn.c intrface.c intrfn.c
    io_redir.c nodisk.c ntfs_adv.c ntfs_fix.c ntfs_udl.c parti386n.c
    partgptn.c partmacn.c partsunn.c partxboxn.c tanalyse.c tbanner.c
    tdelete.c tdiskop.c tdisksel.c testdisk.c texfat.c thfs.c tload.c
    tlog.c tmbrcode.c tntfs.c toptions.c tpartwr.c
)

# ── photorec core (ncurses + non-ncurses) ─────────────────────────────────────
set(photorec_C
    photorec.c phcfg.c addpart.c chgarch.c chgtype.c dir.c exfatp.c
    ext2grp.c ext2_dir.c ext2p.c fat_dir.c fatp.c file_found.c
    geometry.c ntfs_dir.c ntfsp.c pdisksel.c poptions.c sessionp.c
    dfxml.c partgptro.c json_log.c
)

set(photorec_ncurses_C
    phmain.c addpartn.c askloc.c chgarchn.c chgtypen.c fat_cluster.c
    fat_unformat.c geometryn.c hiddenn.c intrfn.c nodisk.c parti386n.c
    partgptn.c partmacn.c partsunn.c partxboxn.c pbanner.c pblocksize.c
    pdiskseln.c pfree_whole.c phbf.c phbs.c phcli.c phnc.c phrecn.c
    ppartseln.c psearchn.c
)

# ── file_C: PhotoRec file format recognisers (400+ formats) ──────────────────
set(file_C
    filegen.c file_list.c
    file_1cd.c file_3dm.c file_3ds.c file_7z.c file_DB.c
    file_a.c file_ab.c file_abr.c file_acb.c file_ace.c file_ado.c
    file_afdesign.c file_ahn.c file_aif.c file_all.c file_als.c
    file_amd.c file_amr.c file_apa.c file_ape.c file_apple.c
    file_ari.c file_arj.c file_asf.c file_asl.c file_asm.c
    file_atd.c file_au.c file_axp.c file_axx.c
    file_bac.c file_bdm.c file_berkeley.c file_bfa.c file_bim.c
    file_bin.c file_binvox.c file_bkf.c file_bld.c file_bmp.c
    file_bpg.c file_bvr.c file_bz2.c
    file_c4d.c file_cab.c file_caf.c file_cam.c file_catdrawing.c
    file_cdt.c file_che.c file_chm.c file_class.c file_clip.c
    file_cm.c file_compress.c file_cow.c file_cpi.c file_crw.c
    file_csh.c file_ctg.c file_cwk.c
    file_d2s.c file_dad.c file_dar.c file_dat.c file_dbf.c
    file_dbn.c file_dcm.c file_ddf.c file_dex.c file_dim.c
    file_dir.c file_djv.c file_dmp.c file_doc.c file_dovecot.c
    file_dpx.c file_drw.c file_drw2.c file_ds2.c file_ds_store.c
    file_dsc.c file_dss.c file_dst.c file_dta.c file_dump.c
    file_dv.c file_dvi.c file_dvr.c file_dwg.c file_dxf.c
    file_e01.c file_edb.c file_ecryptfs.c file_elf.c file_emf.c
    file_ess.c file_evt.c file_evtx.c file_exe.c file_exr.c
    file_exs.c file_ext.c file_ext2.c
    file_fat.c file_fbf.c file_fbk.c file_fbx.c file_fcp.c
    file_fcs.c file_fdb.c file_fds.c file_fh10.c file_fh5.c
    file_filevault.c file_fits.c file_fit.c file_flac.c file_flp.c
    file_flv.c file_fm.c file_fob.c file_fos.c file_fp5.c
    file_fp7.c file_freeway.c file_frm.c file_fs.c file_fwd.c file_fxp.c
    file_gam.c file_gct.c file_gho.c file_gi.c file_gif.c
    file_gm6.c file_gp2.c file_gp5.c file_gpg.c file_gpx.c
    file_gsm.c file_gz.c
    file_hdf.c file_hdf5.c file_hdr.c file_hds.c file_hfsp.c
    file_hm.c file_hr9.c file_http.c
    file_ibd.c file_icc.c file_icns.c file_ico.c file_ifo.c
    file_idx.c file_imb.c file_indd.c file_info.c file_iso.c
    file_it.c file_itu.c
    file_jks.c file_journal.c file_jpg.c file_jsonlz4.c
    file_kdb.c file_kdbx.c file_key.c
    file_ldf.c file_lit.c file_lnk.c file_logic.c file_lso.c
    file_luks.c file_lxo.c file_lz.c file_lzh.c file_lzo.c
    file_m2ts.c file_mat.c file_max.c file_maxis.c file_mb.c
    file_mcd.c file_mdb.c file_mdf.c file_mdp.c file_mfa.c
    file_mfg.c file_mft.c file_mid.c file_mig.c file_mk5.c
    file_mkv.c file_mlv.c file_mobi.c file_mov.c file_mp3.c
    file_mpg.c file_mpl.c file_mrw.c file_msa.c file_mus.c
    file_mxf.c file_myo.c file_mysql.c
    file_nd2.c file_nds.c file_nes.c file_njx.c file_nk2.c
    file_nsf.c
    file_oci.c file_ogg.c file_one.c file_orf.c
    file_pa.c file_paf.c file_pap.c file_par2.c file_pcap.c
    file_pcb.c file_pct.c file_pcx.c file_pdb.c file_pdf.c
    file_pds.c file_pf.c file_pfx.c file_pgdump.c file_plist.c
    file_plr.c file_plt.c file_png.c file_pnm.c file_prc.c
    file_prd.c file_prt.c file_ps.c file_psb.c file_psd.c
    file_psf.c file_psp.c file_pst.c file_ptb.c file_ptf.c
    file_pyc.c file_pzf.c file_pzh.c
    file_qbb.c file_qdf.c file_qkt.c file_qxd.c
    file_r3d.c file_ra.c file_raf.c file_rar.c file_raw.c
    file_rdc.c file_reg.c file_res.c file_rfp.c file_riff.c
    file_rm.c file_rns.c file_rpm.c file_rvl.c file_rw2.c file_rx2.c
    file_save.c file_sdsk.c file_sdw.c file_ses.c file_sgcta.c
    file_shn.c file_shp.c file_sib.c file_sig.c file_sit.c
    file_skd.c file_skp.c file_snag.c file_sp3.c file_spe.c
    file_spf.c file_spss.c file_sql.c file_sqm.c file_steuer2014.c
    file_stl.c file_stu.c file_studio.c file_swf.c
    file_tar.c file_tax.c file_tg.c file_tib.c file_tiff.c
    file_tiff_be.c file_tiff_le.c file_tivo.c file_torrent.c
    file_tph.c file_tpl.c file_ttf.c file_txt.c file_tz.c
    file_v2i.c file_vault.c file_vdi.c file_vdj.c file_veg.c
    file_vfb.c file_vib.c file_vmdk.c file_vmg.c
    file_wad.c file_wallet.c file_wdp.c file_wee.c file_wim.c
    file_win.c file_wks.c file_wld.c file_wmf.c file_wnk.c
    file_woff.c file_wpb.c file_wpd.c file_wtv.c file_wv.c
    file_x3f.c file_x3i.c file_x4a.c file_xar.c file_xcf.c
    file_xfi.c file_xfs.c file_xm.c file_xml.c file_xsv.c
    file_xpt.c file_xv.c file_xz.c
    file_z2d.c file_zcode.c file_zip.c file_zpr.c
    utfsize.c
)

# ── Common compile definitions and include paths ──────────────────────────────
# config.h lives in the cmake binary dir (generated); src/ has the sources.
set(TESTDISK_COMMON_DEFS HAVE_CONFIG_H _GNU_SOURCE)
set(TESTDISK_INCLUDE_DIRS
    "${CMAKE_BINARY_DIR}"   # for generated config.h
    "${CMAKE_CURRENT_SOURCE_DIR}"
)

# ── Helper: apply standard flags to a target ─────────────────────────────────
function(testdisk_target_common tgt)
    target_compile_definitions(${tgt} PRIVATE ${TESTDISK_COMMON_DEFS})
    target_include_directories(${tgt} PRIVATE ${TESTDISK_INCLUDE_DIRS})
    target_compile_options(${tgt} PRIVATE ${TESTDISK_C_WARN_FLAGS})
endfunction()

# ── Helper: link optional libraries to a target ───────────────────────────────
function(testdisk_link_optional tgt)
    # ncurses
    if(HAVE_NCURSES AND CURSES_LIBRARIES)
        target_link_libraries(${tgt} PRIVATE ${CURSES_LIBRARIES})
        target_include_directories(${tgt} PRIVATE ${CURSES_INCLUDE_DIRS})
    endif()
    # ext2fs
    if(HAVE_LIBEXT2FS AND EXT2FS_LIB)
        target_link_libraries(${tgt} PRIVATE ${EXT2FS_LIB})
    endif()
    if(HAVE_LIBCOMM_ERR AND COM_ERR_LIB)
        target_link_libraries(${tgt} PRIVATE ${COM_ERR_LIB})
    endif()
    # jpeg
    if(HAVE_LIBJPEG AND JPEG_LIBRARIES)
        target_link_libraries(${tgt} PRIVATE ${JPEG_LIBRARIES})
        target_include_directories(${tgt} PRIVATE ${JPEG_INCLUDE_DIRS})
    endif()
    # ntfs-3g
    if(HAVE_LIBNTFS3G AND NTFS3G_LIB)
        target_link_libraries(${tgt} PRIVATE ${NTFS3G_LIB})
    endif()
    # ewf
    if(HAVE_LIBEWF AND EWF_LIB)
        target_link_libraries(${tgt} PRIVATE ${EWF_LIB})
    endif()
    # zlib
    if(HAVE_LIBZ AND ZLIB_LIBRARIES)
        target_link_libraries(${tgt} PRIVATE ${ZLIB_LIBRARIES})
    endif()
    # uuid
    if(HAVE_LIBUUID AND UUID_LIB)
        target_link_libraries(${tgt} PRIVATE ${UUID_LIB})
    endif()
endfunction()

# ═══════════════════════════════════════════════════════════════════════════════
# Target: testdisk
# ═══════════════════════════════════════════════════════════════════════════════
add_executable(testdisk
    ${base_C}
    ${fs_C}
    ${testdisk_ncurses_C}
    dir.c exfat_dir.c ext2_dir.c fat_dir.c ntfs_dir.c rfs_dir.c
    partgptw.c next.c
)
testdisk_target_common(testdisk)
testdisk_link_optional(testdisk)
install(TARGETS testdisk DESTINATION ${CMAKE_INSTALL_BINDIR})

# ═══════════════════════════════════════════════════════════════════════════════
# Target: photorec
# ═══════════════════════════════════════════════════════════════════════════════
add_executable(photorec
    ${photorec_C}
    ${file_C}
    ${base_C}
    ${fs_C}
    ${photorec_ncurses_C}
    suspend_no.c
)
testdisk_target_common(photorec)
testdisk_link_optional(photorec)
install(TARGETS photorec DESTINATION ${CMAKE_INSTALL_BINDIR})

# ═══════════════════════════════════════════════════════════════════════════════
# Target: fidentify  (file-type identifier; minimal deps — no ncurses needed)
# ═══════════════════════════════════════════════════════════════════════════════
add_executable(fidentify
    ${file_C}
    ${smallbase_C}
    suspend_no.c
    fidentify.c
)
testdisk_target_common(fidentify)
# fidentify only needs jpeg/zlib/ewf, not ncurses/ext2fs/ntfs
if(HAVE_LIBJPEG AND JPEG_LIBRARIES)
    target_link_libraries(fidentify PRIVATE ${JPEG_LIBRARIES})
    target_include_directories(fidentify PRIVATE ${JPEG_INCLUDE_DIRS})
endif()
if(HAVE_LIBZ AND ZLIB_LIBRARIES)
    target_link_libraries(fidentify PRIVATE ${ZLIB_LIBRARIES})
endif()
if(HAVE_LIBEWF AND EWF_LIB)
    target_link_libraries(fidentify PRIVATE ${EWF_LIB})
endif()
install(TARGETS fidentify DESTINATION ${CMAKE_INSTALL_BINDIR})

# ═══════════════════════════════════════════════════════════════════════════════
# Target: qphotorec  (Qt5 GUI — optional)
# ═══════════════════════════════════════════════════════════════════════════════
if(USE_QT)
    add_executable(qphotorec
        ${photorec_C}
        ${file_C}
        ${base_C}
        ${fs_C}
        suspend_no.c
        qmainrec.cpp qphotorec.cpp qphbs.cpp qpsearch.cpp
        qphotorec.qrc
    )
    testdisk_target_common(qphotorec)
    testdisk_link_optional(qphotorec)
    target_link_libraries(qphotorec PRIVATE Qt5::Widgets Qt5::Gui)
    # Qt needs the src dir for moc-generated headers
    target_include_directories(qphotorec PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    install(TARGETS qphotorec DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
