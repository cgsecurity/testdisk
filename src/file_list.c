/*

    File: file_list.c

    Copyright (C) 1998-2011 Christophe GRENIER <grenier@cgsecurity.org>

    This software is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write the Free Software Foundation, Inc., 51
    Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <assert.h>
#include "types.h"
#include "filegen.h"

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_1cd)
extern const file_hint_t file_hint_1cd;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_3dm)
extern const file_hint_t file_hint_3dm;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_3ds)
extern const file_hint_t file_hint_3ds;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_7z)
extern const file_hint_t file_hint_7z;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_DB)
extern const file_hint_t file_hint_DB;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_a)
extern const file_hint_t file_hint_a;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_abr)
extern const file_hint_t file_hint_abr;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_acb)
extern const file_hint_t file_hint_acb;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mdb)
extern const file_hint_t file_hint_accdb;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ace)
extern const file_hint_t file_hint_ace;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_addressbook)
extern const file_hint_t file_hint_addressbook;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ado)
extern const file_hint_t file_hint_ado;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_afdesign)
extern const file_hint_t file_hint_afdesign;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ahn)
extern const file_hint_t file_hint_ahn;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_aif)
extern const file_hint_t file_hint_aif;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_all)
extern const file_hint_t file_hint_all;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_als)
extern const file_hint_t file_hint_als;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_amd)
extern const file_hint_t file_hint_amd;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_amr)
extern const file_hint_t file_hint_amr;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_apa)
extern const file_hint_t file_hint_apa;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ape)
extern const file_hint_t file_hint_ape;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_apple)
extern const file_hint_t file_hint_apple;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ari)
extern const file_hint_t file_hint_ari;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_arj)
extern const file_hint_t file_hint_arj;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_asf)
extern const file_hint_t file_hint_asf;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_asl)
extern const file_hint_t file_hint_asl;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_asm)
extern const file_hint_t file_hint_asm;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_atd)
extern const file_hint_t file_hint_atd;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_au)
extern const file_hint_t file_hint_au;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_axp)
extern const file_hint_t file_hint_axp;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_axx)
extern const file_hint_t file_hint_axx;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_bac)
extern const file_hint_t file_hint_bac;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_bdm)
extern const file_hint_t file_hint_bdm;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_berkeley)
extern const file_hint_t file_hint_berkeley;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_bfa)
extern const file_hint_t file_hint_bfa;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_bim)
extern const file_hint_t file_hint_bim;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_bin)
extern const file_hint_t file_hint_bin;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_binvox)
extern const file_hint_t file_hint_binvox;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_bkf)
extern const file_hint_t file_hint_bkf;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_blend)
extern const file_hint_t file_hint_blend;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_bmp)
extern const file_hint_t file_hint_bmp;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_bpg)
extern const file_hint_t file_hint_bpg;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_bvr)
extern const file_hint_t file_hint_bvr;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_bz2)
extern const file_hint_t file_hint_bz2;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_c4d)
extern const file_hint_t file_hint_c4d;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_cab)
extern const file_hint_t file_hint_cab;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_caf)
extern const file_hint_t file_hint_caf;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_cam)
extern const file_hint_t file_hint_cam;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_catdrawing)
extern const file_hint_t file_hint_catdrawing;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_cdt)
extern const file_hint_t file_hint_cdt;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_che)
extern const file_hint_t file_hint_che;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_chm)
extern const file_hint_t file_hint_chm;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_class)
extern const file_hint_t file_hint_class;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_clip)
extern const file_hint_t file_hint_clip;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_cm)
extern const file_hint_t file_hint_cm;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_compress)
extern const file_hint_t file_hint_compress;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_cow)
extern const file_hint_t file_hint_cow;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_cpi)
extern const file_hint_t file_hint_cpi;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_crw)
extern const file_hint_t file_hint_crw;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_csh)
extern const file_hint_t file_hint_csh;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ctg)
extern const file_hint_t file_hint_ctg;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_cwk)
extern const file_hint_t file_hint_cwk;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_d2s)
extern const file_hint_t file_hint_d2s;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dad)
extern const file_hint_t file_hint_dad;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dar)
extern const file_hint_t file_hint_dar;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dat)
extern const file_hint_t file_hint_dat;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dbf)
extern const file_hint_t file_hint_dbf;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dbn)
extern const file_hint_t file_hint_dbn;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dcm)
extern const file_hint_t file_hint_dcm;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ddf)
extern const file_hint_t file_hint_ddf;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dex)
extern const file_hint_t file_hint_dex;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dim)
extern const file_hint_t file_hint_dim;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dir)
extern const file_hint_t file_hint_dir;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_djv)
extern const file_hint_t file_hint_djv;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dmp)
extern const file_hint_t file_hint_dmp;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_doc)
extern const file_hint_t file_hint_doc;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dovecot)
extern const file_hint_t file_hint_dovecot;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dpx)
extern const file_hint_t file_hint_dpx;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_drw)
extern const file_hint_t file_hint_drw;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_drw2)
extern const file_hint_t file_hint_drw2;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ds2)
extern const file_hint_t file_hint_ds2;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ds_store)
extern const file_hint_t file_hint_ds_store;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dsc)
extern const file_hint_t file_hint_dsc;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dss)
extern const file_hint_t file_hint_dss;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dst)
extern const file_hint_t file_hint_dst;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dta)
extern const file_hint_t file_hint_dta;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dump)
extern const file_hint_t file_hint_dump;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dv)
extern const file_hint_t file_hint_dv;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dvi)
extern const file_hint_t file_hint_dvi;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dvr)
extern const file_hint_t file_hint_dvr;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dwg)
extern const file_hint_t file_hint_dwg;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dxf)
extern const file_hint_t file_hint_dxf;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_e01)
extern const file_hint_t file_hint_e01;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ecryptfs)
extern const file_hint_t file_hint_ecryptfs;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_edb)
extern const file_hint_t file_hint_edb;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_elf)
extern const file_hint_t file_hint_elf;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_emf)
extern const file_hint_t file_hint_emf;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ess)
extern const file_hint_t file_hint_ess;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_evt)
extern const file_hint_t file_hint_evt;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_evtx)
extern const file_hint_t file_hint_evtx;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_exe)
extern const file_hint_t file_hint_exe;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_exr)
extern const file_hint_t file_hint_exr;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_exs)
extern const file_hint_t file_hint_exs;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ext2_sb)
extern const file_hint_t file_hint_ext2_sb;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ext2_fs)
extern const file_hint_t file_hint_ext2_fs;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fat)
extern const file_hint_t file_hint_fat;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fbf)
extern const file_hint_t file_hint_fbf;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fbk)
extern const file_hint_t file_hint_fbk;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fbx)
extern const file_hint_t file_hint_fbx;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fcp)
extern const file_hint_t file_hint_fcp;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fcs)
extern const file_hint_t file_hint_fcs;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fdb)
extern const file_hint_t file_hint_fdb;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fds)
extern const file_hint_t file_hint_fds;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fh10)
extern const file_hint_t file_hint_fh10;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fh5)
extern const file_hint_t file_hint_fh5;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_filevault)
extern const file_hint_t file_hint_filevault;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fits)
extern const file_hint_t file_hint_fits;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fit)
extern const file_hint_t file_hint_fit;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_flac)
extern const file_hint_t file_hint_flac;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_txt)
extern const file_hint_t file_hint_fasttxt;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_flp)
extern const file_hint_t file_hint_flp;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_flv)
extern const file_hint_t file_hint_flv;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fm)
extern const file_hint_t file_hint_fm;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fob)
extern const file_hint_t file_hint_fob;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fos)
extern const file_hint_t file_hint_fos;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fp5)
extern const file_hint_t file_hint_fp5;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fp7)
extern const file_hint_t file_hint_fp7;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_freeway)
extern const file_hint_t file_hint_freeway;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_frm)
extern const file_hint_t file_hint_frm;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fs)
extern const file_hint_t file_hint_fs;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fwd)
extern const file_hint_t file_hint_fwd;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fxp)
extern const file_hint_t file_hint_fxp;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_gam)
extern const file_hint_t file_hint_gam;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_gct)
extern const file_hint_t file_hint_gct;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_gho)
extern const file_hint_t file_hint_gho;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_gi)
extern const file_hint_t file_hint_gi;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_gif)
extern const file_hint_t file_hint_gif;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_gm6)
extern const file_hint_t file_hint_gm6;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_gp2)
extern const file_hint_t file_hint_gp2;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_gp5)
extern const file_hint_t file_hint_gp5;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_gpg)
extern const file_hint_t file_hint_gpg;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_gpx)
extern const file_hint_t file_hint_gpx;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_gsm)
extern const file_hint_t file_hint_gsm;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_gz)
extern const file_hint_t file_hint_gz;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_hdf)
extern const file_hint_t file_hint_hdf;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_hdf5)
extern const file_hint_t file_hint_hdf5;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_hdr)
extern const file_hint_t file_hint_hdr;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_hds)
extern const file_hint_t file_hint_hds;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_hfsp)
extern const file_hint_t file_hint_hfsp;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_hm)
extern const file_hint_t file_hint_hm;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_hr9)
extern const file_hint_t file_hint_hr9;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_http)
extern const file_hint_t file_hint_http;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ibd)
extern const file_hint_t file_hint_ibd;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_icc)
extern const file_hint_t file_hint_icc;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_icns)
extern const file_hint_t file_hint_icns;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ico)
extern const file_hint_t file_hint_ico;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_idx)
extern const file_hint_t file_hint_idx;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ifo)
extern const file_hint_t file_hint_ifo;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_imb)
extern const file_hint_t file_hint_imb;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_indd)
extern const file_hint_t file_hint_indd;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_info)
extern const file_hint_t file_hint_info;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_iso)
extern const file_hint_t file_hint_iso;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_it)
extern const file_hint_t file_hint_it;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_itunes)
extern const file_hint_t file_hint_itunes;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_jks)
extern const file_hint_t file_hint_jks;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_jpg)
extern const file_hint_t file_hint_jpg;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_jsonlz4)
extern const file_hint_t file_hint_jsonlz4;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_kdb)
extern const file_hint_t file_hint_kdb;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_kdbx)
extern const file_hint_t file_hint_kdbx;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_key)
extern const file_hint_t file_hint_key;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ldf)
extern const file_hint_t file_hint_ldf;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_lit)
extern const file_hint_t file_hint_lit;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_logic)
extern const file_hint_t file_hint_logic;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_lnk)
extern const file_hint_t file_hint_lnk;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_lso)
extern const file_hint_t file_hint_lso;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_luks)
extern const file_hint_t file_hint_luks;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_lxo)
extern const file_hint_t file_hint_lxo;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_lz)
extern const file_hint_t file_hint_lz;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_lzh)
extern const file_hint_t file_hint_lzh;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_lzo)
extern const file_hint_t file_hint_lzo;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_m2ts)
extern const file_hint_t file_hint_m2ts;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mat)
extern const file_hint_t file_hint_mat;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_max)
extern const file_hint_t file_hint_max;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mb)
extern const file_hint_t file_hint_mb;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mcd)
extern const file_hint_t file_hint_mcd;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mdb)
extern const file_hint_t file_hint_mdb;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mdf)
extern const file_hint_t file_hint_mdf;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mdp)
extern const file_hint_t file_hint_mdp;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mfa)
extern const file_hint_t file_hint_mfa;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mfg)
extern const file_hint_t file_hint_mfg;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mft)
extern const file_hint_t file_hint_mft;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mid)
extern const file_hint_t file_hint_mid;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mig)
extern const file_hint_t file_hint_mig;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mk5)
extern const file_hint_t file_hint_mk5;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mkv)
extern const file_hint_t file_hint_mkv;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mlv)
extern const file_hint_t file_hint_mlv;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mobi)
extern const file_hint_t file_hint_mobi;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mov_mdat)
extern const file_hint_t file_hint_mov_mdat;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mov)
extern const file_hint_t file_hint_mov;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mp3)
extern const file_hint_t file_hint_mp3;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mpg)
extern const file_hint_t file_hint_mpg;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mpl)
extern const file_hint_t file_hint_mpl;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mrw)
extern const file_hint_t file_hint_mrw;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_msa)
extern const file_hint_t file_hint_msa;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mus)
extern const file_hint_t file_hint_mus;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mxf)
extern const file_hint_t file_hint_mxf;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_myo)
extern const file_hint_t file_hint_myo;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mysql)
extern const file_hint_t file_hint_mysql;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_nd2)
extern const file_hint_t file_hint_nd2;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_nds)
extern const file_hint_t file_hint_nds;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_nes)
extern const file_hint_t file_hint_nes;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_njx)
extern const file_hint_t file_hint_njx;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_nk2)
extern const file_hint_t file_hint_nk2;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_nsf)
extern const file_hint_t file_hint_nsf;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_oci)
extern const file_hint_t file_hint_oci;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ogg)
extern const file_hint_t file_hint_ogg;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_one)
extern const file_hint_t file_hint_one;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_orf)
extern const file_hint_t file_hint_orf;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pa)
extern const file_hint_t file_hint_pa;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_paf)
extern const file_hint_t file_hint_paf;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pap)
extern const file_hint_t file_hint_pap;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_par2)
extern const file_hint_t file_hint_par2;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pcap)
extern const file_hint_t file_hint_pcap;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pcb)
extern const file_hint_t file_hint_pcb;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pct)
extern const file_hint_t file_hint_pct;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pcx)
extern const file_hint_t file_hint_pcx;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pdb)
extern const file_hint_t file_hint_pdb;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pdf)
extern const file_hint_t file_hint_pdf;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pds)
extern const file_hint_t file_hint_pds;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pf)
extern const file_hint_t file_hint_pf;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pfx)
extern const file_hint_t file_hint_pfx;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pgdump)
extern const file_hint_t file_hint_pgdump;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_plist)
extern const file_hint_t file_hint_plist;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_plr)
extern const file_hint_t file_hint_plr;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_plt)
extern const file_hint_t file_hint_plt;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_png)
extern const file_hint_t file_hint_png;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pnm)
extern const file_hint_t file_hint_pnm;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_prc)
extern const file_hint_t file_hint_prc;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_prd)
extern const file_hint_t file_hint_prd;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_prt)
extern const file_hint_t file_hint_prt;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ps)
extern const file_hint_t file_hint_ps;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_psb)
extern const file_hint_t file_hint_psb;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_psd)
extern const file_hint_t file_hint_psd;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_psf)
extern const file_hint_t file_hint_psf;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_psp)
extern const file_hint_t file_hint_psp;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pst)
extern const file_hint_t file_hint_pst;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ptb)
extern const file_hint_t file_hint_ptb;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ptf)
extern const file_hint_t file_hint_ptf;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pyc)
extern const file_hint_t file_hint_pyc;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pzf)
extern const file_hint_t file_hint_pzf;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pzh)
extern const file_hint_t file_hint_pzh;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_qbb)
extern const file_hint_t file_hint_qbb;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_qdf)
extern const file_hint_t file_hint_qdf;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_qkt)
extern const file_hint_t file_hint_qkt;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_qxd)
extern const file_hint_t file_hint_qxd;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_r3d)
extern const file_hint_t file_hint_r3d;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ra)
extern const file_hint_t file_hint_ra;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_raf)
extern const file_hint_t file_hint_raf;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_rar)
extern const file_hint_t file_hint_rar;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_raw)
extern const file_hint_t file_hint_raw;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_rdc)
extern const file_hint_t file_hint_rdc;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_reg)
extern const file_hint_t file_hint_reg;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_res)
extern const file_hint_t file_hint_res;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_rfp)
extern const file_hint_t file_hint_rfp;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_riff)
extern const file_hint_t file_hint_riff;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_rlv)
extern const file_hint_t file_hint_rlv;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_rm)
extern const file_hint_t file_hint_rm;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_rns)
extern const file_hint_t file_hint_rns;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_rpm)
extern const file_hint_t file_hint_rpm;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_rw2)
extern const file_hint_t file_hint_rw2;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_rx2)
extern const file_hint_t file_hint_rx2;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_save)
extern const file_hint_t file_hint_save;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_sdsk)
extern const file_hint_t file_hint_sdsk;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_sdw)
extern const file_hint_t file_hint_sdw;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ses)
extern const file_hint_t file_hint_ses;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_sgcta)
extern const file_hint_t file_hint_sgcta;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_shn)
extern const file_hint_t file_hint_shn;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_shp)
extern const file_hint_t file_hint_shp;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_sib)
extern const file_hint_t file_hint_sib;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_sig)
extern const file_hint_t file_hint_sig;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_sit)
extern const file_hint_t file_hint_sit;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_skd)
extern const file_hint_t file_hint_skd;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_skp)
extern const file_hint_t file_hint_skp;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_snag)
extern const file_hint_t file_hint_snag;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_txt)
extern const file_hint_t file_hint_snz;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_sp3)
extern const file_hint_t file_hint_sp3;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_spe)
extern const file_hint_t file_hint_spe;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_spf)
extern const file_hint_t file_hint_spf;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_spss)
extern const file_hint_t file_hint_spss;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_sqlite)
extern const file_hint_t file_hint_sqlite;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_sqm)
extern const file_hint_t file_hint_sqm;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_steuer2014)
extern const file_hint_t file_hint_steuer2014;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_stl)
extern const file_hint_t file_hint_stl;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_studio)
extern const file_hint_t file_hint_studio;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_stuffit)
extern const file_hint_t file_hint_stuffit;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_swf)
extern const file_hint_t file_hint_swf;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_tar)
extern const file_hint_t file_hint_tar;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_tax)
extern const file_hint_t file_hint_tax;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_tg)
extern const file_hint_t file_hint_tg;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_tib)
extern const file_hint_t file_hint_tib;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_tiff)
extern const file_hint_t file_hint_tiff;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_tivo)
extern const file_hint_t file_hint_tivo;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_torrent)
extern const file_hint_t file_hint_torrent;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_tph)
extern const file_hint_t file_hint_tph;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_tpl)
extern const file_hint_t file_hint_tpl;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_m2ts)
extern const file_hint_t file_hint_ts;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ttf)
extern const file_hint_t file_hint_ttf;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_txt)
extern const file_hint_t file_hint_txt;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_tz)
extern const file_hint_t file_hint_tz;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_v2i)
extern const file_hint_t file_hint_v2i;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_vault)
extern const file_hint_t file_hint_vault;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_vdi)
extern const file_hint_t file_hint_vdi;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_vdj)
extern const file_hint_t file_hint_vdj;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_veg)
extern const file_hint_t file_hint_veg;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_vfb)
extern const file_hint_t file_hint_vfb;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_vib)
extern const file_hint_t file_hint_vib;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_vmdk)
extern const file_hint_t file_hint_vmdk;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_vmg)
extern const file_hint_t file_hint_vmg;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_wad)
extern const file_hint_t file_hint_wad;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_wallet)
extern const file_hint_t file_hint_wallet;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_wdp)
extern const file_hint_t file_hint_wdp;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_wee)
extern const file_hint_t file_hint_wee;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_wim)
extern const file_hint_t file_hint_wim;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_win)
extern const file_hint_t file_hint_win;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_wks)
extern const file_hint_t file_hint_wks;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_wld)
extern const file_hint_t file_hint_wld;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_wmf)
extern const file_hint_t file_hint_wmf;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_wnk)
extern const file_hint_t file_hint_wnk;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_woff)
extern const file_hint_t file_hint_woff;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_wpb)
extern const file_hint_t file_hint_wpb;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_wpd)
extern const file_hint_t file_hint_wpd;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_wtv)
extern const file_hint_t file_hint_wtv;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_wv)
extern const file_hint_t file_hint_wv;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_x3f)
extern const file_hint_t file_hint_x3f;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_x3i)
extern const file_hint_t file_hint_x3i;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_x4a)
extern const file_hint_t file_hint_x4a;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_xar)
extern const file_hint_t file_hint_xar;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_xcf)
extern const file_hint_t file_hint_xcf;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_xfi)
extern const file_hint_t file_hint_xfi;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_xfs)
extern const file_hint_t file_hint_xfs;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_xm)
extern const file_hint_t file_hint_xm;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_xml)
extern const file_hint_t file_hint_xml;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_xsv)
extern const file_hint_t file_hint_xsv;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_xpt)
extern const file_hint_t file_hint_xpt;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_xv)
extern const file_hint_t file_hint_xv;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_xz)
extern const file_hint_t file_hint_xz;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_z2d)
extern const file_hint_t file_hint_z2d;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_zcode)
extern const file_hint_t file_hint_zcode;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_zip)
extern const file_hint_t file_hint_zip;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_zpr)
extern const file_hint_t file_hint_zpr;
#endif

file_enable_t array_file_enable[]=
{
#if !defined(SINGLE_FORMAT)  || defined(SINGLE_FORMAT_sig)
  { .enable=0, .file_hint=&file_hint_sig  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_1cd)
  { .enable=0, .file_hint=&file_hint_1cd  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_3dm)
  { .enable=0, .file_hint=&file_hint_3dm  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_3ds)
  { .enable=0, .file_hint=&file_hint_3ds  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_7z)
  { .enable=0, .file_hint=&file_hint_7z   },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_DB)
  { .enable=0, .file_hint=&file_hint_DB    },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_a)
  { .enable=0, .file_hint=&file_hint_a    },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_abr)
  { .enable=0, .file_hint=&file_hint_abr  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_acb)
  { .enable=0, .file_hint=&file_hint_acb  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mdb)
  { .enable=0, .file_hint=&file_hint_accdb},
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ace)
  { .enable=0, .file_hint=&file_hint_ace  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_addressbook)
  { .enable=0, .file_hint=&file_hint_addressbook},
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ado)
  { .enable=0, .file_hint=&file_hint_ado  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_afdesign)
  { .enable=0, .file_hint=&file_hint_afdesign  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ahn)
  { .enable=0, .file_hint=&file_hint_ahn  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_aif)
  { .enable=0, .file_hint=&file_hint_aif  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_all)
  { .enable=0, .file_hint=&file_hint_all  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_als)
  { .enable=0, .file_hint=&file_hint_als  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_amd)
  { .enable=0, .file_hint=&file_hint_amd  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_amr)
  { .enable=0, .file_hint=&file_hint_amr  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_apa)
  { .enable=0, .file_hint=&file_hint_apa  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ape)
  { .enable=0, .file_hint=&file_hint_ape  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_apple)
  { .enable=0, .file_hint=&file_hint_apple },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ari)
  { .enable=0, .file_hint=&file_hint_ari  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_arj)
  { .enable=0, .file_hint=&file_hint_arj  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_asf)
  { .enable=0, .file_hint=&file_hint_asf  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_asl)
  { .enable=0, .file_hint=&file_hint_asl  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_asm)
  { .enable=0, .file_hint=&file_hint_asm  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_atd)
  { .enable=0, .file_hint=&file_hint_atd  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_au)
  { .enable=0, .file_hint=&file_hint_au   },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_axp)
  { .enable=0, .file_hint=&file_hint_axp  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_axx)
  { .enable=0, .file_hint=&file_hint_axx  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_bac)
  { .enable=0, .file_hint=&file_hint_bac  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_bdm)
  { .enable=0, .file_hint=&file_hint_bdm  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_berkeley)
  { .enable=0, .file_hint=&file_hint_berkeley },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_bfa)
  { .enable=0, .file_hint=&file_hint_bfa  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_bim)
  { .enable=0, .file_hint=&file_hint_bim  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_bin)
  { .enable=0, .file_hint=&file_hint_bin  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_binvox)
  { .enable=0, .file_hint=&file_hint_binvox  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_bkf)
  { .enable=0, .file_hint=&file_hint_bkf  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_blend)
  { .enable=0, .file_hint=&file_hint_blend },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_bmp)
  { .enable=0, .file_hint=&file_hint_bmp  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_bpg)
  { .enable=0, .file_hint=&file_hint_bpg  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_bvr)
  { .enable=0, .file_hint=&file_hint_bvr  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_bz2)
  { .enable=0, .file_hint=&file_hint_bz2  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_c4d)
  { .enable=0, .file_hint=&file_hint_c4d  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_cab)
  { .enable=0, .file_hint=&file_hint_cab  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_caf)
  { .enable=0, .file_hint=&file_hint_caf  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_cam)
  { .enable=0, .file_hint=&file_hint_cam  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_catdrawing)
  { .enable=0, .file_hint=&file_hint_catdrawing  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_cdt)
  { .enable=0, .file_hint=&file_hint_cdt  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_che)
  { .enable=0, .file_hint=&file_hint_che  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_chm)
  { .enable=0, .file_hint=&file_hint_chm  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_class)
  { .enable=0, .file_hint=&file_hint_class },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_clip)
  { .enable=0, .file_hint=&file_hint_clip  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_cm)
  { .enable=0, .file_hint=&file_hint_cm  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_compress)
  { .enable=0, .file_hint=&file_hint_compress },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_cow)
  { .enable=0, .file_hint=&file_hint_cow  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_cpi)
  { .enable=0, .file_hint=&file_hint_cpi  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_crw)
  { .enable=0, .file_hint=&file_hint_crw  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_csh)
  { .enable=0, .file_hint=&file_hint_csh  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ctg)
  { .enable=0, .file_hint=&file_hint_ctg  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_cwk)
  { .enable=0, .file_hint=&file_hint_cwk  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_d2s)
  { .enable=0, .file_hint=&file_hint_d2s  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dad)
  { .enable=0, .file_hint=&file_hint_dad  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dar)
  { .enable=0, .file_hint=&file_hint_dar  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dat)
  { .enable=0, .file_hint=&file_hint_dat  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dbf)
  { .enable=0, .file_hint=&file_hint_dbf  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dbn)
  { .enable=0, .file_hint=&file_hint_dbn  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dcm)
  { .enable=0, .file_hint=&file_hint_dcm  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ddf)
  { .enable=0, .file_hint=&file_hint_ddf  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dex)
  { .enable=0, .file_hint=&file_hint_dex  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dim)
  { .enable=0, .file_hint=&file_hint_dim  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dir)
  { .enable=0, .file_hint=&file_hint_dir  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_djv)
  { .enable=0, .file_hint=&file_hint_djv  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dmp)
  { .enable=0, .file_hint=&file_hint_dmp  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_drw)
  { .enable=0, .file_hint=&file_hint_drw  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_drw2)
  { .enable=0, .file_hint=&file_hint_drw2  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_doc)
  { .enable=0, .file_hint=&file_hint_doc  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dovecot)
  { .enable=0, .file_hint=&file_hint_dovecot },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dpx)
  { .enable=0, .file_hint=&file_hint_dpx  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ds2)
  { .enable=0, .file_hint=&file_hint_ds2  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ds_store)
  { .enable=0, .file_hint=&file_hint_ds_store  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dsc)
  { .enable=0, .file_hint=&file_hint_dsc  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dss)
  { .enable=0, .file_hint=&file_hint_dss  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dst)
  { .enable=0, .file_hint=&file_hint_dst  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dta)
  { .enable=0, .file_hint=&file_hint_dta  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dump)
  { .enable=0, .file_hint=&file_hint_dump },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dv)
  { .enable=0, .file_hint=&file_hint_dv   },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dvi)
  { .enable=0, .file_hint=&file_hint_dvi  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dvr)
  { .enable=0, .file_hint=&file_hint_dvr  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dwg)
  { .enable=0, .file_hint=&file_hint_dwg  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dxf)
  { .enable=0, .file_hint=&file_hint_dxf  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_e01)
  { .enable=0, .file_hint=&file_hint_e01  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ecryptfs)
  { .enable=0, .file_hint=&file_hint_ecryptfs },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_edb)
  { .enable=0, .file_hint=&file_hint_edb  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_elf)
  { .enable=0, .file_hint=&file_hint_elf  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_emf)
  { .enable=0, .file_hint=&file_hint_emf  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ess)
  { .enable=0, .file_hint=&file_hint_ess  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_evt)
  { .enable=0, .file_hint=&file_hint_evt  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_evtx)
  { .enable=0, .file_hint=&file_hint_evtx  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_exe)
  { .enable=0, .file_hint=&file_hint_exe  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_exr)
  { .enable=0, .file_hint=&file_hint_exr  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_exs)
  { .enable=0, .file_hint=&file_hint_exs  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ext2_sb)
  { .enable=0, .file_hint=&file_hint_ext2_sb },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ext2_fs)
  { .enable=0, .file_hint=&file_hint_ext2_fs },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fat)
  { .enable=0, .file_hint=&file_hint_fat  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fbf)
  { .enable=0, .file_hint=&file_hint_fbf  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fbk)
  { .enable=0, .file_hint=&file_hint_fbk  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fbx)
  { .enable=0, .file_hint=&file_hint_fbx  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fcp)
  { .enable=0, .file_hint=&file_hint_fcp  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fcs)
  { .enable=0, .file_hint=&file_hint_fcs  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fdb)
  { .enable=0, .file_hint=&file_hint_fdb  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fds)
  { .enable=0, .file_hint=&file_hint_fds  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fh10)
  { .enable=0, .file_hint=&file_hint_fh10  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fh5)
  { .enable=0, .file_hint=&file_hint_fh5  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_filevault)
  { .enable=0, .file_hint=&file_hint_filevault },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fits)
  { .enable=0, .file_hint=&file_hint_fits },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fit)
  { .enable=0, .file_hint=&file_hint_fit },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_flac)
  { .enable=0, .file_hint=&file_hint_flac },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_flp)
  { .enable=0, .file_hint=&file_hint_flp  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_flv)
  { .enable=0, .file_hint=&file_hint_flv  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fm)
  { .enable=0, .file_hint=&file_hint_fm  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fob)
  { .enable=0, .file_hint=&file_hint_fob  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fos)
  { .enable=0, .file_hint=&file_hint_fos  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fp5)
  { .enable=0, .file_hint=&file_hint_fp5  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fp7)
  { .enable=0, .file_hint=&file_hint_fp7  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_freeway)
  { .enable=0, .file_hint=&file_hint_freeway  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_frm)
  { .enable=0, .file_hint=&file_hint_frm  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fs)
  { .enable=0, .file_hint=&file_hint_fs   },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fwd)
  { .enable=0, .file_hint=&file_hint_fwd  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fxp)
  { .enable=0, .file_hint=&file_hint_fxp  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_gam)
  { .enable=0, .file_hint=&file_hint_gam  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_gct)
  { .enable=0, .file_hint=&file_hint_gct  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_gho)
  { .enable=0, .file_hint=&file_hint_gho  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_gi)
  { .enable=0, .file_hint=&file_hint_gi  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_gif)
  { .enable=0, .file_hint=&file_hint_gif  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_gm6)
  { .enable=0, .file_hint=&file_hint_gm6  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_gp2)
  { .enable=0, .file_hint=&file_hint_gp2  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_gp5)
  { .enable=0, .file_hint=&file_hint_gp5  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_gpg)
  { .enable=0, .file_hint=&file_hint_gpg  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_gpx)
  { .enable=0, .file_hint=&file_hint_gpx  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_gsm)
  { .enable=0, .file_hint=&file_hint_gsm  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_gz)
  { .enable=0, .file_hint=&file_hint_gz   },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_hdf)
  { .enable=0, .file_hint=&file_hint_hdf  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_hdf5)
  { .enable=0, .file_hint=&file_hint_hdf5  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_hdr)
  { .enable=0, .file_hint=&file_hint_hdr  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_hds)
  { .enable=0, .file_hint=&file_hint_hds  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_hfsp)
  { .enable=0, .file_hint=&file_hint_hfsp },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_hm)
  { .enable=0, .file_hint=&file_hint_hm  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_hr9)
  { .enable=0, .file_hint=&file_hint_hr9  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_http)
  { .enable=0, .file_hint=&file_hint_http },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ibd)
  { .enable=0, .file_hint=&file_hint_ibd  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_icc)
  { .enable=0, .file_hint=&file_hint_icc  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_icns)
  { .enable=0, .file_hint=&file_hint_icns  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ico)
  { .enable=0, .file_hint=&file_hint_ico  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_idx)
  { .enable=0, .file_hint=&file_hint_idx  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ifo)
  { .enable=0, .file_hint=&file_hint_ifo  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_imb)
  { .enable=0, .file_hint=&file_hint_imb  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_indd)
  { .enable=0, .file_hint=&file_hint_indd  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_info)
  { .enable=0, .file_hint=&file_hint_info  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_iso)
  { .enable=0, .file_hint=&file_hint_iso  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_it)
  { .enable=0, .file_hint=&file_hint_it  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_itunes)
  { .enable=0, .file_hint=&file_hint_itunes  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_jks)
  { .enable=0, .file_hint=&file_hint_jks  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_jpg)
  { .enable=0, .file_hint=&file_hint_jpg  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_jsonlz4)
  { .enable=0, .file_hint=&file_hint_jsonlz4  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_kdb)
  { .enable=0, .file_hint=&file_hint_kdb  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_kdbx)
  { .enable=0, .file_hint=&file_hint_kdbx },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_key)
  { .enable=0, .file_hint=&file_hint_key  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ldf)
  { .enable=0, .file_hint=&file_hint_ldf  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_lit)
  { .enable=0, .file_hint=&file_hint_lit  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_logic)
  { .enable=0, .file_hint=&file_hint_logic},
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_lnk)
  { .enable=0, .file_hint=&file_hint_lnk  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_lso)
  { .enable=0, .file_hint=&file_hint_lso  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_luks)
  { .enable=0, .file_hint=&file_hint_luks },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_lxo)
  { .enable=0, .file_hint=&file_hint_lxo  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_lz)
  { .enable=0, .file_hint=&file_hint_lz  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_lzh)
  { .enable=0, .file_hint=&file_hint_lzh  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_lzo)
  { .enable=0, .file_hint=&file_hint_lzo  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_m2ts)
  { .enable=0, .file_hint=&file_hint_m2ts },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mat)
  { .enable=0, .file_hint=&file_hint_mat  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_max)
  { .enable=0, .file_hint=&file_hint_max  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mb)
  { .enable=0, .file_hint=&file_hint_mb   },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mcd)
  { .enable=0, .file_hint=&file_hint_mcd  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mdb)
  { .enable=0, .file_hint=&file_hint_mdb  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mdf)
  { .enable=0, .file_hint=&file_hint_mdf  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mdp)
  { .enable=0, .file_hint=&file_hint_mdp  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mfa)
  { .enable=0, .file_hint=&file_hint_mfa  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mfg)
  { .enable=0, .file_hint=&file_hint_mfg  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mft)
  { .enable=0, .file_hint=&file_hint_mft  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mid)
  { .enable=0, .file_hint=&file_hint_mid  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mig)
  { .enable=0, .file_hint=&file_hint_mig  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mk5)
  { .enable=0, .file_hint=&file_hint_mk5  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mkv)
  { .enable=0, .file_hint=&file_hint_mkv  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mlv)
  { .enable=0, .file_hint=&file_hint_mlv  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mobi)
  { .enable=0, .file_hint=&file_hint_mobi },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mov_mdat)
  { .enable=0, .file_hint=&file_hint_mov_mdat },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mov)
  { .enable=0, .file_hint=&file_hint_mov  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mp3)
  { .enable=0, .file_hint=&file_hint_mp3  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mpg)
  { .enable=0, .file_hint=&file_hint_mpg  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mpl)
  { .enable=0, .file_hint=&file_hint_mpl  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mrw)
  { .enable=0, .file_hint=&file_hint_mrw  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_msa)
  { .enable=0, .file_hint=&file_hint_msa  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mus)
  { .enable=0, .file_hint=&file_hint_mus  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mxf)
  { .enable=0, .file_hint=&file_hint_mxf  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_myo)
  { .enable=0, .file_hint=&file_hint_myo  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mysql)
  { .enable=0, .file_hint=&file_hint_mysql },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_nd2)
  { .enable=0, .file_hint=&file_hint_nd2  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_nds)
  { .enable=0, .file_hint=&file_hint_nds  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_nes)
  { .enable=0, .file_hint=&file_hint_nes  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_njx)
  { .enable=0, .file_hint=&file_hint_njx  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_nk2)
  { .enable=0, .file_hint=&file_hint_nk2  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_nsf)
  { .enable=0, .file_hint=&file_hint_nsf  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_oci)
  { .enable=0, .file_hint=&file_hint_oci  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ogg)
  { .enable=0, .file_hint=&file_hint_ogg  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_one)
  { .enable=0, .file_hint=&file_hint_one  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_orf)
  { .enable=0, .file_hint=&file_hint_orf  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pa)
  { .enable=0, .file_hint=&file_hint_pa  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_paf)
  { .enable=0, .file_hint=&file_hint_paf  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pap)
  { .enable=0, .file_hint=&file_hint_pap  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_par2)
  { .enable=0, .file_hint=&file_hint_par2  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pcap)
  { .enable=0, .file_hint=&file_hint_pcap },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pcb)
  { .enable=0, .file_hint=&file_hint_pcb  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pct)
  { .enable=0, .file_hint=&file_hint_pct  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pcx)
  { .enable=0, .file_hint=&file_hint_pcx  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pdb)
  { .enable=0, .file_hint=&file_hint_pdb  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pdf)
  { .enable=0, .file_hint=&file_hint_pdf  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pds)
  { .enable=0, .file_hint=&file_hint_pds  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pf)
  { .enable=0, .file_hint=&file_hint_pf   },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pfx)
  { .enable=0, .file_hint=&file_hint_pfx  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pgdump)
  { .enable=0, .file_hint=&file_hint_pgdump  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_plist)
  { .enable=0, .file_hint=&file_hint_plist  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_plr)
  { .enable=0, .file_hint=&file_hint_plr  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_plt)
  { .enable=0, .file_hint=&file_hint_plt  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_png)
  { .enable=0, .file_hint=&file_hint_png  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pnm)
  { .enable=0, .file_hint=&file_hint_pnm  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_prc)
  { .enable=0, .file_hint=&file_hint_prc  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_prd)
  { .enable=0, .file_hint=&file_hint_prd  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_prt)
  { .enable=0, .file_hint=&file_hint_prt  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ps)
  { .enable=0, .file_hint=&file_hint_ps   },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_psb)
  { .enable=0, .file_hint=&file_hint_psb  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_psd)
  { .enable=0, .file_hint=&file_hint_psd  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_psf)
  { .enable=0, .file_hint=&file_hint_psf  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_psp)
  { .enable=0, .file_hint=&file_hint_psp  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pst)
  { .enable=0, .file_hint=&file_hint_pst  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ptb)
  { .enable=0, .file_hint=&file_hint_ptb  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ptf)
  { .enable=0, .file_hint=&file_hint_ptf  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pyc)
  { .enable=0, .file_hint=&file_hint_pyc  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pzf)
  { .enable=0, .file_hint=&file_hint_pzf  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pzh)
  { .enable=0, .file_hint=&file_hint_pzh  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_qbb)
  { .enable=0, .file_hint=&file_hint_qbb  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_qdf)
  { .enable=0, .file_hint=&file_hint_qdf  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_qkt)
  { .enable=0, .file_hint=&file_hint_qkt  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_qxd)
  { .enable=0, .file_hint=&file_hint_qxd  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_r3d)
  { .enable=0, .file_hint=&file_hint_r3d  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ra)
  { .enable=0, .file_hint=&file_hint_ra   },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_raf)
  { .enable=0, .file_hint=&file_hint_raf  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_rar)
  { .enable=0, .file_hint=&file_hint_rar  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_raw)
  { .enable=0, .file_hint=&file_hint_raw  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_rdc)
  { .enable=0, .file_hint=&file_hint_rdc  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_reg)
  { .enable=0, .file_hint=&file_hint_reg  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_res)
  { .enable=0, .file_hint=&file_hint_res  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_rfp)
  { .enable=0, .file_hint=&file_hint_rfp  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_riff)
  { .enable=0, .file_hint=&file_hint_riff },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_rlv)
  { .enable=0, .file_hint=&file_hint_rlv  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_rm)
  { .enable=0, .file_hint=&file_hint_rm   },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_rns)
  { .enable=0, .file_hint=&file_hint_rns  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_rpm)
  { .enable=0, .file_hint=&file_hint_rpm  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_rw2)
  { .enable=0, .file_hint=&file_hint_rw2  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_rx2)
  { .enable=0, .file_hint=&file_hint_rx2  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_save)
  { .enable=0, .file_hint=&file_hint_save  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_sdsk)
  { .enable=0, .file_hint=&file_hint_sdsk  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_sdw)
  { .enable=0, .file_hint=&file_hint_sdw  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ses)
  { .enable=0, .file_hint=&file_hint_ses  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_sgcta)
  { .enable=0, .file_hint=&file_hint_sgcta  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_shn)
  { .enable=0, .file_hint=&file_hint_shn  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_shp)
  { .enable=0, .file_hint=&file_hint_shp  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_sib)
  { .enable=0, .file_hint=&file_hint_sib  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_sit)
  { .enable=0, .file_hint=&file_hint_sit  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_skd)
  { .enable=0, .file_hint=&file_hint_skd  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_skp)
  { .enable=0, .file_hint=&file_hint_skp  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_snag)
  { .enable=0, .file_hint=&file_hint_snag  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_txt)
  { .enable=0, .file_hint=&file_hint_snz  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_sp3)
  { .enable=0, .file_hint=&file_hint_sp3  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_spe)
  { .enable=0, .file_hint=&file_hint_spe  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_spf)
  { .enable=0, .file_hint=&file_hint_spf  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_spss)
  { .enable=0, .file_hint=&file_hint_spss },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_sqlite)
  { .enable=0, .file_hint=&file_hint_sqlite	},
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_sqm)
  { .enable=0, .file_hint=&file_hint_sqm  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_steuer2014)
  { .enable=0, .file_hint=&file_hint_steuer2014  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_stl)
  { .enable=0, .file_hint=&file_hint_stl  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_studio)
  { .enable=0, .file_hint=&file_hint_studio  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_stuffit)
  { .enable=0, .file_hint=&file_hint_stuffit  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_swf)
  { .enable=0, .file_hint=&file_hint_swf  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_tar)
  { .enable=0, .file_hint=&file_hint_tar  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_tax)
  { .enable=0, .file_hint=&file_hint_tax  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_tg)
  { .enable=0, .file_hint=&file_hint_tg  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_tib)
  { .enable=0, .file_hint=&file_hint_tib  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_tiff)
  { .enable=0, .file_hint=&file_hint_tiff },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_tivo)
  { .enable=0, .file_hint=&file_hint_tivo  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_torrent)
  { .enable=0, .file_hint=&file_hint_torrent  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_tph)
  { .enable=0, .file_hint=&file_hint_tph  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_tpl)
  { .enable=0, .file_hint=&file_hint_tpl  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_m2ts)
  { .enable=0, .file_hint=&file_hint_ts   },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ttf)
  { .enable=0, .file_hint=&file_hint_ttf  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_txt)
  { .enable=0, .file_hint=&file_hint_fasttxt  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_txt)
  { .enable=0, .file_hint=&file_hint_txt  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_tz)
  { .enable=0, .file_hint=&file_hint_tz   },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_v2i)
  { .enable=0, .file_hint=&file_hint_v2i  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_vault)
  { .enable=0, .file_hint=&file_hint_vault  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_vdi)
  { .enable=0, .file_hint=&file_hint_vdi  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_vdj)
  { .enable=0, .file_hint=&file_hint_vdj  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_veg)
  { .enable=0, .file_hint=&file_hint_veg  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_vfb)
  { .enable=0, .file_hint=&file_hint_vfb  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_vib)
  { .enable=0, .file_hint=&file_hint_vib  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_vmdk)
  { .enable=0, .file_hint=&file_hint_vmdk },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_vmg)
  { .enable=0, .file_hint=&file_hint_vmg  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_wad)
  { .enable=0, .file_hint=&file_hint_wad  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_wallet)
  { .enable=0, .file_hint=&file_hint_wallet  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_wdp)
  { .enable=0, .file_hint=&file_hint_wdp  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_wee)
  { .enable=0, .file_hint=&file_hint_wee  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_wim)
  { .enable=0, .file_hint=&file_hint_wim  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_win)
  { .enable=0, .file_hint=&file_hint_win  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_wks)
  { .enable=0, .file_hint=&file_hint_wks  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_wld)
  { .enable=0, .file_hint=&file_hint_wld  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_wmf)
  { .enable=0, .file_hint=&file_hint_wmf  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_wnk)
  { .enable=0, .file_hint=&file_hint_wnk  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_woff)
  { .enable=0, .file_hint=&file_hint_woff  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_wpb)
  { .enable=0, .file_hint=&file_hint_wpb  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_wpd)
  { .enable=0, .file_hint=&file_hint_wpd  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_wtv)
  { .enable=0, .file_hint=&file_hint_wtv  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_wv)
  { .enable=0, .file_hint=&file_hint_wv   },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_x3f)
  { .enable=0, .file_hint=&file_hint_x3f  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_x3i)
  { .enable=0, .file_hint=&file_hint_x3i  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_x4a)
  { .enable=0, .file_hint=&file_hint_x4a  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_xar)
  { .enable=0, .file_hint=&file_hint_xar  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_xcf)
  { .enable=0, .file_hint=&file_hint_xcf  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_xfi)
  { .enable=0, .file_hint=&file_hint_xfi  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_xfs)
  { .enable=0, .file_hint=&file_hint_xfs  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_xm)
  { .enable=0, .file_hint=&file_hint_xm   },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_xml)
  { .enable=0, .file_hint=&file_hint_xml  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_xsv)
  { .enable=0, .file_hint=&file_hint_xsv  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_xpt)
  { .enable=0, .file_hint=&file_hint_xpt  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_xv)
  { .enable=0, .file_hint=&file_hint_xv   },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_xz)
  { .enable=0, .file_hint=&file_hint_xz   },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_z2d)
  { .enable=0, .file_hint=&file_hint_z2d  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_zcode)
  { .enable=0, .file_hint=&file_hint_zcode  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_zip)
  { .enable=0, .file_hint=&file_hint_zip  },
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_zpr)
  { .enable=0, .file_hint=&file_hint_zpr  },
#endif
  { .enable=0, .file_hint=NULL }
};

#ifdef SINGLE_FORMAT
#ifdef __OPTIMIZE__
#define __compiletime_error(message) __attribute__((__error__(message)))
# define __compiletime_assert(condition, msg, prefix, suffix)		\
	do {								\
		extern void prefix ## suffix(void) __compiletime_error(msg); \
		if (!(condition))					\
			prefix ## suffix();				\
	} while (0)

#define _compiletime_assert(condition, msg, prefix, suffix) \
	__compiletime_assert(condition, msg, prefix, suffix)

#define compiletime_assert(condition, msg) \
	_compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)

static void check_array_file_enable(void)
{
  compiletime_assert(sizeof(file_enable_t) != sizeof(array_file_enable), "No file format has been enabled");
}
#endif
#endif
