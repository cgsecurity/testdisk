/*

    File: photorec.c

    Copyright (C) 1998-2008 Christophe GRENIER <grenier@cgsecurity.org>

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
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <stdarg.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>	/* unlink, ftruncate */
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#include <ctype.h>      /* tolower */
#ifdef HAVE_LOCALE_H
#include <locale.h>	/* setlocale */
#endif
#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#include <errno.h>
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#include "types.h"
#include "common.h"
#include "intrf.h"
#include "godmode.h"
#include "fnctdsk.h"
#ifdef HAVE_NCURSES
#include "intrfn.h"
#else
#include <stdio.h>
#endif
#ifdef HAVE_JPEGLIB_H
#include <jpeglib.h>
#endif
#include "dir.h"
#include "filegen.h"
#include "photorec.h"
#include "fat.h"
#include "hdcache.h"
#include "ext2p.h"
#include "fatp.h"
#include "ntfsp.h"
#include "ewf.h"
#include "log.h"
#include "phrecn.h"
#include "hdaccess.h"
#include "sudo.h"
#include "phcfg.h"
#include "misc.h"
#include "ext2_dir.h"
#include "ntfs_dir.h"
#include "pdisksel.h"

/* #define DEBUG_FILE_FINISH */
/* #define DEBUG_UPDATE_SEARCH_SPACE */
/* #define DEBUG_FREE */

extern const arch_fnct_t arch_i386;
extern const arch_fnct_t arch_mac;
extern const arch_fnct_t arch_none;
extern const arch_fnct_t arch_sun;
extern const arch_fnct_t arch_xbox;

extern const file_hint_t file_hint_7z;
extern const file_hint_t file_hint_a;
extern const file_hint_t file_hint_abcdp;
extern const file_hint_t file_hint_accdb;
extern const file_hint_t file_hint_ace;
extern const file_hint_t file_hint_addressbook;
extern const file_hint_t file_hint_ahn;
extern const file_hint_t file_hint_aif;
extern const file_hint_t file_hint_all;
extern const file_hint_t file_hint_als;
extern const file_hint_t file_hint_amd;
extern const file_hint_t file_hint_amr;
extern const file_hint_t file_hint_arj;
extern const file_hint_t file_hint_asf;
extern const file_hint_t file_hint_asm;
extern const file_hint_t file_hint_au;
extern const file_hint_t file_hint_bkf;
extern const file_hint_t file_hint_blend;
extern const file_hint_t file_hint_bmp;
extern const file_hint_t file_hint_bz2;
extern const file_hint_t file_hint_cab;
extern const file_hint_t file_hint_cam;
extern const file_hint_t file_hint_chm;
extern const file_hint_t file_hint_cm;
extern const file_hint_t file_hint_compress;
extern const file_hint_t file_hint_crw;
extern const file_hint_t file_hint_ctg;
extern const file_hint_t file_hint_cwk;
extern const file_hint_t file_hint_dat;
extern const file_hint_t file_hint_dbf;
extern const file_hint_t file_hint_dim;
extern const file_hint_t file_hint_dir;
extern const file_hint_t file_hint_djv;
extern const file_hint_t file_hint_doc;
extern const file_hint_t file_hint_dpx;
extern const file_hint_t file_hint_drw;
extern const file_hint_t file_hint_ds2;
extern const file_hint_t file_hint_dsc;
extern const file_hint_t file_hint_dss;
extern const file_hint_t file_hint_dta;
extern const file_hint_t file_hint_dump;
extern const file_hint_t file_hint_dv;
extern const file_hint_t file_hint_dwg;
extern const file_hint_t file_hint_elf;
extern const file_hint_t file_hint_emf;
extern const file_hint_t file_hint_evt;
extern const file_hint_t file_hint_exe;
extern const file_hint_t file_hint_ext2_sb;
extern const file_hint_t file_hint_fbk;
extern const file_hint_t file_hint_fcp;
extern const file_hint_t file_hint_fcs;
extern const file_hint_t file_hint_fdb;
extern const file_hint_t file_hint_fh10;
extern const file_hint_t file_hint_fh5;
extern const file_hint_t file_hint_fits;
extern const file_hint_t file_hint_flac;
extern const file_hint_t file_hint_fasttxt;
extern const file_hint_t file_hint_flv;
extern const file_hint_t file_hint_fob;
extern const file_hint_t file_hint_frm;
extern const file_hint_t file_hint_fs;
extern const file_hint_t file_hint_gho;
extern const file_hint_t file_hint_gif;
extern const file_hint_t file_hint_gpg;
extern const file_hint_t file_hint_gz;
extern const file_hint_t file_hint_ifo;
extern const file_hint_t file_hint_imb;
extern const file_hint_t file_hint_indd;
extern const file_hint_t file_hint_iso;
extern const file_hint_t file_hint_itunes;
extern const file_hint_t file_hint_jpg;
extern const file_hint_t file_hint_kdb;
extern const file_hint_t file_hint_lnk;
extern const file_hint_t file_hint_m2ts;
extern const file_hint_t file_hint_max;
extern const file_hint_t file_hint_mb;
extern const file_hint_t file_hint_mcd;
extern const file_hint_t file_hint_mdb;
extern const file_hint_t file_hint_mdf;
extern const file_hint_t file_hint_mfg;
extern const file_hint_t file_hint_mid;
extern const file_hint_t file_hint_mkv;
extern const file_hint_t file_hint_mov;
extern const file_hint_t file_hint_mp3;
extern const file_hint_t file_hint_mpg;
extern const file_hint_t file_hint_mrw;
extern const file_hint_t file_hint_mus;
extern const file_hint_t file_hint_mysql;
extern const file_hint_t file_hint_njx;
extern const file_hint_t file_hint_ogg;
extern const file_hint_t file_hint_one;
extern const file_hint_t file_hint_orf;
extern const file_hint_t file_hint_paf;
extern const file_hint_t file_hint_pap;
extern const file_hint_t file_hint_pcap;
extern const file_hint_t file_hint_pct;
extern const file_hint_t file_hint_pcx;
extern const file_hint_t file_hint_pdf;
extern const file_hint_t file_hint_pfx;
extern const file_hint_t file_hint_png;
extern const file_hint_t file_hint_prc;
extern const file_hint_t file_hint_prt;
extern const file_hint_t file_hint_ps;
extern const file_hint_t file_hint_psd;
extern const file_hint_t file_hint_psp;
extern const file_hint_t file_hint_pst;
extern const file_hint_t file_hint_ptb;
extern const file_hint_t file_hint_qbb;
extern const file_hint_t file_hint_qdf;
extern const file_hint_t file_hint_qxd;
extern const file_hint_t file_hint_ra;
extern const file_hint_t file_hint_raf;
extern const file_hint_t file_hint_rar;
extern const file_hint_t file_hint_raw;
extern const file_hint_t file_hint_rdc;
extern const file_hint_t file_hint_reg;
extern const file_hint_t file_hint_res;
extern const file_hint_t file_hint_riff;
extern const file_hint_t file_hint_rm;
extern const file_hint_t file_hint_rns;
extern const file_hint_t file_hint_rpm;
extern const file_hint_t file_hint_sib;
extern const file_hint_t file_hint_sit;
extern const file_hint_t file_hint_skp;
extern const file_hint_t file_hint_sp3;
extern const file_hint_t file_hint_spe;
extern const file_hint_t file_hint_spss;
extern const file_hint_t file_hint_sqlite;
extern const file_hint_t file_hint_stl;
extern const file_hint_t file_hint_stuffit;
extern const file_hint_t file_hint_swf;
extern const file_hint_t file_hint_tar;
extern const file_hint_t file_hint_tib;
extern const file_hint_t file_hint_tiff;
extern const file_hint_t file_hint_tph;
extern const file_hint_t file_hint_txt;
extern const file_hint_t file_hint_veg;
extern const file_hint_t file_hint_vmdk;
extern const file_hint_t file_hint_wks;
extern const file_hint_t file_hint_wmf;
extern const file_hint_t file_hint_wnk;
extern const file_hint_t file_hint_wpd;
extern const file_hint_t file_hint_x3f;
extern const file_hint_t file_hint_xcf;
extern const file_hint_t file_hint_xm;
extern const file_hint_t file_hint_xsv;
extern const file_hint_t file_hint_zip;

static alloc_data_t *update_search_space(const file_recovery_t *file_recovery, alloc_data_t *list_search_space, alloc_data_t **new_current_search_space, uint64_t *offset, const unsigned int blocksize);
static alloc_data_t *update_search_space_aux(alloc_data_t *list_search_space, uint64_t start, uint64_t end, alloc_data_t **new_current_search_space, uint64_t *offset);

static void list_free_add(const file_recovery_t *file_recovery, alloc_data_t *list_search_space);

#ifdef HAVE_SIGACTION
void sighup_hdlr(int shup)
{
  log_critical("SIGHUP detected! PhotoRec has been killed.\n");
  log_close();
  exit(1);
}
#endif

void list_space_used(const file_recovery_t *file_recovery, const unsigned int sector_size)
{
  struct td_list_head *tmp;
  uint64_t file_size=0;
  uint64_t file_size_on_disk=0;
  if(file_recovery->filename==NULL)
    return;
  log_info("%s\t",file_recovery->filename);
  td_list_for_each(tmp, &file_recovery->location.list)
  {
    const alloc_list_t *element=td_list_entry(tmp, alloc_list_t, list);
    file_size_on_disk+=(element->end-element->start+1);
    if(element->data>0)
    {
      log_info(" %lu-%lu", (unsigned long)(element->start/sector_size), (unsigned long)(element->end/sector_size));
      file_size+=(element->end-element->start+1);
    }
    else
    {
      log_info(" (%lu-%lu)", (unsigned long)(element->start/sector_size), (unsigned long)(element->end/sector_size));
    }
  }
  log_info("\n");
  /*
  log_trace("list file_size %lu, file_size_on_disk %lu\n",
      (unsigned long)file_size, (unsigned long)file_size_on_disk);
  log_trace("file_size %lu, file_size_on_disk %lu\n",
      (unsigned long)file_recovery->file_size, (unsigned long)file_recovery->file_size_on_disk);
   */
}

static void list_free_add(const file_recovery_t *file_recovery, alloc_data_t *list_search_space)
{
  struct td_list_head *search_walker = NULL;
#ifdef DEBUG_FREE
  log_trace("list_free_add %lu\n",(long unsigned)(file_recovery->location.start/512));
#endif
  td_list_for_each(search_walker, &list_search_space->list)
  {
    alloc_data_t *current_search_space;
    current_search_space=td_list_entry(search_walker, alloc_data_t, list);
    if(current_search_space->start < file_recovery->location.start && file_recovery->location.start < current_search_space->end)
    {
      alloc_data_t *new_free_space;
      new_free_space=(alloc_data_t*)MALLOC(sizeof(*new_free_space));
      new_free_space->start=file_recovery->location.start;
      new_free_space->end=current_search_space->end;
      new_free_space->file_stat=NULL;
      current_search_space->end=file_recovery->location.start-1;
      td_list_add(&new_free_space->list, search_walker);
    }
    if(current_search_space->start==file_recovery->location.start)
    {
      current_search_space->file_stat=file_recovery->file_stat;
      return ;
    }
  }
}

static alloc_data_t *update_search_space(const file_recovery_t *file_recovery, alloc_data_t *list_search_space, alloc_data_t **new_current_search_space, uint64_t *offset, const unsigned int blocksize)
{
  struct td_list_head *search_walker = NULL;
#ifdef DEBUG_UPDATE_SEARCH_SPACE
  log_trace("update_search_space\n");
  info_list_search_space(list_search_space, NULL, DEFAULT_SECTOR_SIZE, 0, 1);
#endif

  td_list_for_each(search_walker, &list_search_space->list)
  {
    struct td_list_head *tmp;
    alloc_data_t *current_search_space;
    current_search_space=td_list_entry(search_walker, alloc_data_t, list);
    if(current_search_space->start <= file_recovery->location.start &&
        file_recovery->location.start <= current_search_space->end)
    {
      *offset=file_recovery->location.start;
      *new_current_search_space=current_search_space;
      td_list_for_each(tmp, &file_recovery->location.list)
      {
	const alloc_list_t *element=td_list_entry(tmp, alloc_list_t, list);
        uint64_t end=(element->end-(element->start%blocksize)+blocksize-1+1)/blocksize*blocksize+(element->start%blocksize)-1;
        list_search_space=update_search_space_aux(list_search_space, element->start, end, new_current_search_space, offset);
      }
      return list_search_space;
    }
  }
  return list_search_space;
}

alloc_data_t *del_search_space(alloc_data_t *list_search_space, const uint64_t start, const uint64_t end)
{
  return update_search_space_aux(list_search_space, start, end, NULL, NULL);
}

static alloc_data_t *update_search_space_aux(alloc_data_t *list_search_space, const uint64_t start, const uint64_t end, alloc_data_t **new_current_search_space, uint64_t *offset)
{
  struct td_list_head *search_walker = NULL;
#ifdef DEBUG_UPDATE_SEARCH_SPACE
  log_trace("update_search_space_aux offset=%llu remove [%llu-%llu]\n",
      (long long unsigned)((*offset)/512),
      (unsigned long long)(start/512),
      (unsigned long long)(end/512));
#endif
  if(start >= end)
    return list_search_space;
  td_list_for_each(search_walker, &list_search_space->list)
  {
    alloc_data_t *current_search_space;
    current_search_space=td_list_entry(search_walker, alloc_data_t, list);
#ifdef DEBUG_UPDATE_SEARCH_SPACE
    log_trace("update_search_space_aux offset=%llu remove [%llu-%llu] in [%llu-%llu]\n",
        (long long unsigned)((*offset)/512),
        (unsigned long long)(start/512),
        (unsigned long long)(end/512),
        (unsigned long long)(current_search_space->start/512),
        (unsigned long long)(current_search_space->end/512));
#endif
    if(current_search_space->start==start)
    {
      const uint64_t pivot=current_search_space->end+1;
      if(end+1<current_search_space->end)
      { /* current_search_space->start==start end+1<current_search_space->end */
        if(offset!=NULL && new_current_search_space!=NULL &&
            current_search_space->start<=*offset && *offset<=end)
        {
          *new_current_search_space=current_search_space;
          *offset=end+1;
        }
        current_search_space->start=end+1;
        current_search_space->file_stat=NULL;
        return list_search_space;
      }
      /* current_search_space->start==start current_search_space->end<=end */
      if(list_search_space==current_search_space)
        list_search_space=td_list_entry(current_search_space->list.next, alloc_data_t, list);
      if(offset!=NULL && new_current_search_space!=NULL &&
          current_search_space->start<=*offset && *offset<=current_search_space->end)
      {
        *new_current_search_space=td_list_entry(current_search_space->list.next, alloc_data_t, list);
        *offset=(*new_current_search_space)->start;
      }
      td_list_del(search_walker);
      free(current_search_space);
      return update_search_space_aux(list_search_space, pivot, end, new_current_search_space, offset);
    }
    if(current_search_space->end==end)
    {
      const uint64_t pivot=current_search_space->start-1;
#ifdef DEBUG_UPDATE_SEARCH_SPACE
      log_trace("current_search_space->end==end\n");
#endif
      if(current_search_space->start+1<start)
      { /* current_search_space->start<start current_search_space->end==end */
        if(offset!=NULL && new_current_search_space!=NULL &&
            start<=*offset && *offset<=current_search_space->end)
        {
          *new_current_search_space=td_list_entry(current_search_space->list.next, alloc_data_t, list);
          *offset=(*new_current_search_space)->start;
        }
        current_search_space->end=start-1;
        return list_search_space;
      }
      /* start<=current_search_space->start current_search_space->end==end */
      if(list_search_space==current_search_space)
        list_search_space=td_list_entry(current_search_space->list.next, alloc_data_t, list);
      if(offset!=NULL && new_current_search_space!=NULL &&
          current_search_space->start<=*offset && *offset<=current_search_space->end)
      {
        *new_current_search_space=td_list_entry(current_search_space->list.next, alloc_data_t, list);
        *offset=(*new_current_search_space)->start;
      }
      td_list_del(search_walker);
      free(current_search_space);
      return update_search_space_aux(list_search_space, start, pivot, new_current_search_space, offset);
    }
    if(start < current_search_space->start && current_search_space->start <= end)
    {
      const uint64_t pivot=current_search_space->start;
      list_search_space=update_search_space_aux(list_search_space, start, pivot-1,  new_current_search_space, offset);
      return update_search_space_aux(list_search_space, pivot, end, new_current_search_space, offset);
    }
    if(start <= current_search_space->end && current_search_space->end < end)
    {
      const uint64_t pivot=current_search_space->end;
      list_search_space=update_search_space_aux(list_search_space, start, pivot, new_current_search_space, offset);
      return update_search_space_aux(list_search_space, pivot+1, end, new_current_search_space, offset);
    }
    if(current_search_space->start < start && end < current_search_space->end)
    {
      alloc_data_t *new_free_space;
      new_free_space=(alloc_data_t*)MALLOC(sizeof(*new_free_space));
      new_free_space->start=start;
      new_free_space->end=current_search_space->end;
      new_free_space->file_stat=NULL;
      current_search_space->end=start-1;
      td_list_add(&new_free_space->list,search_walker);
      if(offset!=NULL && new_current_search_space!=NULL &&
          new_free_space->start<=*offset && *offset<=new_free_space->end)
      {
        *new_current_search_space=new_free_space;
      }
      return update_search_space_aux(list_search_space, start, end, new_current_search_space, offset);
    }
  }
  return list_search_space;
}

void init_search_space(alloc_data_t *list_search_space, const disk_t *disk_car, const partition_t *partition)
{
  alloc_data_t *new_sp;
  new_sp=(alloc_data_t*)MALLOC(sizeof(*new_sp));
  new_sp->start=partition->part_offset;
  new_sp->end=partition->part_offset+partition->part_size-1;
  if(new_sp->end > disk_car->disk_size-1)
    new_sp->end = disk_car->disk_size-1;
  if(new_sp->end > disk_car->disk_real_size-1)
    new_sp->end = disk_car->disk_real_size-1;
  new_sp->file_stat=NULL;
  new_sp->list.prev=&new_sp->list;
  new_sp->list.next=&new_sp->list;
  td_list_add_tail(&new_sp->list, &list_search_space->list);
}

void free_list_search_space(alloc_data_t *list_search_space)
{
  struct td_list_head *search_walker = NULL;
  struct td_list_head *search_walker_next = NULL;
  td_list_for_each_safe(search_walker,search_walker_next,&list_search_space->list)
  {
    alloc_data_t *current_search_space;
    current_search_space=td_list_entry(search_walker, alloc_data_t, list);
    td_list_del(search_walker);
    free(current_search_space);
  }
}

void reset_file_recovery(file_recovery_t *file_recovery)
{
  file_recovery->filename[0]='\0';
  file_recovery->time=0;
  file_recovery->file_stat=NULL;
  file_recovery->handle=NULL;
  file_recovery->file_size=0;
  file_recovery->file_size_on_disk=0;
  file_recovery->location.list.prev=&file_recovery->location.list;
  file_recovery->location.list.next=&file_recovery->location.list;
  file_recovery->location.start=0;
  file_recovery->location.end=0;
  file_recovery->location.data=0;
  file_recovery->extension=NULL;
  file_recovery->min_filesize=0;
  file_recovery->calculated_file_size=0;
  file_recovery->data_check=NULL;
  file_recovery->file_check=NULL;
  file_recovery->offset_error=0;
}

unsigned int photorec_mkdir(const char *recup_dir, const unsigned int initial_dir_num)
{
  char working_recup_dir[2048];
  int dir_ok=0;
  int dir_num=initial_dir_num;
#ifdef DJGPP
  int i=0;
#endif
  do
  {
    snprintf(working_recup_dir,sizeof(working_recup_dir)-1,"%s.%d",recup_dir,dir_num);
#ifdef HAVE_MKDIR
#ifdef __MINGW32__
    if(mkdir(working_recup_dir)!=0 && errno==EEXIST)
#else
      if(mkdir(working_recup_dir, 0775)!=0 && errno==EEXIST)
#endif
#else
#warning You need a mkdir function!
#endif
      {
	dir_num++;
      }
      else
      {
	dir_ok=1;
      }
#ifdef DJGPP
  /* Avoid endless loop in Dos version of Photorec after 999 directories if working with short name */
    i++;
    if(dir_ok==0 && i==1000)
    {
      dir_num=initial_dir_num;
      dir_ok=1;
    }
#endif
  } while(dir_ok==0);
  return dir_num;
}

int get_prev_file_header(alloc_data_t *list_search_space, alloc_data_t **current_search_space, uint64_t *offset)
{
  int nbr;
  alloc_data_t *file_space=*current_search_space;
  for(nbr=0;nbr<10;nbr++)
  {
    file_space=td_list_entry(file_space->list.prev, alloc_data_t, list);
    if(file_space==list_search_space)
      return -1;
    if(file_space->file_stat!=NULL)
    {
      *current_search_space=file_space;
      *offset=file_space->start;
      return 0;
    }
  }
  return -1;
}

void forget(alloc_data_t *list_search_space, alloc_data_t *current_search_space)
{
  struct td_list_head *search_walker = NULL;
  struct td_list_head *prev= NULL;
  int nbr=0;
  if(current_search_space==list_search_space)
    return ;
  for(search_walker=&current_search_space->list;
      search_walker!=&list_search_space->list;
      search_walker=prev)
  {
    prev=search_walker->prev;
    if(nbr>10000)
    {
      alloc_data_t *tmp;
      tmp=td_list_entry(search_walker, alloc_data_t, list);
      td_list_del(&tmp->list);
      free(tmp);
    }
    else
      nbr++;
  }
}

void list_cluster_free(list_cluster_t *list_cluster)
{
  struct td_list_head *dir_walker = NULL;
  struct td_list_head *dir_walker_next = NULL;
  td_list_for_each_safe(dir_walker,dir_walker_next,&list_cluster->list)
  {
    list_cluster_t *info;
    info=td_list_entry(dir_walker, list_cluster_t, list);
    delete_list_file(info->dir_list);
    td_list_del(dir_walker);
    free(info);
  }
}

unsigned int remove_used_space(disk_t *disk_car, const partition_t *partition, alloc_data_t *list_search_space)
{
  if(partition->upart_type==UP_FAT16 || partition->upart_type==UP_FAT32)
    return fat_remove_used_space(disk_car, partition, list_search_space);
#ifdef HAVE_LIBNTFS
  else if(partition->upart_type==UP_NTFS)
    return ntfs_remove_used_space(disk_car, partition, list_search_space);
#endif
#ifdef HAVE_LIBEXT2FS
  else if(partition->upart_type==UP_EXT2 || partition->upart_type==UP_EXT3 || partition->upart_type==UP_EXT4)
    return ext2_remove_used_space(disk_car, partition, list_search_space);
#endif
  return 0;
}

void update_stats(file_stat_t *file_stats, alloc_data_t *list_search_space)
{
  struct td_list_head *search_walker = NULL;
  int i;
  /* Reset */
  for(i=0;file_stats[i].file_hint!=NULL;i++)
    file_stats[i].not_recovered=0;
  /* Update */
  td_list_for_each(search_walker, &list_search_space->list)
  {
    alloc_data_t *current_search_space;
    current_search_space=td_list_entry(search_walker, alloc_data_t, list);
    if(current_search_space->file_stat!=NULL)
    {
      current_search_space->file_stat->not_recovered++;
    }
  }
}

void write_stats_log(const file_stat_t *file_stats)
{
  unsigned int file_nbr=0;
  unsigned int i;
  unsigned int nbr;
  file_stat_t *new_file_stats;
  for(i=0;file_stats[i].file_hint!=NULL;i++);
  if(i==0)
    return ;
  nbr=i;
  new_file_stats=(file_stat_t*)MALLOC(nbr*sizeof(file_stat_t));
  memcpy(new_file_stats, file_stats, nbr*sizeof(file_stat_t));
  qsort(new_file_stats, nbr, sizeof(file_stat_t), sorfile_stat_ts);
  for(i=0;i<nbr;i++)
  {
    if(new_file_stats[i].recovered+new_file_stats[i].not_recovered>0)
    {
      file_nbr+=new_file_stats[i].recovered;
      log_info("%s: %u/%u recovered\n",
          (new_file_stats[i].file_hint->extension!=NULL?
           new_file_stats[i].file_hint->extension:""),
          new_file_stats[i].recovered, new_file_stats[i].recovered+new_file_stats[i].not_recovered);
    }
  }
  free(new_file_stats);
  if(file_nbr>1)
  {
    log_info("Total: %u files found\n\n",file_nbr);
  }
  else
  {
    log_info("Total: %u file found\n\n",file_nbr);
  }
}

int sorfile_stat_ts(const void *p1, const void *p2)
{
  const file_stat_t *f1=(const file_stat_t *)p1;
  const file_stat_t *f2=(const file_stat_t *)p2;
  /* bigest to lowest */
  if(f1->recovered < f2->recovered)
    return 1;
  if(f1->recovered > f2->recovered)
    return -1;
  return 0;
}

void write_stats_stdout(const file_stat_t *file_stats)
{
  int i;
  unsigned int file_nbr=0;
  for(i=0;file_stats[i].file_hint!=NULL;i++)
  {
    if(file_stats[i].recovered+file_stats[i].not_recovered>0)
    {
      file_nbr+=file_stats[i].recovered;
      printf("%s: %u/%u recovered\n",
          (file_stats[i].file_hint->extension!=NULL?
           file_stats[i].file_hint->extension:""),
          file_stats[i].recovered, file_stats[i].recovered+file_stats[i].not_recovered);
    }
  }
  if(file_nbr>1)
  {
    printf("Total: %u files found\n\n",file_nbr);
  }
  else
  {
    printf("Total: %u file found\n\n",file_nbr);
  }
}

partition_t *new_whole_disk(const disk_t *disk_car)
{
  partition_t *fake_partition;
  fake_partition=partition_new(disk_car->arch);
  fake_partition->part_offset=0;
  fake_partition->part_size=disk_car->disk_size;
  strncpy(fake_partition->fsname,"Whole disk",sizeof(fake_partition->fsname)-1);
  return fake_partition;
}


typedef struct info_cluster_offset cluster_offset_t;

struct info_cluster_offset
{
  unsigned int cluster_size;
  unsigned long int offset;
  unsigned int nbr;
};

unsigned int find_blocksize(alloc_data_t *list_search_space, const unsigned int default_blocksize, uint64_t *offset)
{
  int blocksize_ok=2;
  unsigned int blocksize;
  *offset=0;
  for(blocksize=128*512;blocksize>=default_blocksize && blocksize_ok==2;blocksize=blocksize>>1)
  {
    struct td_list_head *search_walker = NULL;
    blocksize_ok=0;
    td_list_for_each(search_walker, &list_search_space->list)
    {
      alloc_data_t *tmp;
      tmp=td_list_entry(search_walker, alloc_data_t, list);
      if(tmp->file_stat!=NULL)
      {
	if(blocksize_ok==0)
	{
	  *offset=tmp->start%blocksize;
	  blocksize_ok=1;
	}
	else if(tmp->start%blocksize!=*offset)
	{
	  blocksize_ok=2;
	  break;
	}
      }
    }
    if(blocksize_ok==0)
      return default_blocksize;
  }
  blocksize=blocksize<<1;
  return blocksize;
}

alloc_data_t * update_blocksize(unsigned int blocksize, alloc_data_t *list_search_space, const uint64_t offset)
{
  struct td_list_head *search_walker = NULL;
  struct td_list_head *search_walker_next = NULL;
  td_list_for_each_safe(search_walker,search_walker_next,&list_search_space->list)
  {
    alloc_data_t *current_search_space;
    current_search_space=td_list_entry(search_walker, alloc_data_t, list);
    current_search_space->start=(current_search_space->start-offset%blocksize+blocksize-1)/blocksize*blocksize+offset%blocksize;
    if(current_search_space->start>current_search_space->end)
    {
      td_list_del(search_walker);
      if(list_search_space==current_search_space)
        list_search_space=td_list_entry(search_walker_next, alloc_data_t, list);
      free(current_search_space);
    }
  }
  return list_search_space;
}

int main( int argc, char **argv )
{
  int i;
  int use_sudo=0;
  int help=0, version=0, verbose=0;
  int create_log=TD_LOG_NONE;
  int run_setlocale=1;
  int testdisk_mode=TESTDISK_O_RDONLY|TESTDISK_O_READAHEAD_32K;
  const char *recup_dir=NULL;
  list_disk_t *list_disk=NULL;
  list_disk_t *element_disk;
  char *cmd_device=NULL;
  char *cmd_run=NULL;
#ifdef TARGET_SOLARIS
  const arch_fnct_t *arch=&arch_sun;
#elif defined __APPLE__
  const arch_fnct_t *arch=&arch_mac;
#else
  const arch_fnct_t *arch=&arch_i386;
#endif
#ifdef HAVE_SIGACTION
  struct sigaction action, old_action;
#endif
  file_enable_t list_file_enable[]=
  {
    { .enable=0, .file_hint=&file_hint_7z   },
    { .enable=0, .file_hint=&file_hint_a    },
    { .enable=0, .file_hint=&file_hint_abcdp},
    { .enable=0, .file_hint=&file_hint_accdb},
    { .enable=0, .file_hint=&file_hint_ace  },
    { .enable=0, .file_hint=&file_hint_addressbook},
    { .enable=0, .file_hint=&file_hint_ahn  },
    { .enable=0, .file_hint=&file_hint_aif  },
    { .enable=0, .file_hint=&file_hint_all  },
    { .enable=0, .file_hint=&file_hint_als  },
    { .enable=0, .file_hint=&file_hint_amd  },
    { .enable=0, .file_hint=&file_hint_amr  },
    { .enable=0, .file_hint=&file_hint_arj  },
    { .enable=0, .file_hint=&file_hint_asf  },
    { .enable=0, .file_hint=&file_hint_asm  },
    { .enable=0, .file_hint=&file_hint_au   },
    { .enable=0, .file_hint=&file_hint_bkf  },
    { .enable=0, .file_hint=&file_hint_blend },
    { .enable=0, .file_hint=&file_hint_bmp  },
    { .enable=0, .file_hint=&file_hint_bz2  },
    { .enable=0, .file_hint=&file_hint_cab  },
    { .enable=0, .file_hint=&file_hint_cam  },
    { .enable=0, .file_hint=&file_hint_chm  },
    { .enable=0, .file_hint=&file_hint_cm  },
    { .enable=0, .file_hint=&file_hint_compress },
    { .enable=0, .file_hint=&file_hint_crw  },
    { .enable=0, .file_hint=&file_hint_ctg  },
    { .enable=0, .file_hint=&file_hint_cwk  },
    { .enable=0, .file_hint=&file_hint_dat  },
    { .enable=0, .file_hint=&file_hint_dbf  },
    { .enable=0, .file_hint=&file_hint_dim  },
    { .enable=0, .file_hint=&file_hint_dir  },
    { .enable=0, .file_hint=&file_hint_djv  },
    { .enable=0, .file_hint=&file_hint_drw  },
    { .enable=0, .file_hint=&file_hint_doc  },
    { .enable=0, .file_hint=&file_hint_dpx  },
    { .enable=0, .file_hint=&file_hint_ds2  },
    { .enable=0, .file_hint=&file_hint_dsc  },
    { .enable=0, .file_hint=&file_hint_dss  },
    { .enable=0, .file_hint=&file_hint_dta  },
    { .enable=0, .file_hint=&file_hint_dump },
    { .enable=0, .file_hint=&file_hint_dv   },
    { .enable=0, .file_hint=&file_hint_dwg  },
    { .enable=0, .file_hint=&file_hint_elf  },
    { .enable=0, .file_hint=&file_hint_emf  },
    { .enable=0, .file_hint=&file_hint_evt  },
    { .enable=0, .file_hint=&file_hint_exe  },
    { .enable=0, .file_hint=&file_hint_ext2_sb },
    { .enable=0, .file_hint=&file_hint_fbk  },
    { .enable=0, .file_hint=&file_hint_fcp  },
    { .enable=0, .file_hint=&file_hint_fcs  },
    { .enable=0, .file_hint=&file_hint_fdb  },
    { .enable=0, .file_hint=&file_hint_fh10  },
    { .enable=0, .file_hint=&file_hint_fh5  },
    { .enable=0, .file_hint=&file_hint_fits },
    { .enable=0, .file_hint=&file_hint_flac },
    { .enable=0, .file_hint=&file_hint_flv  },
    { .enable=0, .file_hint=&file_hint_fob  },
    { .enable=0, .file_hint=&file_hint_frm  },
    { .enable=0, .file_hint=&file_hint_fs   },
    { .enable=0, .file_hint=&file_hint_gho  },
    { .enable=0, .file_hint=&file_hint_gif  },
    { .enable=0, .file_hint=&file_hint_gpg  },
    { .enable=0, .file_hint=&file_hint_gz   },
    { .enable=0, .file_hint=&file_hint_ifo  },
    { .enable=0, .file_hint=&file_hint_imb  },
    { .enable=0, .file_hint=&file_hint_indd  },
    { .enable=0, .file_hint=&file_hint_iso  },
    { .enable=0, .file_hint=&file_hint_itunes  },
    { .enable=0, .file_hint=&file_hint_jpg  },
    { .enable=0, .file_hint=&file_hint_kdb  },
    { .enable=0, .file_hint=&file_hint_lnk  },
    { .enable=0, .file_hint=&file_hint_m2ts },
    { .enable=0, .file_hint=&file_hint_max  },
    { .enable=0, .file_hint=&file_hint_mb   },
    { .enable=0, .file_hint=&file_hint_mcd  },
    { .enable=0, .file_hint=&file_hint_mdb  },
    { .enable=0, .file_hint=&file_hint_mdf  },
    { .enable=0, .file_hint=&file_hint_mfg  },
    { .enable=0, .file_hint=&file_hint_mid  },
    { .enable=0, .file_hint=&file_hint_mkv  },
    { .enable=0, .file_hint=&file_hint_mov  },
    { .enable=0, .file_hint=&file_hint_mp3  },
    { .enable=0, .file_hint=&file_hint_mpg  },
    { .enable=0, .file_hint=&file_hint_mrw  },
    { .enable=0, .file_hint=&file_hint_mus  },
    { .enable=0, .file_hint=&file_hint_mysql },
    { .enable=0, .file_hint=&file_hint_njx  },
    { .enable=0, .file_hint=&file_hint_ogg  },
    { .enable=0, .file_hint=&file_hint_one  },
    { .enable=0, .file_hint=&file_hint_orf  },
    { .enable=0, .file_hint=&file_hint_paf  },
    { .enable=0, .file_hint=&file_hint_pap  },
    { .enable=0, .file_hint=&file_hint_pcap },
    { .enable=0, .file_hint=&file_hint_pct  },
    { .enable=0, .file_hint=&file_hint_pcx  },
    { .enable=0, .file_hint=&file_hint_pdf  },
    { .enable=0, .file_hint=&file_hint_pfx  },
    { .enable=0, .file_hint=&file_hint_png  },
    { .enable=0, .file_hint=&file_hint_prc  },
    { .enable=0, .file_hint=&file_hint_prt  },
    { .enable=0, .file_hint=&file_hint_ps   },
    { .enable=0, .file_hint=&file_hint_psd  },
    { .enable=0, .file_hint=&file_hint_psp  },
    { .enable=0, .file_hint=&file_hint_pst  },
    { .enable=0, .file_hint=&file_hint_ptb  },
    { .enable=0, .file_hint=&file_hint_qbb  },
    { .enable=0, .file_hint=&file_hint_qdf  },
    { .enable=0, .file_hint=&file_hint_qxd  },
    { .enable=0, .file_hint=&file_hint_ra  },
    { .enable=0, .file_hint=&file_hint_raf  },
    { .enable=0, .file_hint=&file_hint_rar  },
    { .enable=0, .file_hint=&file_hint_raw  },
    { .enable=0, .file_hint=&file_hint_rdc  },
    { .enable=0, .file_hint=&file_hint_reg  },
    { .enable=0, .file_hint=&file_hint_res  },
    { .enable=0, .file_hint=&file_hint_riff },
    { .enable=0, .file_hint=&file_hint_rm   },
    { .enable=0, .file_hint=&file_hint_rns  },
    { .enable=0, .file_hint=&file_hint_rpm  },
    { .enable=0, .file_hint=&file_hint_sib  },
    { .enable=0, .file_hint=&file_hint_sit  },
    { .enable=0, .file_hint=&file_hint_skp  },
    { .enable=0, .file_hint=&file_hint_sp3  },
    { .enable=0, .file_hint=&file_hint_spe  },
    { .enable=0, .file_hint=&file_hint_spss },
    { .enable=0, .file_hint=&file_hint_sqlite	},
    { .enable=0, .file_hint=&file_hint_stl  },
    { .enable=0, .file_hint=&file_hint_stuffit  },
    { .enable=0, .file_hint=&file_hint_swf  },
    { .enable=0, .file_hint=&file_hint_tar  },
    { .enable=0, .file_hint=&file_hint_tib  },
    { .enable=0, .file_hint=&file_hint_tiff },
    { .enable=0, .file_hint=&file_hint_tph  },
    { .enable=0, .file_hint=&file_hint_fasttxt  },
    { .enable=0, .file_hint=&file_hint_txt  },
    { .enable=0, .file_hint=&file_hint_vmdk },
    { .enable=0, .file_hint=&file_hint_veg  },
    { .enable=0, .file_hint=&file_hint_wks  },
    { .enable=0, .file_hint=&file_hint_wmf  },
    { .enable=0, .file_hint=&file_hint_wnk  },
    { .enable=0, .file_hint=&file_hint_wpd  },
    { .enable=0, .file_hint=&file_hint_x3f  },
    { .enable=0, .file_hint=&file_hint_xcf  },
    { .enable=0, .file_hint=&file_hint_xm   },
    { .enable=0, .file_hint=&file_hint_xsv  },
    { .enable=0, .file_hint=&file_hint_zip  },
    { .enable=0, .file_hint=NULL }
  };
  /* random (weak is ok) is need fot GPT */
  srand(time(NULL));
#ifdef HAVE_SIGACTION
  /* set up the signal handler for SIGHUP */
  action.sa_handler  = sighup_hdlr;
  action.sa_flags = 0;
  if(sigaction(SIGHUP, &action, &old_action)==-1)
  {
    printf("Error on SIGACTION call\n");
    return -1;
  }
#endif
  printf("PhotoRec %s, Data Recovery Utility, %s\nChristophe GRENIER <grenier@cgsecurity.org>\nhttp://www.cgsecurity.org\n",VERSION,TESTDISKDATE);
  for(i=1;i<argc;i++)
  {
    if((strcmp(argv[i],"/log")==0) ||(strcmp(argv[i],"-log")==0))
    {
      if(create_log==TD_LOG_NONE)
        create_log=log_open("photorec.log", TD_LOG_APPEND, 0, "PhotoRec", argc, argv);
    }
    else if((strcmp(argv[i],"/debug")==0) || (strcmp(argv[i],"-debug")==0))
    {
      verbose++;
      if(create_log==TD_LOG_NONE)
        create_log=log_open("photorec.log", TD_LOG_APPEND, 0, "PhotoRec", argc, argv);
    }
    else if(((strcmp(argv[i],"/d")==0)||(strcmp(argv[i],"-d")==0)) &&(i+1<argc))
    {
      int len=strlen(argv[i+1]);
      if(argv[i+1][len-1]=='\\' || argv[i+1][len-1]=='/')
      {
        char *new_recup_dir=(char *)MALLOC(len+strlen(DEFAULT_RECUP_DIR)+1);
        strcpy(new_recup_dir,argv[i+1]);
        strcat(new_recup_dir,DEFAULT_RECUP_DIR);
        recup_dir=new_recup_dir;	/* small memory leak */
      }
      else
        recup_dir=argv[i+1];
      i++;
    }
    else if((strcmp(argv[i],"/all")==0) || (strcmp(argv[i],"-all")==0))
      testdisk_mode|=TESTDISK_O_ALL;
    else if((strcmp(argv[i],"/direct")==0) || (strcmp(argv[i],"-direct")==0))
      testdisk_mode|=TESTDISK_O_DIRECT;
    else if((strcmp(argv[i],"/help")==0) || (strcmp(argv[i],"-help")==0) || (strcmp(argv[i],"--help")==0) ||
      (strcmp(argv[i],"/h")==0) || (strcmp(argv[i],"-h")==0))
      help=1;
    else if((strcmp(argv[i],"/version")==0) || (strcmp(argv[i],"-version")==0) || (strcmp(argv[i],"--version")==0) ||
      (strcmp(argv[i],"/v")==0) || (strcmp(argv[i],"-v")==0))
      version=1;
    else if((strcmp(argv[i],"/nosetlocale")==0) || (strcmp(argv[i],"-nosetlocale")==0))
      run_setlocale=0;
    else if(strcmp(argv[i],"/cmd")==0)
    {
      if(i+2>=argc)
        help=1;
      else
      {
        disk_t *disk_car;
        cmd_device=argv[++i];
        cmd_run=argv[++i];
        /* There is no log currently */
        disk_car=file_test_availability(cmd_device,verbose,arch,testdisk_mode);
        if(disk_car==NULL)
        {
          printf("\nUnable to open file or device %s\n",cmd_device);
          help=1;
        }
        else
          list_disk=insert_new_disk(list_disk,disk_car);
      }
    }
    else
    {
      disk_t *disk_car=file_test_availability(argv[i],verbose,arch,testdisk_mode);
      if(disk_car==NULL)
      {
        printf("\nUnable to open file or device %s\n",argv[i]);
        help=1;
      }
      else
        list_disk=insert_new_disk(list_disk,disk_car);
    }
  }
  if(version!=0)
  {
    printf("\n");
    printf("Version: %s\n", VERSION);
    printf("Compiler: %s\n", get_compiler());
    printf("ext2fs lib: %s, ntfs lib: %s, ewf lib: %s, libjpeg: ",
	td_ext2fs_version(), td_ntfs_version(), td_ewf_version());
#if defined(HAVE_LIBJPEG)
#if defined(JPEG_LIB_VERSION)
    printf("%u", JPEG_LIB_VERSION);
#else
    printf("yes");
#endif
#else
    printf("none");
#endif
    printf("\n");
    printf("OS: %s\n" , get_os());
    return 0;
  }
  if(help!=0)
  {
    printf("\nUsage: photorec [/log] [/debug] [/d recup_dir] [file.dd|file.e01|device]\n"\
	"       photorec /version\n" \
        "\n" \
        "/log          : create a photorec.log file\n" \
        "/debug        : add debug information\n" \
        "\n" \
        "PhotoRec searches various file formats (JPEG, Office...), it stores them\n" \
        "in recup_dir directory.\n" \
        "\n" \
        "If you have problems with PhotoRec or bug reports, please contact me.\n");
    return 0;
  }
  screen_buffer_reset();
#ifdef HAVE_SETLOCALE
  if(run_setlocale>0)
  {
    const char *locale;
    locale = setlocale (LC_ALL, "");
    if (locale==NULL) {
      locale = setlocale (LC_ALL, NULL);
      log_error("Failed to set locale, using default '%s'.\n", locale);
    } else {
      log_info("Using locale '%s'.\n", locale);
    }
  }
#endif
#ifdef HAVE_NCURSES
  /* ncurses need locale for correct unicode support */
  if(start_ncurses("PhotoRec", argv[0]))
    return 1;
#endif
  create_log=log_open("photorec.log", create_log, 1, "PhotoRec", argc, argv);
  log_info("PhotoRec %s, Data Recovery Utility, %s\nChristophe GRENIER <grenier@cgsecurity.org>\nhttp://www.cgsecurity.org\n", VERSION, TESTDISKDATE);
  log_info("OS: %s\n" , get_os());
  log_info("Compiler: %s\n", get_compiler());
  log_info("ext2fs lib: %s, ntfs lib: %s, ewf lib: %s, libjpeg: ",
      td_ext2fs_version(), td_ntfs_version(), td_ewf_version());
#if defined(HAVE_LIBJPEG)
#if defined(JPEG_LIB_VERSION)
  log_info("%u", JPEG_LIB_VERSION);
#else
  log_info("yes");
#endif
#else
  log_info("none");
#endif
  log_info("\n");
#if defined(__CYGWIN__) || defined(__MINGW32__) || defined(DJGPP)
#else
#ifdef HAVE_GETEUID
  if(geteuid()!=0)
  {
    log_warning("User is not root!\n");
  }
#endif
#endif
#ifdef HAVE_NCURSES
  aff_copy(stdscr);
  wmove(stdscr,5,0);
  wprintw(stdscr, "Please wait...\n");
  wrefresh(stdscr);
#endif
  /* Scan for available device only if no device or image has been supplied in parameter */
  if(list_disk==NULL)
    list_disk=hd_parse(list_disk,verbose,arch,testdisk_mode);
  hd_update_all_geometry(list_disk,0,verbose);
  /* Activate the cache, even if photorec has its own */
  for(element_disk=list_disk;element_disk!=NULL;element_disk=element_disk->next)
    element_disk->disk=new_diskcache(element_disk->disk,testdisk_mode);
  /* save disk parameters to rapport */
  log_info("Hard disk list\n");
  for(element_disk=list_disk;element_disk!=NULL;element_disk=element_disk->next)
  {
    disk_t *disk=element_disk->disk;
    if(disk->model==NULL)
      log_info("%s, sector size=%u\n",
	  disk->description(disk), disk->sector_size);
    else
      log_info("%s, sector size=%u - %s\n",
	  disk->description(disk), disk->sector_size, disk->model);
  }
  log_info("\n");
  file_options_load(list_file_enable);
  use_sudo=do_curses_photorec(verbose, recup_dir, list_disk, list_file_enable, cmd_device, &cmd_run);
#ifdef HAVE_NCURSES
  end_ncurses();
#endif
  delete_list_disk(list_disk);
  log_info("PhotoRec exited normally.\n");
  if(log_close()!=0)
  {
    printf("PhotoRec: Log file corrupted!\n");
  }
  else
  {
    printf("PhotoRec exited normally.\n");
  }
#ifdef SUDO_BIN
  if(use_sudo>0)
    run_sudo(argc, argv);
#endif
  return 0;
}

void file_search_footer(file_recovery_t *file_recovery, const unsigned char*footer, const unsigned int footer_length)
{
  const unsigned int read_size=4096;
  unsigned char*buffer;
  int64_t file_size;
  if(footer_length==0)
    return ;
  buffer=(unsigned char*)MALLOC(read_size+footer_length-1);
  file_size=file_recovery->file_size;
  memset(buffer+read_size,0,footer_length-1);
  do
  {
    int i;
    int taille;
    if(file_size%read_size!=0)
      file_size=file_size-(file_size%read_size);
    else
      file_size-=read_size;
    if(fseek(file_recovery->handle,file_size,SEEK_SET)<0)
      return;
    taille=fread(buffer,1,read_size,file_recovery->handle);
    for(i=taille-1;i>=0;i--)
    {
      if(buffer[i]==footer[0] && memcmp(buffer+i,footer,footer_length)==0)
      {
        file_recovery->file_size=file_size+i+footer_length;
        free(buffer);
        return;
      }
    }
    memcpy(buffer+read_size,buffer,footer_length-1);
  } while(file_size>0);
  file_recovery->file_size=0;
  free(buffer);
}

void file_search_lc_footer(file_recovery_t *file_recovery, const unsigned char*footer, const unsigned int footer_length)
{
  const unsigned int read_size=4096;
  unsigned char*buffer;
  int64_t file_size;
  if(footer_length==0)
    return ;
  buffer=(unsigned char*)MALLOC(read_size+footer_length-1);
  file_size=file_recovery->file_size;
  memset(buffer+read_size,0,footer_length-1);
  do
  {
    int i;
    int taille;
    if(file_size%read_size!=0)
      file_size=file_size-(file_size%read_size);
    else
      file_size-=read_size;
    if(fseek(file_recovery->handle,file_size,SEEK_SET)<0)
      return;
    taille=fread(buffer,1,read_size,file_recovery->handle);
    for(i=0;i<taille;i++)
      buffer[i]=tolower(buffer[i]);
    for(i=taille-1;i>=0;i--)
    {
      if(buffer[i]==footer[0] && memcmp(buffer+i,footer,footer_length)==0)
      {
        file_recovery->file_size=file_size+i+footer_length;
        free(buffer);
        return;
      }
    }
    memcpy(buffer+read_size,buffer,footer_length-1);
  } while(file_size>0);
  file_recovery->file_size=0;
  free(buffer);
}

int data_check_size(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  if(file_recovery->file_size>=file_recovery->calculated_file_size)
  {
    file_recovery->file_size=file_recovery->calculated_file_size;
    return 2;
  }
  return 1;
}

void file_check_size(file_recovery_t *file_recovery)
{
  if(file_recovery->file_size<file_recovery->calculated_file_size)
    file_recovery->file_size=0;
  else
    file_recovery->file_size=file_recovery->calculated_file_size;
}

static void free_list_allocation(alloc_list_t *list_allocation)
{
  struct td_list_head *tmp = NULL;
  struct td_list_head *tmp_next = NULL;
  td_list_for_each_safe(tmp,tmp_next,&list_allocation->list)
  {
    alloc_list_t *allocated_space;
    allocated_space=td_list_entry(tmp, alloc_list_t, list);
    td_list_del(tmp);
    free(allocated_space);
  }
}

/* file_finish() returns
   -1: file not recovered, file_size=0 offset_error!=0
    0: file not recovered
    1: file recovered
 */
int file_finish(file_recovery_t *file_recovery, const char *recup_dir, const int paranoid, unsigned int *file_nbr,
    const unsigned int blocksize, alloc_data_t *list_search_space, alloc_data_t **current_search_space, uint64_t *offset,
    unsigned int *dir_num, const photorec_status_t status, const disk_t *disk)
{
  int file_recovered=0;
#ifdef DEBUG_FILE_FINISH
  log_debug("file_finish start %lu (%lu-%lu)\n", (long unsigned int)((*offset)/blocksize),
      (unsigned long int)((*current_search_space)->start/blocksize),
      (unsigned long int)((*current_search_space)->end/blocksize));
  log_debug("file_recovery->offset_error=%llu\n", (long long unsigned)file_recovery->offset_error);
  log_debug("file_recovery->handle %s NULL\n", (file_recovery->handle!=NULL?"!=":"=="));
  info_list_search_space(list_search_space, NULL, DEFAULT_SECTOR_SIZE, 0, 1);
#endif
  if(file_recovery->handle)
  {
    if(status!=STATUS_EXT2_ON_SAVE_EVERYTHING && status!=STATUS_EXT2_OFF_SAVE_EVERYTHING)
    {
      if(file_recovery->file_stat!=NULL && file_recovery->file_check!=NULL && paranoid>0)
      { /* Check if recovered file is valid */
        file_recovery->file_check(file_recovery);
      }
      /* FIXME: need to adapt read_size to volume size to avoid this */
      if(file_recovery->file_size > disk->disk_size)
        file_recovery->file_size = disk->disk_size;
      if(file_recovery->file_size > disk->disk_real_size)
        file_recovery->file_size = disk->disk_real_size;
      if(file_recovery->file_stat!=NULL && file_recovery->file_size> 0 &&
          file_recovery->file_size < file_recovery->min_filesize)
      { 
        log_info("File too small ( %llu < %llu), reject it\n",
            (long long unsigned) file_recovery->file_size,
            (long long unsigned) file_recovery->min_filesize);
        file_recovery->file_size=0;
        file_recovery->file_size_on_disk=0;
      }
#ifdef HAVE_FTRUNCATE
      fflush(file_recovery->handle);
      if(ftruncate(fileno(file_recovery->handle), file_recovery->file_size)<0)
      {
        log_critical("ftruncate failed.\n");
      }
#endif
    }
    fclose(file_recovery->handle);
    file_recovery->handle=NULL;
    //    log_debug("%s %llu\n",file_recovery->filename,(long long unsigned)file_recovery->file_size);
    if(file_recovery->file_size>0)
    {
      if(file_recovery->time!=0 && file_recovery->time!=(time_t)-1)
	set_date(file_recovery->filename, file_recovery->time, file_recovery->time);
      if((++(*file_nbr))%MAX_FILES_PER_DIR==0)
      {
        *dir_num=photorec_mkdir(recup_dir,*dir_num+1);
      }
      if(status!=STATUS_EXT2_ON_SAVE_EVERYTHING && status!=STATUS_EXT2_OFF_SAVE_EVERYTHING)
        file_recovery->file_stat->recovered++;
    }
    else
    {
      unlink(file_recovery->filename);
    }
  }
  if(file_recovery->file_stat!=NULL)
  {
    list_truncate(&file_recovery->location,file_recovery->file_size);
    if(file_recovery->file_size>0)
      list_space_used(file_recovery, disk->sector_size);
    if(file_recovery->file_size==0)
    {
      /* File hasn't been sucessfully recovered, remember where it begins */
      list_free_add(file_recovery, list_search_space);
      if((*current_search_space)!=list_search_space &&
          !((*current_search_space)->start <= *offset && *offset <= (*current_search_space)->end))
        *current_search_space=td_list_entry((*current_search_space)->list.next, alloc_data_t, list);
    }
    else if(status!=STATUS_EXT2_ON_SAVE_EVERYTHING && status!=STATUS_EXT2_OFF_SAVE_EVERYTHING && status!=STATUS_FIND_OFFSET)
    {
      list_search_space=update_search_space(file_recovery,list_search_space,current_search_space,offset,blocksize);
      file_recovered=1;
    }
    free_list_allocation(&file_recovery->location);
  }
  if(file_recovery->file_size==0 && file_recovery->offset_error!=0)
    file_recovered=-1;
  else
    reset_file_recovery(file_recovery);
#ifdef DEBUG_FILE_FINISH
  log_debug("file_finish end %lu (%lu-%lu)\n\n", (long unsigned int)((*offset)/blocksize),
      (unsigned long int)((*current_search_space)->start/blocksize),
      (unsigned long int)((*current_search_space)->end/blocksize));
  info_list_search_space(list_search_space, NULL, DEFAULT_SECTOR_SIZE, 0, 1);
#endif
  return file_recovered;
}

alloc_data_t *file_finish2(file_recovery_t *file_recovery, const char *recup_dir, const int paranoid, unsigned int *file_nbr,
    const unsigned int blocksize, alloc_data_t *list_search_space,
    unsigned int *dir_num, const photorec_status_t status, const disk_t *disk)
{
  alloc_data_t *datanext=NULL;
#ifdef DEBUG_FILE_FINISH
  log_debug("file_recovery->offset_error=%llu\n", (long long unsigned)file_recovery->offset_error);
  log_debug("file_recovery->handle %s NULL\n", (file_recovery->handle!=NULL?"!=":"=="));
  info_list_search_space(list_search_space, NULL, DEFAULT_SECTOR_SIZE, 0, 1);
#endif
  if(file_recovery->handle)
  {
    if(status!=STATUS_EXT2_ON_SAVE_EVERYTHING && status!=STATUS_EXT2_OFF_SAVE_EVERYTHING)
    {
      if(file_recovery->file_stat!=NULL && file_recovery->file_check!=NULL && paranoid>0)
      { /* Check if recovered file is valid */
        file_recovery->file_check(file_recovery);
      }
      /* FIXME: need to adapt read_size to volume size to avoid this */
      if(file_recovery->file_size > disk->disk_size)
        file_recovery->file_size = disk->disk_size;
      if(file_recovery->file_size > disk->disk_real_size)
        file_recovery->file_size = disk->disk_real_size;

      if(file_recovery->file_stat!=NULL && file_recovery->file_size> 0 &&
          file_recovery->file_size < file_recovery->min_filesize)
      { 
        log_info("File too small ( %llu < %llu), reject it\n",
            (long long unsigned) file_recovery->file_size,
            (long long unsigned) file_recovery->min_filesize);
        file_recovery->file_size=0;
        file_recovery->file_size_on_disk=0;
      }
#ifdef HAVE_FTRUNCATE
      fflush(file_recovery->handle);
      if(ftruncate(fileno(file_recovery->handle), file_recovery->file_size)<0)
      {
        log_critical("ftruncate failed.\n");
      }
#endif
    }
    fclose(file_recovery->handle);
    file_recovery->handle=NULL;
    //    log_debug("%s %llu\n",file_recovery->filename,(long long unsigned)file_recovery->file_size);
    if(file_recovery->file_size>0)
    {
      if(file_recovery->time!=0 && file_recovery->time!=(time_t)-1)
	set_date(file_recovery->filename, file_recovery->time, file_recovery->time);
      if((++(*file_nbr))%MAX_FILES_PER_DIR==0)
      {
        *dir_num=photorec_mkdir(recup_dir,*dir_num+1);
      }
      if(status!=STATUS_EXT2_ON_SAVE_EVERYTHING && status!=STATUS_EXT2_OFF_SAVE_EVERYTHING)
        file_recovery->file_stat->recovered++;
    }
    else
    {
      unlink(file_recovery->filename);
    }
  }
  if(file_recovery->file_stat!=NULL)
  {
    if(file_recovery->file_size==0)
    {
      /* File hasn't been sucessfully recovered */
    }
    else
    {
      datanext=file_truncate(list_search_space, file_recovery, disk->sector_size, blocksize);
    }
    free_list_allocation(&file_recovery->location);
  }
  if(file_recovery->file_size==0 && file_recovery->offset_error!=0)
  {
  }
  else
    reset_file_recovery(file_recovery);
#ifdef DEBUG_FILE_FINISH
  info_list_search_space(list_search_space, NULL, DEFAULT_SECTOR_SIZE, 0, 1);
#endif
  return datanext;
}

void info_list_search_space(const alloc_data_t *list_search_space, const alloc_data_t *current_search_space, const unsigned int sector_size, const int keep_corrupted_file, const int verbose)
{
  struct td_list_head *search_walker = NULL;
  unsigned long int nbr_headers=0;
  uint64_t sectors_with_unknown_data=0;
  td_list_for_each(search_walker,&list_search_space->list)
  {
    alloc_data_t *tmp;
    tmp=td_list_entry(search_walker, alloc_data_t, list);
    if(tmp->file_stat!=NULL)
    {
      nbr_headers++;
      tmp->file_stat->not_recovered++;
    }
    sectors_with_unknown_data+=(tmp->end-tmp->start+sector_size-1)/sector_size;
    if(verbose>0)
    {
      if(tmp==current_search_space)
        log_info("* ");
      log_info("%lu-%lu: %s\n",(long unsigned)(tmp->start/sector_size),
          (long unsigned)(tmp->end/sector_size),
          (tmp->file_stat!=NULL && tmp->file_stat->file_hint!=NULL?
           (tmp->file_stat->file_hint->extension?
            tmp->file_stat->file_hint->extension:""):
           "(null)"));
    }
  }
  log_info("%llu sectors contains unknown data, %lu invalid files found %s.\n",
      (long long unsigned)sectors_with_unknown_data, (long unsigned)nbr_headers,
      (keep_corrupted_file>0?"but saved":"and rejected"));
}


