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

#if defined(DISABLED_FOR_FRAMAC)
#undef HAVE_FTRUNCATE
#undef HAVE_LIBEXT2FS
#undef HAVE_LIBNTFS
#undef HAVE_LIBNTFS3G
#undef ENABLE_DFXML
#endif

#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>	/* unlink, ftruncate */
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <errno.h>
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#if defined(__FRAMAC__)
#include "__fc_builtin.h"
#endif
#include <limits.h>
#include "types.h"
#include "common.h"
#include "fnctdsk.h"
#include "dir.h"
#include "filegen.h"
#include "photorec.h"
#include "exfatp.h"
#include "ext2p.h"
#include "fatp.h"
#include "ntfsp.h"
#include "log.h"
#include "setdate.h"
#include "dfxml.h"

/* #define DEBUG_FILE_FINISH */
/* #define DEBUG_UPDATE_SEARCH_SPACE */
/* #define DEBUG_FREE */
uint64_t gpfh_nbr=0;

static void update_search_space_aux(alloc_data_t *list_search_space, uint64_t start, uint64_t end, alloc_data_t **new_current_search_space, uint64_t *offset);

/*@
  @ requires valid_file_recovery(file_recovery);
  @ requires valid_list_search_space(list_search_space);
  @ requires \separated(file_recovery, list_search_space);
  @*/
static void file_block_truncate_zero(const file_recovery_t *file_recovery, alloc_data_t *list_search_space);

/*@
  @ requires valid_file_recovery(file_recovery);
  @ requires valid_list_search_space(list_search_space);
  @ requires \separated(file_recovery, list_search_space);
  @*/
static int file_block_truncate(const file_recovery_t *file_recovery, alloc_data_t *list_search_space, const unsigned int blocksize);

void file_block_log(const file_recovery_t *file_recovery, const unsigned int sector_size)
{
  struct td_list_head *tmp;
  if(file_recovery->filename[0]=='\0')
    return;
#ifndef DISABLED_FOR_FRAMAC
  log_info("%s\t",file_recovery->filename);
  td_list_for_each(tmp, &file_recovery->location.list)
  {
    const alloc_list_t *element=td_list_entry_const(tmp, const alloc_list_t, list);
    if(element->data>0)
      log_info(" %lu-%lu", (unsigned long)(element->start/sector_size), (unsigned long)(element->end/sector_size));
    else
      log_info(" (%lu-%lu)", (unsigned long)(element->start/sector_size), (unsigned long)(element->end/sector_size));
  }
  log_info("\n");
#endif
}

void del_search_space(alloc_data_t *list_search_space, const uint64_t start, const uint64_t end)
{
  update_search_space_aux(list_search_space, start, end, NULL, NULL);
}

/*@
  @ requires \valid(list_search_space);
  @ requires new_current_search_space == \null || (\valid(new_current_search_space) && \valid(*new_current_search_space));
  @ requires offset == \null || \valid(offset);
  @ decreases end-start;
  @*/
static void update_search_space_aux(alloc_data_t *list_search_space, const uint64_t start, const uint64_t end, alloc_data_t **new_current_search_space, uint64_t *offset)
{
  struct td_list_head *search_walker = NULL;
#ifdef DEBUG_UPDATE_SEARCH_SPACE
  log_trace("update_search_space_aux offset=%llu remove [%llu-%llu]\n",
      (long long unsigned)(offset==NULL?0:((*offset)/512)),
      (unsigned long long)(start/512),
      (unsigned long long)(end/512));
#endif
  if(start > end)
    return ;
  /*@
    @ loop invariant \valid(list_search_space);
    @ loop invariant new_current_search_space == \null || (\valid(new_current_search_space) && \valid(*new_current_search_space));
    @ loop invariant offset == \null || \valid(offset);
    @*/
  td_list_for_each_prev(search_walker, &list_search_space->list)
  {
    alloc_data_t *current_search_space;
    current_search_space=td_list_entry(search_walker, alloc_data_t, list);
    /*@ assert \valid(current_search_space); */
#ifdef DEBUG_UPDATE_SEARCH_SPACE
    log_trace("update_search_space_aux offset=%llu remove [%llu-%llu] in [%llu-%llu]\n",
	(long long unsigned)(offset==NULL?0:((*offset)/512)),
        (unsigned long long)(start/512),
        (unsigned long long)(end/512),
        (unsigned long long)(current_search_space->start/512),
        (unsigned long long)(current_search_space->end/512));
#endif
    if(current_search_space->start==start)
    {
      const uint64_t pivot=current_search_space->end+1;
      if(end < current_search_space->end)
      { /* current_search_space->start==start end<current_search_space->end */
        if(offset!=NULL && new_current_search_space!=NULL &&
            current_search_space->start<=*offset && *offset<=end)
        {
	  /*@ assert \valid(new_current_search_space); */
          *new_current_search_space=current_search_space;
          *offset=end+1;
        }
        current_search_space->start=end+1;
        current_search_space->file_stat=NULL;
        return ;
      }
      /* current_search_space->start==start current_search_space->end<=end */
      if(offset!=NULL && new_current_search_space!=NULL &&
          current_search_space->start<=*offset && *offset<=current_search_space->end)
      {
        *new_current_search_space=td_list_next_entry(current_search_space, list);
	/*@ assert \valid(*new_current_search_space); */
        *offset=(*new_current_search_space)->start;
      }
      td_list_del(search_walker);
      free(current_search_space);
      update_search_space_aux(list_search_space, pivot, end, new_current_search_space, offset);
      return ;
    }
    if(current_search_space->end==end)
    {
      const uint64_t pivot=current_search_space->start-1;
#ifdef DEBUG_UPDATE_SEARCH_SPACE
      log_trace("current_search_space->end==end\n");
#endif
      if(current_search_space->start < start)
      { /* current_search_space->start<start current_search_space->end==end */
        if(offset!=NULL && new_current_search_space!=NULL &&
            start<=*offset && *offset<=current_search_space->end)
        {
	  *new_current_search_space=td_list_next_entry(current_search_space, list);
	  /*@ assert \valid(*new_current_search_space); */
          *offset=(*new_current_search_space)->start;
        }
        current_search_space->end=start-1;
        return ;
      }
      /* start<=current_search_space->start current_search_space->end==end */
      if(offset!=NULL && new_current_search_space!=NULL &&
          current_search_space->start<=*offset && *offset<=current_search_space->end)
      {
	*new_current_search_space=td_list_next_entry(current_search_space, list);
	/*@ assert \valid(*new_current_search_space); */
        *offset=(*new_current_search_space)->start;
      }
      td_list_del(search_walker);
      free(current_search_space);
      update_search_space_aux(list_search_space, start, pivot, new_current_search_space, offset);
      return ;
    }
    if(start < current_search_space->start && current_search_space->start <= end)
    {
      const uint64_t pivot=current_search_space->start;
      update_search_space_aux(list_search_space, start, pivot-1,  new_current_search_space, offset);
      update_search_space_aux(list_search_space, pivot, end,      new_current_search_space, offset);
      return ;
    }
    if(start <= current_search_space->end && current_search_space->end < end)
    {
      const uint64_t pivot=current_search_space->end;
      update_search_space_aux(list_search_space, start, pivot, new_current_search_space, offset);
      update_search_space_aux(list_search_space, pivot+1, end, new_current_search_space, offset);
      return ;
    }
    if(current_search_space->start < start && end < current_search_space->end)
    {
      alloc_data_t *new_free_space;
      new_free_space=(alloc_data_t*)MALLOC(sizeof(*new_free_space));
      /*@ assert \valid(new_free_space); */
      new_free_space->start=start;
      new_free_space->end=current_search_space->end;
      new_free_space->file_stat=NULL;
      new_free_space->data=1;
      current_search_space->end=start-1;
      td_list_add(&new_free_space->list,search_walker);
      if(offset!=NULL && new_current_search_space!=NULL &&
          new_free_space->start<=*offset && *offset<=new_free_space->end)
      {
        *new_current_search_space=new_free_space;
      }
      update_search_space_aux(list_search_space, start, end, new_current_search_space, offset);
      return ;
    }
  }
}

void init_search_space(alloc_data_t *list_search_space, const disk_t *disk_car, const partition_t *partition)
{
  alloc_data_t *new_sp;
  new_sp=(alloc_data_t*)MALLOC(sizeof(*new_sp));
  /*@ assert \valid(new_sp); */
  new_sp->start=partition->part_offset;
  new_sp->end=partition->part_offset+partition->part_size-1;
  if(new_sp->end > disk_car->disk_size-1)
    new_sp->end = disk_car->disk_size-1;
  if(new_sp->end > disk_car->disk_real_size-1)
    new_sp->end = disk_car->disk_real_size-1;
  new_sp->file_stat=NULL;
  new_sp->data=1;
  new_sp->list.prev=&new_sp->list;
  new_sp->list.next=&new_sp->list;
  td_list_add_tail(&new_sp->list, &list_search_space->list);
}

void free_list_search_space(alloc_data_t *list_search_space)
{
  struct td_list_head *search_walker = NULL;
  struct td_list_head *search_walker_next = NULL;
  /*@
    @ loop invariant \valid(search_walker);
    @ loop invariant \valid(search_walker_next);
    @ loop invariant valid_list_search_space(list_search_space);
    @*/
  td_list_for_each_safe(search_walker,search_walker_next,&list_search_space->list)
  {
    alloc_data_t *current_search_space;
    current_search_space=td_list_entry(search_walker, alloc_data_t, list);
    /*@ assert \valid(current_search_space); */
    td_list_del(search_walker);
    free(current_search_space);
    /*@ assert \valid(search_walker); */
  }
}

/** 
 * @param recup_dir - base name of output directory
 * @param initial_dir_num - first number to try appending.
 * @return the number that was appended.
 */

unsigned int photorec_mkdir(const char *recup_dir, const unsigned int initial_dir_num)
{
  unsigned int dir_num=initial_dir_num;
#ifdef DJGPP
  int i=0;
  /*@ assert valid_read_string(recup_dir); */
#endif
  /*@
    @ loop invariant \separated(recup_dir, &errno);
    @ loop assigns errno, dir_num;
    @*/
  while(1)
  {
    char working_recup_dir[2048];
    snprintf(working_recup_dir, sizeof(working_recup_dir)-1, "%s.%u", recup_dir, dir_num);
    working_recup_dir[sizeof(working_recup_dir)-1]='\0';
    /*@ assert valid_read_string(&working_recup_dir[0]); */
#ifdef HAVE_MKDIR
#ifdef __MINGW32__
    if(mkdir(working_recup_dir)==0 || errno!=EEXIST)
      return dir_num;
#else
    if(mkdir(working_recup_dir, 0775)==0 || errno!=EEXIST)
      return dir_num;
#endif
#else
#warning "You need a mkdir function!"
#endif
    if(dir_num == UINT_MAX)
      dir_num=0;
    else
      dir_num++;
#ifdef DJGPP
  /* Avoid endless loop in Dos version of Photorec after 999 directories if working with short name */
    i++;
    if(i==1000)
    {
      dir_num=initial_dir_num;
      return dir_num;
    }
#endif
  }
}

/*@
  @ requires \separated(list_search_space, current_search_space, offset, &gpfh_nbr);
  @ assigns  gpfh_nbr, *current_search_space, *offset;
  @ */
int get_prev_file_header(const alloc_data_t *list_search_space, alloc_data_t **current_search_space, uint64_t *offset)
{
  int nbr;
  /*@ assert \valid(current_search_space); */
  alloc_data_t *file_space=*current_search_space;
  uint64_t size=0;
  gpfh_nbr++;
  /* Search backward the first fragment of a file not successfully recovered
   * Limit the search to 3 fragments or 200MB */
  /*@
    @ loop invariant \valid(current_search_space);
    @ loop invariant \valid(offset);
    @ loop invariant \valid_read(file_space);
    @ loop assigns nbr, file_space, *current_search_space, *offset;
    @ loop variant 3 - nbr;
    @*/
  for(nbr=0; nbr<3 && size < (uint64_t)200*1024*1024; nbr++)
  {
    file_space=td_list_prev_entry(file_space, list);
    /*@ assert \valid(file_space); */
    if(file_space==list_search_space)
      return -1;
    /*@ assert file_space->end > file_space->start; */
    size+=file_space->end - file_space->start + 1;
    if(file_space->file_stat!=NULL)
    {
      *current_search_space=file_space;
      *offset=file_space->start;
      /*@ assert *current_search_space!=list_search_space && *offset == (*current_search_space)->start; */
      return 0;
    }
  }
  return -1;
}

void forget(const alloc_data_t *list_search_space, alloc_data_t *current_search_space)
{
  struct td_list_head *search_walker = NULL;
  struct td_list_head *prev= NULL;
  int nbr=0;
  if(current_search_space==list_search_space)
    return ;
  /*@
    @ loop invariant \valid(search_walker);
    @*/
  for(search_walker=&current_search_space->list;
      search_walker!=&list_search_space->list;
      search_walker=prev)
  {
    prev=search_walker->prev;
    if(nbr>10000)
    {
      alloc_data_t *tmp;
      tmp=td_list_entry(search_walker, alloc_data_t, list);
      /*@ assert \valid(tmp); */
      td_list_del(&tmp->list);
      free(tmp);
    }
    else
      nbr++;
  }
}

unsigned int remove_used_space(disk_t *disk_car, const partition_t *partition, alloc_data_t *list_search_space)
{
#ifndef DISABLED_FOR_FRAMAC
  if( partition->upart_type==UP_FAT12 ||
      partition->upart_type==UP_FAT16 || 
      partition->upart_type==UP_FAT32)
    return fat_remove_used_space(disk_car, partition, list_search_space);
  else if(partition->upart_type==UP_EXFAT)
    return exfat_remove_used_space(disk_car, partition, list_search_space);
#if defined(HAVE_LIBNTFS) || defined(HAVE_LIBNTFS3G)
  else if(partition->upart_type==UP_NTFS)
    return ntfs_remove_used_space(disk_car, partition, list_search_space);
#endif
#if defined(HAVE_LIBEXT2FS)
  else if(partition->upart_type==UP_EXT2 || partition->upart_type==UP_EXT3 || partition->upart_type==UP_EXT4)
    return ext2_remove_used_space(disk_car, partition, list_search_space);
#endif
#endif
  return 0;
}

void update_stats(file_stat_t *file_stats, alloc_data_t *list_search_space)
{
#ifndef DISABLED_FOR_FRAMAC
  struct td_list_head *search_walker = NULL;
  int i;
  /* Reset */
  /*@
    @ loop assigns i, file_stats[i].not_recovered;
    @*/
  for(i=0;file_stats[i].file_hint!=NULL;i++)
  {
    /*@ assert \valid(file_stats[i]); */
    file_stats[i].not_recovered=0;
  }
  /* Update */
  td_list_for_each(search_walker, &list_search_space->list)
  {
    alloc_data_t *current_search_space;
    current_search_space=td_list_entry(search_walker, alloc_data_t, list);
    /*@ assert \valid(current_search_space); */
    if(current_search_space->file_stat!=NULL)
    {
      current_search_space->file_stat->not_recovered++;
    }
  }
#endif
}

void write_stats_log(const file_stat_t *file_stats)
{
#ifndef DISABLED_FOR_FRAMAC
  unsigned int file_nbr=0;
  unsigned int i;
  unsigned int nbr;
  file_stat_t *new_file_stats;
  /*@
    @ loop assigns i;
    @*/
  for(i=0;file_stats[i].file_hint!=NULL;i++);
  if(i==0)
    return ;
  nbr=i;
  new_file_stats=(file_stat_t*)MALLOC(nbr*sizeof(file_stat_t));
  /*@ assert \valid(new_file_stats); */
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
  if(file_nbr!=1)
  {
    log_info("Total: %u files found\n\n",file_nbr);
  }
  else
  {
    log_info("Total: %u file found\n\n",file_nbr);
  }
#endif
}

int sorfile_stat_ts(const void *p1, const void *p2)
{
  const file_stat_t *f1=(const file_stat_t *)p1;
  const file_stat_t *f2=(const file_stat_t *)p2;
  /*@ assert \valid_read(f1); */
  /*@ assert \valid_read(f2); */
  /* bigest to lowest */
  if(f1->recovered < f2->recovered)
    return 1;
  if(f1->recovered > f2->recovered)
    return -1;
  return 0;
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

unsigned int find_blocksize(const alloc_data_t *list_search_space, const unsigned int default_blocksize, uint64_t *offset)
{
  /* NTFS cluster size can be 2 MB since Windows 10 Creators edition */
  // FIXME unsigned int blocksize=2*1024*1024;
  unsigned int blocksize=128*512;
  int run_again;
  *offset=0;
  if(td_list_empty(&list_search_space->list))
    return default_blocksize;
  {
    const alloc_data_t *tmp=td_list_first_entry(&list_search_space->list, alloc_data_t, list);
    /*@ assert \valid_read(tmp); */
    *offset=tmp->start % blocksize;
  }
  /*@
    @ loop invariant blocksize > 0;
    @ loop invariant \valid(offset);
    @ loop invariant valid_list_search_space(list_search_space);
    @*/
  do
  {
    const struct td_list_head *search_walker = NULL;
    run_again=0;
    /*@
      @ loop invariant blocksize > 0;
      @ loop invariant \valid(offset);
      @ loop invariant valid_list_search_space(list_search_space);
      @ loop invariant \valid(search_walker);
      @*/
    td_list_for_each(search_walker, &list_search_space->list)
    {
      const alloc_data_t *tmp=td_list_entry_const(search_walker, const alloc_data_t, list);
      /*@ assert \valid_read(tmp); */
      if(tmp->file_stat!=NULL)
      {
	if(tmp->start%blocksize!=*offset && blocksize>default_blocksize)
	{
	  blocksize=blocksize>>1;
	  *offset=tmp->start%blocksize;
	  run_again=1;
	}
      }
    }
  } while(run_again>0);
  return blocksize;
}

void update_blocksize(const unsigned int blocksize, alloc_data_t *list_search_space, const uint64_t offset)
{
#ifndef DISABLED_FOR_FRAMAC
  struct td_list_head *search_walker;
  struct td_list_head *search_walker_prev = NULL;
  log_info("blocksize=%u, offset=%u\n", blocksize, (unsigned int)(offset%blocksize));
  /* Align end of last range (round up) */
  search_walker=list_search_space->list.prev;
  {
    alloc_data_t *current_search_space;
    current_search_space=td_list_entry(search_walker, alloc_data_t, list);
    /*@ assert \valid(current_search_space); */
    current_search_space->end=(current_search_space->end+1-offset%blocksize+blocksize-1)/blocksize*blocksize+offset%blocksize-1;
  }
  /* Align start of each range */
  td_list_for_each_prev_safe(search_walker,search_walker_prev,&list_search_space->list)
  {
    alloc_data_t *current_search_space=td_list_entry(search_walker, alloc_data_t, list);
    /*@ assert \valid_read(current_search_space); */
    /*@ assert current_search_space->start >= offset; */
    const uint64_t aligned_start=(current_search_space->start-offset%blocksize+blocksize-1)/blocksize*blocksize+offset%blocksize;
    if(current_search_space->start!=aligned_start)
    {
      alloc_data_t *prev_search_space=td_list_entry(search_walker_prev, alloc_data_t, list);
      /*@ assert \valid_read(prev_search_space); */
      if(prev_search_space->end + 1 == current_search_space->start)
      {
	/* merge with previous block */
	prev_search_space->end = current_search_space->end;
	td_list_del(search_walker);
	free(current_search_space);
      }
      else
      {
	current_search_space->start=aligned_start;
	current_search_space->file_stat=NULL;
	if(current_search_space->start>=current_search_space->end)
	{
	  /* block too small - delete it */
	  td_list_del(search_walker);
	  free(current_search_space);
	}
      }
    }
  }
  /* Align end of each range (truncate) */
  td_list_for_each_prev_safe(search_walker, search_walker_prev, &list_search_space->list)
  {
    alloc_data_t *current_search_space=td_list_entry(search_walker, alloc_data_t, list);
    /*@ assert \valid_read(current_search_space); */
    current_search_space->end=(current_search_space->end+1-offset%blocksize)/blocksize*blocksize+offset%blocksize-1;
    if(current_search_space->start>=current_search_space->end)
    {
      /* block too small - delete it */
      td_list_del(search_walker);
      free(current_search_space);
    }
  }
#endif
}

uint64_t free_list_allocation_end=0;

/*@
  @ requires \valid(list_allocation);
  @*/
static void file_block_free(alloc_list_t *list_allocation)
{
#ifndef DISABLED_FOR_FRAMAC
  struct td_list_head *tmp = NULL;
  struct td_list_head *tmp_next = NULL;
  td_list_for_each_safe(tmp,tmp_next,&list_allocation->list)
  {
    alloc_list_t *allocated_space;
    allocated_space=td_list_entry(tmp, alloc_list_t, list);
    /*@ assert \valid(allocated_space); */
    header_ignored_cond_reset(allocated_space->start, allocated_space->end);
    free_list_allocation_end=allocated_space->end;
    td_list_del(tmp);
    free(allocated_space);
  }
#endif
}

/*@
  @ requires \valid(file_recovery);
  @ requires \valid(params);
  @ requires valid_ph_param(params);
  @ requires \valid(file_recovery->handle);
  @ requires valid_file_recovery(file_recovery);
  @ requires \separated(file_recovery, params, file_recovery->handle);
  @ decreases 0;
  @*/
static void file_finish_aux(file_recovery_t *file_recovery, struct ph_param *params, const int paranoid)
{
#ifndef DISABLED_FOR_FRAMAC
  /*@ assert valid_file_recovery(file_recovery); */
  /*@ assert file_recovery->file_check == \null || \valid_function(file_recovery->file_check); */
  if(params->status!=STATUS_EXT2_ON_SAVE_EVERYTHING &&
      params->status!=STATUS_EXT2_OFF_SAVE_EVERYTHING &&
      file_recovery->file_stat!=NULL && file_recovery->file_check!=NULL && paranoid>0)
    { /* Check if recovered file is valid */
      /*@ assert file_recovery->file_check != \null; */
      /*@ assert \valid_function(file_recovery->file_check); */
      file_recovery->file_check(file_recovery);
    }
  /* FIXME: need to adapt read_size to volume size to avoid this */
  if(file_recovery->file_size > params->disk->disk_size)
    file_recovery->file_size = params->disk->disk_size;
  if(file_recovery->file_size > params->disk->disk_real_size)
    file_recovery->file_size = params->disk->disk_real_size;
  if(file_recovery->file_stat!=NULL && file_recovery->file_size> 0 &&
      file_recovery->file_size < file_recovery->min_filesize)
  { 
#ifndef DISABLED_FOR_FRAMAC
    log_info("%s File too small ( %llu < %llu), reject it\n",
	file_recovery->filename,
	(long long unsigned) file_recovery->file_size,
	(long long unsigned) file_recovery->min_filesize);
#endif
    file_recovery->file_size=0;
  }
  if(file_recovery->file_size==0)
  {
    if(paranoid==2)
      return ;
    fclose(file_recovery->handle);
    file_recovery->handle=NULL;
    /* File is zero-length; erase it */
    /*@ assert valid_read_string((const char *)file_recovery->filename); */
    unlink(file_recovery->filename);
    return;
  }
#if defined(HAVE_FTRUNCATE)
  fflush(file_recovery->handle);
  if(ftruncate(fileno(file_recovery->handle), file_recovery->file_size)<0)
  {
    log_critical("ftruncate failed.\n");
  }
#endif
  fclose(file_recovery->handle);
  file_recovery->handle=NULL;
  if(file_recovery->time!=0 && file_recovery->time!=(time_t)-1)
    set_date(file_recovery->filename, file_recovery->time, file_recovery->time);
  /*@ assert valid_file_recovery(file_recovery); */
  if(file_recovery->file_rename!=NULL)
  {
    /*@ assert file_recovery->file_rename != \null; */
    /*@ assert \valid_function(file_recovery->file_rename); */
    file_recovery->file_rename(file_recovery);
  }
  if((++params->file_nbr)%MAX_FILES_PER_DIR==0)
  {
    params->dir_num=photorec_mkdir(params->recup_dir, params->dir_num+1);
  }
  if(params->status!=STATUS_EXT2_ON_SAVE_EVERYTHING &&
      params->status!=STATUS_EXT2_OFF_SAVE_EVERYTHING &&
      file_recovery->file_stat!=NULL)
    file_recovery->file_stat->recovered++;
#endif
}

/** file_finish_bf()
    @param file_recovery - 
    @param struct ph_param *params
    @param alloc_data_t *list_search_space

    @returns:
   -1: file not recovered, file_size=0 offset_error!=0
    0: file not recovered
    1: file recovered
 */

int file_finish_bf(file_recovery_t *file_recovery, struct ph_param *params,
    alloc_data_t *list_search_space)
{
  if(file_recovery->file_stat==NULL)
    return 0;
  if(file_recovery->handle)
    file_finish_aux(file_recovery, params, 2);
  if(file_recovery->file_size==0)
  {
    if(file_recovery->offset_error!=0)
      return -1;
    file_block_truncate_zero(file_recovery, list_search_space);
    if(file_recovery->handle!=NULL)
    {
      fclose(file_recovery->handle);
      unlink(file_recovery->filename);
    }
    reset_file_recovery(file_recovery);
    return 0;
  }
  file_block_truncate(file_recovery, list_search_space, params->blocksize);
  file_block_log(file_recovery, params->disk->sector_size);
#ifdef ENABLE_DFXML
  xml_log_file_recovered(file_recovery);
#endif
  file_block_free(&file_recovery->location);
  return 1;
}

void file_recovery_aborted(file_recovery_t *file_recovery, struct ph_param *params, alloc_data_t *list_search_space)
{
  if(file_recovery->file_stat==NULL)
    return ;
  params->offset=file_recovery->location.start;
  if(file_recovery->handle)
  {
    fclose(file_recovery->handle);
    file_recovery->handle=NULL;
    /*@ assert valid_file_recovery(file_recovery); */
    /* File is zero-length; erase it */
    unlink(file_recovery->filename);
  }
  file_block_truncate_zero(file_recovery, list_search_space);
  reset_file_recovery(file_recovery);
}

pfstatus_t file_finish2(file_recovery_t *file_recovery, struct ph_param *params, const int paranoid, alloc_data_t *list_search_space)
{
  int file_truncated;
  if(file_recovery->file_stat==NULL)
    return PFSTATUS_BAD;
  if(file_recovery->handle)
    file_finish_aux(file_recovery, params, (paranoid==0?0:1));
  if(file_recovery->file_size==0)
  {
    file_block_truncate_zero(file_recovery, list_search_space);
    reset_file_recovery(file_recovery);
    return PFSTATUS_BAD;
  }
  file_truncated=file_block_truncate(file_recovery, list_search_space, params->blocksize);
  file_block_log(file_recovery, params->disk->sector_size);
#ifdef ENABLE_DFXML
  xml_log_file_recovered(file_recovery);
#endif
  file_block_free(&file_recovery->location);
  reset_file_recovery(file_recovery);
  return (file_truncated>0?PFSTATUS_OK_TRUNCATED:PFSTATUS_OK);
}

void info_list_search_space(const alloc_data_t *list_search_space, const alloc_data_t *current_search_space, const unsigned int sector_size, const int keep_corrupted_file, const int verbose)
{
#ifndef DISABLED_FOR_FRAMAC
  struct td_list_head *search_walker = NULL;
  unsigned long int nbr_headers=0;
  uint64_t sectors_with_unknown_data=0;
  td_list_for_each(search_walker,&list_search_space->list)
  {
    alloc_data_t *tmp;
    tmp=td_list_entry(search_walker, alloc_data_t, list);
    /*@ assert \valid(tmp); */
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
  log_info("%llu sectors contain unknown data, %lu invalid files found %s.\n",
      (long long unsigned)sectors_with_unknown_data, (long unsigned)nbr_headers,
      (keep_corrupted_file>0?"but saved":"and rejected"));
#endif
}

void free_search_space(alloc_data_t *list_search_space)
{
  struct td_list_head *search_walker = NULL;
  struct td_list_head *search_walker_next = NULL;
  td_list_for_each_safe(search_walker,search_walker_next,&list_search_space->list)
  {
    alloc_data_t *current_search_space;
    current_search_space=td_list_entry(search_walker, alloc_data_t, list);
    /*@ assert \valid(current_search_space); */
    td_list_del(search_walker);
    free(current_search_space);
  }
}

void set_filename(file_recovery_t *file_recovery, struct ph_param *params)
{
  const int broken=(params->status==STATUS_EXT2_ON_SAVE_EVERYTHING ||
      params->status==STATUS_EXT2_OFF_SAVE_EVERYTHING);
  if(file_recovery->extension==NULL || file_recovery->extension[0]=='\0')
  {
    snprintf(file_recovery->filename,sizeof(file_recovery->filename)-1,
	"%s.%u/%c%07lu", params->recup_dir,
	params->dir_num, (broken?'b':'f'),
	(unsigned long int)((file_recovery->location.start - params->partition->part_offset)/ params->disk->sector_size));
  }
  else
  {
    snprintf(file_recovery->filename,sizeof(file_recovery->filename)-1,
	"%s.%u/%c%07lu.%s", params->recup_dir,
	params->dir_num, (broken?'b':'f'),
	(unsigned long int)((file_recovery->location.start - params->partition->part_offset) / params->disk->sector_size), file_recovery->extension);
  }
}

/*@
  @ requires \valid(new_current_search_space);
  @ requires \valid(list_search_space);
  @ requires \separated(new_current_search_space, list_search_space);
  @ assigns  *new_current_search_space;
  @*/
static void set_search_start_aux(alloc_data_t **new_current_search_space, alloc_data_t *list_search_space, const uint64_t offset)
{
  struct td_list_head *search_walker = NULL;
  /*@
    @ loop invariant \valid(list_search_space);
    @ loop invariant \valid(search_walker);
    @ loop assigns search_walker, *new_current_search_space;
    @*/
  td_list_for_each(search_walker, &list_search_space->list)
  {
    alloc_data_t *current_search_space;
    current_search_space=td_list_entry(search_walker, alloc_data_t, list);
    /*@ assert \valid(current_search_space); */
    if(current_search_space->start<=offset && offset<= current_search_space->end)
    {
      *new_current_search_space=current_search_space;
      return;
    }
  }
  /* not found */
  search_walker=list_search_space->list.next;
  *new_current_search_space=td_list_entry(search_walker, alloc_data_t, list);
}

uint64_t set_search_start(struct ph_param *params, alloc_data_t **new_current_search_space, alloc_data_t *list_search_space)
{
  /*@ assert \valid(new_current_search_space); */
  uint64_t offset=(*new_current_search_space)->start;
  if(params->offset!=PH_INVALID_OFFSET)
  {
    offset=params->offset;
    set_search_start_aux(new_current_search_space, list_search_space, offset);
  }
  else if(params->cmd_run!=NULL && params->cmd_run[0]!='\0')
  {
    offset=0;
    skip_comma_in_command(&params->cmd_run);
    /*@
      @ loop invariant valid_disk(params->disk);
      @ loop invariant \valid(params);
      @ loop invariant valid_read_string(params->cmd_run);
      @ loop assigns offset, params->cmd_run;
      @*/
    while(*params->cmd_run >= '0' && *params->cmd_run <= '9')
    {
      offset=offset * 10 + (*params->cmd_run - '0');
      params->cmd_run++;
    }
    offset*=params->disk->sector_size;
    set_search_start_aux(new_current_search_space, list_search_space, offset);
  }
  return offset;
}

/*@
  @ requires \valid(params);
  @ requires valid_ph_param(params);
  @ requires params->disk->sector_size > 0;
  @ requires valid_read_string(params->recup_dir);
  @ assigns params->file_nbr;
  @ assigns params->status;
  @ assigns params->real_start_time;
  @ assigns params->dir_num;
  @ assigns params->offset;
  @ assigns params->blocksize;
  @ ensures  valid_ph_param(params);
  @ ensures  params->file_nbr == 0;
  @ ensures  params->status == STATUS_FIND_OFFSET;
  @ ensures  params->dir_num == 1;
  @ ensures  params->offset == PH_INVALID_OFFSET;
  @ ensures  params->blocksize > 0;
  @ ensures  valid_read_string(params->recup_dir);
  @*/
static void params_reset_aux(struct ph_param *params)
{
  params->file_nbr=0;
  params->status=STATUS_FIND_OFFSET;
  params->real_start_time=time(NULL);
  params->dir_num=1;
  params->offset=PH_INVALID_OFFSET;
  if(params->blocksize==0)
    params->blocksize=params->disk->sector_size;
  /*@ assert params->blocksize > 0; */
}

void params_reset(struct ph_param *params, const struct ph_options *options)
{
  /*@ assert valid_ph_param(params); */
  params->file_stats=init_file_stats(options->list_file_format);
  /*@ assert valid_ph_param(params); */
  params_reset_aux(params);
}

const char *status_to_name(const photorec_status_t status)
{
  switch(status)
  {
    case STATUS_UNFORMAT:
      return "STATUS_UNFORMAT";
    case STATUS_FIND_OFFSET:
      return "STATUS_FIND_OFFSET";
    case STATUS_EXT2_ON:
      return "STATUS_EXT2_ON";
    case STATUS_EXT2_ON_BF:			
      return "STATUS_EXT2_ON_BF";
    case STATUS_EXT2_OFF:
      return "STATUS_EXT2_OFF";
    case STATUS_EXT2_OFF_BF:
      return "STATUS_EXT2_OFF_BF";
    case STATUS_EXT2_ON_SAVE_EVERYTHING:
      return "STATUS_EXT2_ON_SAVE_EVERYTHING";
    case STATUS_EXT2_OFF_SAVE_EVERYTHING:
      return "STATUS_EXT2_OFF_SAVE_EVERYTHING";
    case STATUS_QUIT :
    default:
      return "STATUS_QUIT";
  }
}

void status_inc(struct ph_param *params, const struct ph_options *options)
{
  params->offset=PH_INVALID_OFFSET;
  switch(params->status)
  {
    case STATUS_UNFORMAT:
      params->status=STATUS_FIND_OFFSET;
      break;
    case STATUS_FIND_OFFSET:
      params->status=(options->mode_ext2>0?STATUS_EXT2_ON:STATUS_EXT2_OFF);
      params->file_nbr=0;
      break;
    case STATUS_EXT2_ON:
      if(options->paranoid>1)
	params->status=STATUS_EXT2_ON_BF;
      else if(options->paranoid==1 && options->keep_corrupted_file>0)
	params->status=STATUS_EXT2_ON_SAVE_EVERYTHING;
      else
	params->status=STATUS_QUIT;
      break;
    case STATUS_EXT2_ON_BF:
      if(options->keep_corrupted_file>0)
	params->status=STATUS_EXT2_ON_SAVE_EVERYTHING;
      else
	params->status=STATUS_QUIT;
      break;
    case STATUS_EXT2_OFF:
      if(options->paranoid>1)
	params->status=STATUS_EXT2_OFF_BF;
      else if(options->paranoid==1 && options->keep_corrupted_file>0)
	params->status=STATUS_EXT2_OFF_SAVE_EVERYTHING;
      else
	params->status=STATUS_QUIT;
      break;
    case STATUS_EXT2_OFF_BF:
      if(options->keep_corrupted_file>0)
	params->status=STATUS_EXT2_OFF_SAVE_EVERYTHING;
      else
	params->status=STATUS_QUIT;
      break;
    default:
      params->status=STATUS_QUIT;
      break;
  }
}

list_part_t *init_list_part(disk_t *disk, const struct ph_options *options)
{
  int insert_error=0;
  list_part_t *list_part;
  partition_t *partition_wd;
  list_part=disk->arch->read_part(disk, (options!=NULL?options->verbose:0), 0);
  /*@ assert valid_list_part(list_part); */
  partition_wd=new_whole_disk(disk);
  list_part=insert_new_partition(list_part, partition_wd, 0, &insert_error);
  if(insert_error>0)
  {
    free(partition_wd);
  }
  /*@ assert valid_list_part(list_part); */
  return list_part;
}

/* file_block_remove_from_sp: remove block from list_search_space, update offset and new_current_search_space in consequence */
/*@
  @ requires \valid(tmp);
  @ requires \valid(new_current_search_space);
  @ requires \valid(offset);
  @ requires \separated(tmp, new_current_search_space, offset);
  @*/
static inline void file_block_remove_from_sp_aux(alloc_data_t *tmp, alloc_data_t **new_current_search_space, uint64_t *offset, const unsigned int blocksize)
{
#ifndef DISABLED_FOR_FRAMAC
  if(tmp->start == *offset)
  {
    tmp->start+=blocksize;
    *offset += blocksize;
    tmp->file_stat=NULL;
    if(tmp->start <= tmp->end)
      return ;
    *new_current_search_space=td_list_next_entry(tmp, list);
    /*@ assert \valid(*new_current_search_space); */
    *offset=(*new_current_search_space)->start;
    td_list_del(&tmp->list);
    free(tmp);
    return ;
  }
  if(*offset + blocksize == tmp->end + 1)
  {
    tmp->end-=blocksize;
    *new_current_search_space=td_list_next_entry(tmp, list);
    *offset=(*new_current_search_space)->start;
    return ;
  }
  {
    alloc_data_t *new_sp;
    new_sp=(alloc_data_t*)MALLOC(sizeof(*new_sp));
    /*@ assert \valid(new_sp); */
    new_sp->start=*offset + blocksize;
    new_sp->end=tmp->end;
    new_sp->file_stat=NULL;
    new_sp->data=tmp->data;
    new_sp->list.prev=&new_sp->list;
    new_sp->list.next=&new_sp->list;
    tmp->end=*offset - 1;
    td_list_add(&new_sp->list, &tmp->list);
    *new_current_search_space=new_sp;
    *offset += blocksize;
  }
#endif
}

/*@
  @ requires \valid(list_search_space);
  @ requires \valid(new_current_search_space);
  @ requires \valid(offset);
  @ requires \separated(list_search_space, new_current_search_space, offset);
  @*/
static inline void file_block_remove_from_sp(alloc_data_t *list_search_space, alloc_data_t **new_current_search_space, uint64_t *offset, const unsigned int blocksize)
{
#ifndef DISABLED_FOR_FRAMAC
  struct td_list_head *search_walker = &(*new_current_search_space)->list;
  if(search_walker!=NULL)
  {
    alloc_data_t *tmp;
    tmp=td_list_entry(search_walker, alloc_data_t, list);
    if(tmp->start <= *offset && *offset + blocksize <= tmp->end + 1)
    {
      file_block_remove_from_sp_aux(tmp, new_current_search_space, offset, blocksize);
      return;
    }
  }
  td_list_for_each(search_walker, &list_search_space->list)
  {
    alloc_data_t *tmp;
    tmp=td_list_entry(search_walker, alloc_data_t, list);
    if(tmp->start <= *offset && *offset + blocksize <= tmp->end + 1)
    {
      file_block_remove_from_sp_aux(tmp, new_current_search_space, offset, blocksize);
      return ;
    }
  }
  log_critical("file_block_remove_from_sp(list_search_space, alloc_data_t **new_current_search_space, uint64_t *offset, const unsigned int blocksize) failed\n");
  log_flush();
  exit(1);
#endif
}

/*@
  @ requires \valid(list);
  @ requires \valid(list->list.prev);
  @ requires offset + blocksize < 0xffffffffffffffff;
  @*/
static inline void file_block_add_to_file(alloc_list_t *list, const uint64_t offset, const uint64_t blocksize, const unsigned int data)
{
#ifndef DISABLED_FOR_FRAMAC
  if(!td_list_empty(&list->list))
  {
    alloc_list_t *prev=td_list_last_entry(&list->list, alloc_list_t, list);
    if(prev->end+1==offset && prev->data==data)
    {
      prev->end=offset+blocksize-1;
      return ;
    }
  }
  {
    alloc_list_t *new_list=(alloc_list_t *)MALLOC(sizeof(*new_list));
    /*@ assert \valid(new_list); */
    new_list->start=offset;
    new_list->end=offset+blocksize-1;
    new_list->data=data;
    td_list_add_tail(&new_list->list, &list->list);
  }
#endif
}

void file_block_append(file_recovery_t *file_recovery, alloc_data_t *list_search_space, alloc_data_t **new_current_search_space, uint64_t *offset, const unsigned int blocksize, const unsigned int data)
{
  file_block_add_to_file(&file_recovery->location, *offset, blocksize, data);
  file_block_remove_from_sp(list_search_space, new_current_search_space, offset, blocksize);
}

/*@
  @ requires \valid(list_search_space);
  @*/
static void file_block_truncate_aux(const uint64_t start, const uint64_t end, alloc_data_t *list_search_space)
{
  struct td_list_head *search_walker = NULL;
  if(start >= end)
    return ;
#ifndef DISABLED_FOR_FRAMAC
  td_list_for_each(search_walker, &list_search_space->list)
  {
    alloc_data_t *tmp;
    tmp=td_list_entry(search_walker, alloc_data_t, list);
    /*@ assert \valid(tmp); */
    if(tmp->start == end + 1 && tmp->file_stat==NULL)
    {
      tmp->start=start;
      return;
    }
    if(tmp->end + 1 == start)
    {
      tmp->end=end;
      return;
    }
    if(end < tmp->start)
    {
      alloc_data_t *new_sp;
      new_sp=(alloc_data_t*)MALLOC(sizeof(*new_sp));
      /*@ assert \valid(new_sp); */
      new_sp->start=start;
      new_sp->end=end;
      new_sp->file_stat=NULL;
      new_sp->data=1;
      new_sp->list.prev=&new_sp->list;
      new_sp->list.next=&new_sp->list;
      td_list_add(&new_sp->list, tmp->list.prev);
      return;
    }
  }
  {
    alloc_data_t *new_sp;
    new_sp=(alloc_data_t*)MALLOC(sizeof(*new_sp));
    /*@ assert \valid(new_sp); */
    new_sp->start=start;
    new_sp->end=end;
    new_sp->file_stat=NULL;
    new_sp->data=1;
    new_sp->list.prev=&new_sp->list;
    new_sp->list.next=&new_sp->list;
    td_list_add_tail(&new_sp->list, &list_search_space->list);
  }
#endif
}

/*@
  @ requires \valid(list_search_space);
  @ requires \valid(file_stat);
  @ requires \separated(list_search_space, file_stat);
  @*/
static void file_block_truncate_zero_aux(const uint64_t start, const uint64_t end, alloc_data_t *list_search_space, file_stat_t *file_stat)
{
  struct td_list_head *search_walker = NULL;
  if(start >= end)
    return ;
#ifndef DISABLED_FOR_FRAMAC
  td_list_for_each(search_walker, &list_search_space->list)
  {
    alloc_data_t *tmp;
    tmp=td_list_entry(search_walker, alloc_data_t, list);
    /*@ assert \valid(tmp); */
    if(tmp->start == end + 1 && tmp->file_stat==NULL)
    {
      tmp->start=start;
      tmp->file_stat=file_stat;
      return;
    }
    if(end < tmp->start)
    {
      alloc_data_t *new_sp;
      new_sp=(alloc_data_t*)MALLOC(sizeof(*new_sp));
      /*@ assert \valid(new_sp); */
      new_sp->start=start;
      new_sp->end=end;
      new_sp->file_stat=file_stat;
      new_sp->data=1;
      new_sp->list.prev=&new_sp->list;
      new_sp->list.next=&new_sp->list;
      td_list_add(&new_sp->list, tmp->list.prev);
      return;
    }
  }
  {
    alloc_data_t *new_sp;
    new_sp=(alloc_data_t*)MALLOC(sizeof(*new_sp));
    /*@ assert \valid(new_sp); */
    new_sp->start=start;
    new_sp->end=end;
    new_sp->file_stat=file_stat;
    new_sp->data=1;
    new_sp->list.prev=&new_sp->list;
    new_sp->list.next=&new_sp->list;
    td_list_add_tail(&new_sp->list, &list_search_space->list);
  }
#endif
}

static void file_block_truncate_zero(const file_recovery_t *file_recovery, alloc_data_t *list_search_space)
{
#ifndef DISABLED_FOR_FRAMAC
  struct td_list_head *tmp;
  struct td_list_head *next;
  int first=1;
  td_list_for_each_safe(tmp, next, &file_recovery->location.list)
  {
    alloc_list_t *element=td_list_entry(tmp, alloc_list_t, list);
    if(first)
    {
      file_block_truncate_zero_aux(element->start, element->end, list_search_space, file_recovery->file_stat);
      first=0;
    }
    else
      file_block_truncate_aux(element->start, element->end, list_search_space);
    td_list_del(tmp);
    free(element);
  }
#endif
}

static int file_block_truncate(const file_recovery_t *file_recovery, alloc_data_t *list_search_space, const unsigned int blocksize)
{
  struct td_list_head *tmp;
  struct td_list_head *next;
  uint64_t size=0;
  int file_truncated=0;
#ifndef DISABLED_FOR_FRAMAC
  td_list_for_each_safe(tmp, next, &file_recovery->location.list)
  {
    alloc_list_t *element=td_list_entry(tmp, alloc_list_t, list);
    if(size >= file_recovery->file_size)
    {
      file_block_truncate_aux(element->start, element->end, list_search_space);
      td_list_del(tmp);
      free(element);
      file_truncated=1;
    }
    else if(element->data>0)
    {
      if(size + element->end - element->start + 1 > file_recovery->file_size)
      {
	const uint64_t diff=(file_recovery->file_size - size + blocksize - 1) / blocksize * blocksize;
	file_block_truncate_aux(element->start + diff, element->end, list_search_space);
	element->end-=element->end - element->start + 1 - diff;
	size=file_recovery->file_size;
      }
      else
	size+=(element->end-element->start+1);
    }
  }
#endif
  return file_truncated;
}

/*@
  @ requires valid_file_recovery(file_recovery);
  @ terminates \true;
  @ assigns  \nothing;
  @*/
static uint64_t file_offset_end(const file_recovery_t *file_recovery)
{
  /*@ assert valid_file_recovery(file_recovery); */
  const struct td_list_head *tmp=file_recovery->location.list.prev;
  const alloc_list_t *element=td_list_entry_const(tmp, const alloc_list_t, list);
  /*@ assert \valid_read(element); */
  return element->end;
}

/*@
  @ requires \valid_read(file_recovery);
  @ requires \valid(list_search_space);
  @ requires \valid(new_current_search_space);
  @ requires \valid(offset);
  @ requires \separated(file_recovery, list_search_space, new_current_search_space, offset);
  @ assigns  *new_current_search_space, *offset;
  @*/
static void file_block_move(const file_recovery_t *file_recovery, alloc_data_t *list_search_space, alloc_data_t **new_current_search_space, uint64_t *offset)
{
#ifndef DISABLED_FOR_FRAMAC
  const uint64_t end=file_offset_end(file_recovery);
  struct td_list_head *tmp;
  /*@ loop assigns tmp; */
  td_list_for_each(tmp, &list_search_space->list)
  {
    alloc_data_t *element=td_list_entry(tmp, alloc_data_t, list);
    if(element->start > end)
    {
      *new_current_search_space=element;
      *offset=element->start;
      return;
    }
  }
  *new_current_search_space=list_search_space;
#endif
}

void file_block_truncate_and_move(file_recovery_t *file_recovery, alloc_data_t *list_search_space, const unsigned int blocksize,  alloc_data_t **new_current_search_space, uint64_t *offset, unsigned char *buffer)
{
#ifndef DISABLED_FOR_FRAMAC
  file_block_truncate(file_recovery, list_search_space, blocksize);
  file_block_move(file_recovery, list_search_space, new_current_search_space, offset);
  if(file_recovery->offset_ok > file_recovery->file_size)
    file_recovery->offset_ok=file_recovery->file_size;
  if(file_recovery->offset_error > file_recovery->file_size)
    file_recovery->offset_error=0;
  file_recovery->calculated_file_size=0;
  if(file_recovery->data_check!=NULL)
  {
    uint64_t i;
    unsigned char *block_buffer;
    block_buffer=&buffer[blocksize];
    if(my_fseek(file_recovery->handle, 0, SEEK_SET) < 0)
      return ;
    for(i=0; i< file_recovery->file_size; i+= blocksize)
    {
      if(fread(block_buffer, blocksize, 1, file_recovery->handle) != 1)
	return ;
      file_recovery->data_check(buffer, 2*blocksize, file_recovery);
      if(file_recovery->data_check==NULL)
	return ;
      memcpy(buffer, block_buffer, blocksize);
    }
  }
  else
  {
    if(my_fseek(file_recovery->handle, file_recovery->file_size, SEEK_SET) < 0)
      return ;
  }
#endif
}
