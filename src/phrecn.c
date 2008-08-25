/*

    File: phrecn.c

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
#include <ctype.h>      /* tolower */
#include "types.h"
#include "common.h"
#include "intrf.h"
#ifdef HAVE_NCURSES
#include "intrfn.h"
#else
#include <stdio.h>
#endif
#include <errno.h>
#include "fnctdsk.h"
#include "dir.h"
#include "fat_dir.h"
#include "list.h"
#include "chgtype.h"
#include "lang.h"
#include "filegen.h"
#include "photorec.h"
#include "sessionp.h"
#include "phrecn.h"
#include "partauto.h"
#include "log.h"
#include "hdaccess.h"
#include "file_tar.h"
#include "phcfg.h"
#include "ext2grp.h"
#include "pdisksel.h"
#include "pblocksize.h"
#include "pfree_whole.h"

/* #define DEBUG */
/* #define DEBUG_GET_NEXT_SECTOR */
/* #define DEBUG_BF */
#define READ_SIZE 1024*512

extern const file_hint_t file_hint_tar;
extern const file_hint_t file_hint_dir;
extern file_check_list_t file_check_list;

#ifdef HAVE_NCURSES
static int photorec_progressbar(WINDOW *window, const unsigned int pass, const photorec_status_t status, const uint64_t offset, disk_t *disk_car, partition_t *partition, const unsigned int file_nbr, const time_t elapsed_time, const file_stat_t *file_stats);
static void recovery_finished(const unsigned int file_nbr, const char *recup_dir, const int ind_stop, char **current_cmd);
#endif

static int photorec_bf(disk_t *disk_car, partition_t *partition, const int verbose, const int paranoid, const char *recup_dir, const int interface, file_stat_t *file_stats, unsigned int *file_nbr, unsigned int *blocksize, alloc_data_t *list_search_space, const time_t real_start_time, unsigned int *dir_num, const photorec_status_t status, const unsigned int pass);
static int photorec_aux(disk_t *disk_car, partition_t *partition, const int verbose, const int paranoid, const char *recup_dir, const int interface, file_stat_t *file_stats, unsigned int *file_nbr, const unsigned int blocksize, alloc_data_t *list_search_space, const time_t real_start_time, unsigned int *dir_num, const photorec_status_t status, const unsigned int pass, const unsigned int lowmem);
static int photorec_bf_aux(disk_t *disk_car, partition_t *partition, const int paranoid, const char *recup_dir, const int interface, file_stat_t *file_stats, unsigned int *file_nbr, file_recovery_t *file_recovery, unsigned int blocksize, alloc_data_t *list_search_space, alloc_data_t *current_search_space, const time_t real_start_time, unsigned int *dir_num, const photorec_status_t status);
static int interface_cannot_create_file(void);

/* ==================== INLINE FUNCTIONS ========================= */
/* Check if the block looks like an indirect/double-indirect block */
static inline int ind_block(const unsigned char *buffer, const unsigned int blocksize)
{
  const uint32_t *p32=(const uint32_t *)buffer;
  unsigned int i;
  unsigned int diff=1;	/* IND: Indirect block */
  if(le32(p32[0])==0)
    return 0;
  if(le32(p32[1])==le32(p32[0])+blocksize/4+1)
    diff=blocksize/4+1;	/* DIND: Double Indirect block */
  for(i=0;i<blocksize/4-1 && le32(p32[i+1])!=0;i++)
  {
    if(le32(p32[i+1])!=le32(p32[i])+diff)
    {
      return 0;
    }
  }
  i++;
  for(;i<blocksize/4 && le32(p32[i])==0;i++);
  if(i<blocksize/4)
  {
    return 0;
  }
  return 1;	/* Ok: ind_block points to non-fragmented block */
}

static
#ifndef DEBUG_GET_NEXT_SECTOR
inline
#endif
void get_next_header(alloc_data_t *list_search_space, alloc_data_t **current_search_space, uint64_t *offset)
{
#ifdef DEBUG_GET_NEXT_SECTOR
  log_trace(" get_next_header %llu (%llu-%llu)\n",
      (unsigned long long)((*offset)/512),
      (unsigned long long)((*current_search_space)->start/512),
      (unsigned long long)((*current_search_space)->end)/512);
#endif
  if((*current_search_space) != list_search_space)
    *current_search_space=td_list_entry((*current_search_space)->list.next, alloc_data_t, list);
  *offset=(*current_search_space)->start;
}

static
#ifndef DEBUG_GET_NEXT_SECTOR
inline
#endif
void get_next_sector(alloc_data_t *list_search_space, alloc_data_t **current_search_space, uint64_t *offset, const unsigned int blocksize)
{
#ifdef DEBUG_GET_NEXT_SECTOR
  log_debug(" get_next_sector %llu (%llu-%llu)\n",
      (unsigned long long)((*offset)/512),
      (unsigned long long)((*current_search_space)->start/512),
      (unsigned long long)((*current_search_space)->end)/512);
#endif
  if((*current_search_space) == list_search_space)
  {
    return ;
  }
#ifdef DEBUG_GET_NEXT_SECTOR
  if(! ((*current_search_space)->start <= *offset && (*offset)<=(*current_search_space)->end))
  {
    log_critical("BUG: get_next_sector stop everything %llu (%llu-%llu)\n",
        (unsigned long long)((*offset)/512),
        (unsigned long long)((*current_search_space)->start/512),
        (unsigned long long)((*current_search_space)->end/512));
    log_flush();
    bug();
    exit(1);
  }
#endif
  if((*offset)+blocksize <= (*current_search_space)->end)
    *offset+=blocksize;
  else
    get_next_header(list_search_space, current_search_space, offset);
}

static inline void file_recovery_cpy(file_recovery_t *dst, file_recovery_t *src)
{
  memcpy(dst, src, sizeof(*dst));
#if 0
  if(td_list_empty(&src->location.list))
  {
    dst->location.list.prev=&dst->location.list;
    dst->location.list.next=&dst->location.list;
  }
  else
  {
    src->location.list.prev=&src->location.list;
    src->location.list.next=&src->location.list;
    dst->location.list.prev->next=&dst->location.list;
    dst->location.list.next->prev=&dst->location.list;
  }
#else
  dst->location.list.prev=&dst->location.list;
  dst->location.list.next=&dst->location.list;
#endif
}

static inline void list_append_block(alloc_list_t *list, const uint64_t offset, const uint64_t blocksize, const unsigned int data)
{
  if(!td_list_empty(&list->list))
  {
    alloc_list_t *prev=td_list_entry(list->list.prev, alloc_list_t, list);
    if(prev->end+1==offset && prev->data==data)
    {
      prev->end=offset+blocksize-1;
      return ;
    }
  }
  {
    alloc_list_t *new_list=(alloc_list_t *)MALLOC(sizeof(*new_list));
    new_list->start=offset;
    new_list->end=offset+blocksize-1;
    new_list->data=data;
    td_list_add_tail(&new_list->list, &list->list);
  }
}

/* ==================== INLINE FUNCTIONS ========================= */

#ifdef HAVE_NCURSES
static void photorec_info(WINDOW *window, const file_stat_t *file_stats)
{
  unsigned int i;
  unsigned int nbr;
  unsigned int others=0;
  file_stat_t *new_file_stats;
  for(i=0;file_stats[i].file_hint!=NULL;i++);
  nbr=i;
  if(nbr==0)
    return ;
  new_file_stats=(file_stat_t*)MALLOC(nbr*sizeof(file_stat_t));
  memcpy(new_file_stats, file_stats, nbr*sizeof(file_stat_t));
  qsort(new_file_stats, nbr, sizeof(file_stat_t), sorfile_stat_ts);
  for(i=0;i<nbr && new_file_stats[i].recovered>0;i++)
  {
    if(i<10)
    {
      wmove(window,11+i,0);
      wclrtoeol(window);
      wprintw(window, "%s: %u recovered\n",
          (new_file_stats[i].file_hint->extension!=NULL?
           new_file_stats[i].file_hint->extension:""),
          new_file_stats[i].recovered);
    }
    else
      others+=new_file_stats[i].recovered;
  }
  if(others>0)
  {
    wmove(window,11+10,0);
    wclrtoeol(window);
    wprintw(window, "others: %u recovered\n", others);
  }
  free(new_file_stats);
}

static int photorec_progressbar(WINDOW *window, const unsigned int pass, const photorec_status_t status, const uint64_t offset, disk_t *disk_car, partition_t *partition, const unsigned int file_nbr, const time_t elapsed_time, const file_stat_t *file_stats)
{
  wmove(window,9,0);
  wclrtoeol(window);
  if(status==STATUS_EXT2_ON_BF || status==STATUS_EXT2_OFF_BF)
  {
    wprintw(window,"Bruteforce %10lu sectors remaining (test %u), %u files found\n",
        (unsigned long)((offset-partition->part_offset)/disk_car->sector_size), pass, file_nbr);
  }
  else
  {
    wprintw(window, "Pass %u - ", pass);
    if(status==STATUS_FIND_OFFSET)
      wprintw(window,"Reading sector %10lu/%lu, %u/10 headers found\n",
          (unsigned long)((offset-partition->part_offset)/disk_car->sector_size),
          (unsigned long)(partition->part_size/disk_car->sector_size), file_nbr);
    else
      wprintw(window,"Reading sector %10lu/%lu, %u files found\n",
          (unsigned long)((offset-partition->part_offset)/disk_car->sector_size),
          (unsigned long)(partition->part_size/disk_car->sector_size), file_nbr);
  }
  wmove(window,10,0);
  wclrtoeol(window);
  wprintw(window,"Elapsed time %uh%02um%02us",
      (unsigned)(elapsed_time/60/60),
      (unsigned)(elapsed_time/60%60),
      (unsigned)(elapsed_time%60));
  if(offset-partition->part_offset!=0 && (status!=STATUS_EXT2_ON_BF && status!=STATUS_EXT2_OFF_BF))
  {
    wprintw(window," - Estimated time for achievement %uh%02um%02u\n",
        (unsigned)((partition->part_offset+partition->part_size-1-offset)*elapsed_time/(offset-partition->part_offset)/3600),
        (unsigned)(((partition->part_offset+partition->part_size-1-offset)*elapsed_time/(offset-partition->part_offset)/60)%60),
        (unsigned)((partition->part_offset+partition->part_size-1-offset)*elapsed_time/(offset-partition->part_offset))%60);
  }
  photorec_info(window, file_stats);
  wrefresh(window);
  return check_enter_key_or_s(window);
}

void aff_copy(WINDOW *window)
{
  wclear(window);
  keypad(window, TRUE); /* Need it to get arrow key */
  wmove(window,0,0);
  wprintw(window, "PhotoRec %s, Data Recovery Utility, %s\n",VERSION,TESTDISKDATE);
  wmove(window,1,0);
  wprintw(window, "Christophe GRENIER <grenier@cgsecurity.org>");
  wmove(window,2,0);
  wprintw(window, "http://www.cgsecurity.org");
}
#endif

static void set_filename(file_recovery_t *file_recovery, const char *recup_dir, const unsigned int dir_num, const disk_t *disk, const partition_t *partition, const int broken)
{
  if(file_recovery->extension==NULL || file_recovery->extension[0]=='\0')
  {
    snprintf(file_recovery->filename,sizeof(file_recovery->filename)-1,"%s.%u/%c%u",recup_dir,
	dir_num,(broken?'b':'f'),
	(unsigned int)((file_recovery->location.start-partition->part_offset)/disk->sector_size));
  }
  else
  {
    snprintf(file_recovery->filename,sizeof(file_recovery->filename)-1,"%s.%u/%c%u.%s",recup_dir,
	dir_num, (broken?'b':'f'),
	(unsigned int)((file_recovery->location.start-partition->part_offset)/disk->sector_size), file_recovery->extension);
  }
}

static int photorec_bf(disk_t *disk_car, partition_t *partition, const int verbose, const int paranoid, const char *recup_dir, const int interface, file_stat_t *file_stats, unsigned int *file_nbr, unsigned int *blocksize, alloc_data_t *list_search_space, const time_t real_start_time, unsigned int *dir_num, const photorec_status_t status, const unsigned int pass)
{
  struct td_list_head *search_walker = NULL;
  struct td_list_head *n= NULL;
  unsigned char *buffer_start;
  unsigned int read_size;
  unsigned int buffer_size;
  int ind_stop=0;
  int pass2=pass;
  read_size=((*blocksize)>8192?(*blocksize):8192);
  buffer_size=(*blocksize)+READ_SIZE;
  buffer_start=(unsigned char *)MALLOC(buffer_size);
  for(search_walker=list_search_space->list.prev, n=search_walker->prev;
      search_walker!=&list_search_space->list && ind_stop==0;
      search_walker=n,n=search_walker->prev)
  {
    alloc_data_t *current_search_space;
    unsigned char *buffer;
    unsigned char *buffer_olddata;
    uint64_t offset;
    int need_to_check_file;
    file_recovery_t file_recovery;
    current_search_space=td_list_entry(search_walker, alloc_data_t, list);
    offset=current_search_space->start;
    buffer_olddata=buffer_start;
    buffer=buffer_olddata+(*blocksize);
    reset_file_recovery(&file_recovery);
    memset(buffer_olddata,0,(*blocksize));
    disk_car->read(disk_car,READ_SIZE, buffer, offset);
#ifdef DEBUG_BF
    info_list_search_space(list_search_space, current_search_space, disk_car->sector_size, 0, verbose);
#endif
    log_flush();

    do
    {
      uint64_t old_offset=offset;
      need_to_check_file=0;
      if(offset==current_search_space->start)
      {
        file_recovery_t file_recovery_new;
	struct td_list_head *tmpl;
        file_recovery_new.file_stat=NULL;
	td_list_for_each(tmpl, &file_check_list.list)
	{
	  struct td_list_head *tmp;
	  const file_check_list_t *pos=td_list_entry(tmpl, file_check_list_t, list);
	  td_list_for_each(tmp, &pos->file_checks[pos->has_value==0?0:buffer[pos->offset]].list)
	  {
	    const file_check_t *file_check=td_list_entry(tmp, file_check_t, list);
	    if((file_check->length==0 || memcmp(buffer + file_check->offset, file_check->value, file_check->length)==0) &&
		file_check->header_check(buffer, read_size, 0, &file_recovery, &file_recovery_new)!=0)
	    {
	      file_recovery_new.file_stat=file_check->file_stat;
	      break;
	    }
	  }
	  if(file_recovery_new.file_stat!=NULL)
	    break;
	}
        if(file_recovery_new.file_stat!=NULL)
        {
	  file_recovery_new.location.start=offset;
          if(verbose>0)
          {
            log_info("%s header found at sector %lu\n",
                ((file_recovery_new.extension!=NULL && file_recovery_new.extension[0]!='\0')?
                 file_recovery_new.extension:file_recovery_new.file_stat->file_hint->description),
                (unsigned long)((offset-partition->part_offset)/disk_car->sector_size));
          }
          if(file_recovery.file_stat==NULL)
          { /* Header found => file found */
            file_recovery_cpy(&file_recovery, &file_recovery_new);
          }
          else if(file_recovery_new.file_stat->file_hint!=NULL)
          {
            if(verbose>0)
              log_verbose("New file found => stop the recovery of current file\n");
            need_to_check_file=1;
          }
        }
        else if(file_recovery.file_stat==NULL)
          need_to_check_file=1;	/* No header found => no file => stop */
      }
      if(file_recovery.file_stat!=NULL && file_recovery.handle==NULL)
      { /* Create new file */
	set_filename(&file_recovery, recup_dir, *dir_num, disk_car, partition,
	    (status==STATUS_EXT2_ON_SAVE_EVERYTHING||status==STATUS_EXT2_OFF_SAVE_EVERYTHING));
        if(file_recovery.file_stat->file_hint->recover==1)
        {
          if(!(file_recovery.handle=fopen(file_recovery.filename,"w+b")))
          { 
            log_critical("Cannot create file %s: %s\n", file_recovery.filename, strerror(errno));
            ind_stop=2;
          }
        }
      }
      if(file_recovery.handle!=NULL)
      {
        if((status==STATUS_EXT2_ON || status==STATUS_EXT2_ON_SAVE_EVERYTHING) &&
            file_recovery.file_stat!=NULL && file_recovery.file_size_on_disk>=12*(*blocksize) &&
            ind_block(buffer,*blocksize)!=0)
        {
          list_append_block(&file_recovery.location,offset,*blocksize,0);
          file_recovery.file_size_on_disk+=*blocksize;
          if(verbose>1)
          {
            log_verbose("Skipping sector %10lu/%lu\n",(unsigned long)((offset-partition->part_offset)/disk_car->sector_size),(unsigned long)(partition->part_size/disk_car->sector_size));
          }
          memcpy(buffer,buffer_olddata,(*blocksize));
        }
        else
        {
          if(file_recovery.handle!=NULL)
          {
            if(fwrite(buffer,*blocksize,1,file_recovery.handle)<1)
            { 
              log_critical("Cannot write to file %s\n", file_recovery.filename);
              ind_stop=3;
            }
          }
          if(file_recovery.file_stat!=NULL)
          {
            int res=1;
            list_append_block(&file_recovery.location,offset,*blocksize,1);
            if(file_recovery.data_check!=NULL)
              res=file_recovery.data_check(buffer_olddata,2*(*blocksize),&file_recovery);
            file_recovery.file_size+=*blocksize;
            file_recovery.file_size_on_disk+=*blocksize;
            if(res==2)
            { /* EOF found */
              need_to_check_file=1;
            }
          }
        }
        if(file_recovery.file_stat!=NULL && file_recovery.file_stat->file_hint->max_filesize>0 && file_recovery.file_size>=file_recovery.file_stat->file_hint->max_filesize)
        {
          log_verbose("File should not be bigger than %llu, stop adding data\n",
              (long long unsigned)file_recovery.file_stat->file_hint->max_filesize);
          need_to_check_file=1;
        }
      }
      get_next_sector(list_search_space, &current_search_space, &offset, *blocksize);
      if(current_search_space==list_search_space)
        need_to_check_file=1;
      if(need_to_check_file==0)
      {
        buffer_olddata+=*blocksize;
        buffer+=*blocksize;
        if(old_offset+*blocksize!=offset || buffer+read_size>buffer_start+buffer_size)
        {
          memcpy(buffer_start,buffer_olddata,*blocksize);
          buffer_olddata=buffer_start;
          buffer=buffer_olddata+*blocksize;
          if(verbose>1)
          {
            log_verbose("Reading sector %10lu/%lu\n",
                (unsigned long)((offset-partition->part_offset)/disk_car->sector_size),
                (unsigned long)((partition->part_size-1)/disk_car->sector_size));
          }
          disk_car->read(disk_car,READ_SIZE, buffer, offset);
        }
      }
    } while(need_to_check_file==0);
    if(need_to_check_file==1)
    {
      if(file_finish(&file_recovery,recup_dir,paranoid,file_nbr, *blocksize, list_search_space, &current_search_space, &offset, dir_num,status,disk_car->sector_size,disk_car)<0)
      { /* BF */
        current_search_space=td_list_entry(search_walker, alloc_data_t, list);
        ind_stop=photorec_bf_aux(disk_car, partition, paranoid, recup_dir, interface, file_stats, file_nbr, &file_recovery, *blocksize, list_search_space, current_search_space, real_start_time, dir_num, status);
        pass2++;
      }
    }
  }
#ifdef HAVE_NCURSES
  photorec_info(stdscr, file_stats);
#endif
  return ind_stop;
}

static int photorec_bf_aux(disk_t *disk_car, partition_t *partition, const int paranoid, const char *recup_dir, const int interface, file_stat_t *file_stats, unsigned int *file_nbr, file_recovery_t *file_recovery, unsigned int blocksize, alloc_data_t *list_search_space, alloc_data_t *start_search_space, const time_t real_start_time, unsigned int *dir_num, const photorec_status_t status)
{
  uint64_t offset;
  uint64_t original_offset_error, file_offset;
  long int save_seek;
  unsigned char *block_buffer;
  int blocs_to_skip,i;
  int ind_stop;
  int testbf=0;
  time_t previous_time=0;
  alloc_data_t *current_search_space;
  //Init. of the brute force
#ifdef DEBUG_BF
  log_trace("photorec_bf_aux location.start=%lu\n",
      (long unsigned)(file_recovery->location.start/disk_car->sector_size));
#endif
  original_offset_error=file_recovery->offset_error;

  file_recovery->handle=fopen(file_recovery->filename, "w+b");
  if(file_recovery->handle==NULL)
  {
    log_critical("Brute Force : Cannot create file %s: %s\n", file_recovery->filename, strerror(errno));
    return 2;
  }
  block_buffer=(unsigned char *) MALLOC(sizeof(unsigned char)*blocksize);

  current_search_space=start_search_space;
  /* We have offset==start_search_space->start==file_recovery->location.start */
  offset=start_search_space->start;;

  // Writing the file until the error location
#ifdef DEBUG_BF
  log_debug("Writing the file until the error location %llu\n", (long long unsigned)original_offset_error);
#endif
  //FIXME: Handle ext2/ext3, handle fwrite return value
  file_recovery->file_size=0;
  for(i=0; i<(original_offset_error+blocksize-1)/blocksize; i++)
  {
    disk_car->read(disk_car,blocksize, block_buffer, offset);
    fwrite(block_buffer, blocksize, 1, file_recovery->handle);
    list_append_block(&file_recovery->location, offset, blocksize, 1);
    file_recovery->file_size+=blocksize;
    get_next_sector(list_search_space, &current_search_space, &offset, blocksize);
  }
#ifdef DEBUG_BF
  log_trace("BF Amorce ");
  list_space_used(file_recovery, blocksize);
  log_trace("\n");
#endif
  //Main Loop
  do
  {
    ind_stop=0;
    for(file_offset=(original_offset_error+blocksize-1)/blocksize*blocksize;
        file_offset >= blocksize && (original_offset_error+blocksize-1)/blocksize*blocksize<file_offset+8*512 && ind_stop==0;
        file_offset -= blocksize)
    {
      alloc_data_t *extractblock_search_space;
      uint64_t extrablock_offset;
      /* Set extractblock_search_space & extrablock_offset to the begining of the potential extra block */
#ifdef DEBUG_BF
      log_debug("Set extractblock_search_space & extrablock_offset to the begining of the potential extra block\n");
#endif
      /* Get the last block added to the file */
      extrablock_offset=0;
      if(!td_list_empty(&file_recovery->location.list))
      {
	const alloc_list_t *element=td_list_entry(file_recovery->location.list.prev, alloc_list_t, list);
	extrablock_offset=element->end/blocksize*blocksize;
      }
      /* Get the corresponding search_place */
      extractblock_search_space=td_list_entry(list_search_space->list.next, alloc_data_t, list);
      while(extractblock_search_space != list_search_space &&
          !(extractblock_search_space->start <= extrablock_offset &&
            extrablock_offset <= extractblock_search_space->end))
        extractblock_search_space=td_list_entry(extractblock_search_space->list.next, alloc_data_t, list);
      /* Update extractblock_search_space & extrablock_offset */
      get_next_sector(list_search_space, &extractblock_search_space, &extrablock_offset, blocksize);
      /* */
      for(blocs_to_skip=1; blocs_to_skip<=250 && ind_stop==0; blocs_to_skip++)
      {
        offset=extrablock_offset;
        current_search_space=extractblock_search_space;
        testbf++;
        if(interface!=0)
        {
          time_t current_time;
          current_time=time(NULL);
          if(current_time>previous_time)
          {
            previous_time=current_time;
#ifdef HAVE_NCURSES
            ind_stop=photorec_progressbar(stdscr, testbf, status, file_recovery->location.start, disk_car, partition, *file_nbr, current_time-real_start_time, file_stats);
#endif
            if(ind_stop!=0)
            {
              file_finish(file_recovery,recup_dir,paranoid,file_nbr,blocksize,list_search_space,&current_search_space, &offset, dir_num,status,disk_car->sector_size,disk_car);
              free(block_buffer);
              return ind_stop;
            }
          }
        }
        fseek(file_recovery->handle,file_offset,SEEK_SET);
        list_truncate(&file_recovery->location,file_offset);
        file_recovery->file_size=file_offset;
        /* Skip extra blocs */
#ifdef DEBUG_BF
        log_debug("Skip %u extra blocs\n", blocs_to_skip);
#endif
        for(i=0; i<blocs_to_skip;i++)
        {
          get_next_sector(list_search_space, &current_search_space, &offset, blocksize);
        }
        { /* Add remaining data blocs */
          uint64_t offset_error_tmp;
          file_recovery->offset_error=original_offset_error;
          do
          {
            offset_error_tmp=file_recovery->offset_error;
            file_recovery->file_size=file_offset;

            for (;file_recovery->file_size < file_recovery->offset_error+100*blocksize &&
                current_search_space != list_search_space;
                file_recovery->file_size+=blocksize)
            {
              /* FIXME: handle fwrite return value */
              disk_car->read(disk_car, blocksize, block_buffer, offset);
              fwrite(block_buffer, blocksize, 1, file_recovery->handle);
              list_append_block(&file_recovery->location, offset, blocksize, 1);
              get_next_sector(list_search_space, &current_search_space, &offset, blocksize);
            }
            save_seek=ftell(file_recovery->handle);
#ifdef DEBUG_BF
            log_trace("BF ");
            list_space_used(file_recovery, blocksize);
#endif
            file_recovery->file_check(file_recovery);
#ifdef DEBUG_BF
            log_trace("offset_error %llu %llu\n",
                (long long unsigned) file_recovery->offset_error,
                (long long unsigned) offset_error_tmp);
            log_flush();
#endif
            fseek(file_recovery->handle, save_seek, SEEK_SET);
          } while(file_recovery->offset_error/blocksize*blocksize > offset_error_tmp/blocksize*blocksize);
        }
        if(file_recovery->offset_error==0)
        { /* Recover the file */
          file_finish(file_recovery,recup_dir,paranoid,file_nbr,blocksize,list_search_space,&current_search_space, &offset, dir_num,status,disk_car->sector_size,disk_car);
          free(block_buffer);
          return ind_stop;
        }
        else if(file_recovery->offset_error/blocksize*blocksize >= original_offset_error+4096)
        { /* Try to recover file composed of multiple fragments */
          log_info("%s multiple fragment %llu -> %llu\n", file_recovery->filename,
              (unsigned long long)original_offset_error,
              (unsigned long long)file_recovery->offset_error);
          log_flush();
          original_offset_error=file_recovery->offset_error;
          ind_stop=2;
        }
      }
    }
  } while(ind_stop==2);
  /* Cleanup */
  file_finish(file_recovery,recup_dir,paranoid,file_nbr,blocksize,list_search_space,&current_search_space, &offset, dir_num,status,disk_car->sector_size,disk_car);
  free(block_buffer);
  return ind_stop;
}

#if defined(__CYGWIN__) || defined(__MINGW32__)
/* Live antivirus protection may open file as soon as they are created by *
 * PhotoRec. PhotoRec will not be able to overwrite a file as long as the *
 * antivirus is scanning it, so let's wait a little bit if the creation   *
 * failed. */

#ifndef HAVE_SLEEP
#define sleep(x) Sleep((x)*1000)
#endif

static FILE *fopen_with_retry(const char *path, const char *mode)
{
  FILE *handle;
  if((handle=fopen(path, mode))!=NULL)
    return handle;
  sleep(1);
  if((handle=fopen(path, mode))!=NULL)
    return handle;
  sleep(2);
  if((handle=fopen(path, mode))!=NULL)
    return handle;
  return NULL;
}
#endif

static int photorec_find_blocksize(disk_t *disk_car, partition_t *partition, const int verbose, const int interface, file_stat_t *file_stats, unsigned int *file_nbr, unsigned int *blocksize, alloc_data_t *list_search_space, const time_t real_start_time, const unsigned int expert)
{
  uint64_t offset=0;
  unsigned char *buffer_start;
  unsigned char *buffer_olddata;
  unsigned char *buffer;
  time_t start_time;
  time_t previous_time;
  unsigned int buffer_size;
  const unsigned int read_size=((*blocksize)>65536?(*blocksize):65536);
  alloc_data_t *current_search_space;
  file_recovery_t file_recovery;
  static alloc_data_t list_file={
    .list = TD_LIST_HEAD_INIT(list_file.list)
  };
  buffer_size=(*blocksize)+READ_SIZE;
  buffer_start=(unsigned char *)MALLOC(buffer_size);
  buffer_olddata=buffer_start;
  buffer=buffer_olddata+(*blocksize);
  reset_file_recovery(&file_recovery);
  start_time=time(NULL);
  previous_time=start_time;
  memset(buffer_olddata,0,(*blocksize));
  current_search_space=td_list_entry(list_search_space->list.next, alloc_data_t, list);
  if(current_search_space!=list_search_space)
    offset=current_search_space->start;
  if(verbose>0)
    info_list_search_space(list_search_space, current_search_space, disk_car->sector_size, 0, verbose);
  disk_car->read(disk_car,READ_SIZE, buffer, offset);
  while(current_search_space!=list_search_space)
  {
    uint64_t old_offset=offset;
    {
      file_recovery_t file_recovery_new;
      if(file_recovery.file_stat!=NULL &&
          file_recovery.file_stat->file_hint->min_header_distance > 0 &&
          file_recovery.file_size<=file_recovery.file_stat->file_hint->min_header_distance)
      {
      }
      else if(file_recovery.file_stat!=NULL && file_recovery.file_stat->file_hint==&file_hint_tar &&
          header_check_tar(buffer-0x200,0x200,0,&file_recovery,&file_recovery_new))
      { /* Currently saving a tar, do not check the data for know header */
      }
      else
      {
	struct td_list_head *tmpl;
        file_recovery_new.file_stat=NULL;
	td_list_for_each(tmpl, &file_check_list.list)
	{
	  struct td_list_head *tmp;
	  const file_check_list_t *pos=td_list_entry(tmpl, file_check_list_t, list);
	  td_list_for_each(tmp, &pos->file_checks[pos->has_value==0?0:buffer[pos->offset]].list)
	  {
	    const file_check_t *file_check=td_list_entry(tmp, file_check_t, list);
	    if((file_check->length==0 || memcmp(buffer + file_check->offset, file_check->value, file_check->length)==0) &&
		file_check->header_check(buffer, read_size, 1, &file_recovery, &file_recovery_new)!=0)
	    {
	      file_recovery_new.file_stat=file_check->file_stat;
	      break;
	    }
	  }
	  if(file_recovery_new.file_stat!=NULL)
	    break;
	}
        if(file_recovery_new.file_stat!=NULL && file_recovery_new.file_stat->file_hint!=NULL)
	{
	  /* A new file begins, backup file offset */
	  alloc_data_t *new_file_alloc;
	  file_recovery_new.location.start=offset;
	  file_recovery_cpy(&file_recovery, &file_recovery_new);
	  new_file_alloc=(alloc_data_t*)MALLOC(sizeof(*new_file_alloc));
	  new_file_alloc->start=offset;
	  new_file_alloc->end=0;
	  td_list_add_tail(&new_file_alloc->list,&list_file.list);
	  (*file_nbr)++;
	}
      }
    }
    /* Check for data EOF */
    if(file_recovery.file_stat!=NULL)
    {
      int res=1;
      list_append_block(&file_recovery.location,offset,*blocksize,1);
      if(file_recovery.data_check!=NULL)
	res=file_recovery.data_check(buffer_olddata,2*(*blocksize),&file_recovery);
      file_recovery.file_size+=*blocksize;
      file_recovery.file_size_on_disk+=*blocksize;
      if(res==2)
      {
	/* EOF found */
	reset_file_recovery(&file_recovery);
      }
    }
    /* Check for maximum filesize */
    if(file_recovery.file_stat!=NULL && file_recovery.file_stat->file_hint->max_filesize>0 && file_recovery.file_size>=file_recovery.file_stat->file_hint->max_filesize)
    {
      reset_file_recovery(&file_recovery);
    }

    if(*file_nbr>=10)
    {
      current_search_space=list_search_space;
    }
    else
      get_next_sector(list_search_space, &current_search_space,&offset,*blocksize);
    if(current_search_space==list_search_space)
    {
      /* End of disk found => EOF */
      reset_file_recovery(&file_recovery);
    }
    buffer_olddata+=*blocksize;
    buffer+=*blocksize;
    if( old_offset+*blocksize!=offset ||
        buffer+read_size>buffer_start+buffer_size)
    {
      memcpy(buffer_start,buffer_olddata,*blocksize);
      buffer_olddata=buffer_start;
      buffer=buffer_olddata+*blocksize;
      if(verbose>1)
      {
        log_verbose("Reading sector %10lu/%lu\n",(unsigned long)((offset-partition->part_offset)/disk_car->sector_size),(unsigned long)((partition->part_size-1)/disk_car->sector_size));
      }
      if(disk_car->read(disk_car,READ_SIZE, buffer, offset)<0)
      {
#ifdef HAVE_NCURSES
        if(interface!=0)
        {
          wmove(stdscr,11,0);
          wclrtoeol(stdscr);
          wprintw(stdscr,"Error reading sector %10lu\n",
              (unsigned long)((offset-partition->part_offset)/disk_car->sector_size));
        }
#endif
      }
#ifdef HAVE_NCURSES
      if(interface!=0)
      {
        time_t current_time;
        current_time=time(NULL);
        if(current_time>previous_time)
        {
          previous_time=current_time;
          if(photorec_progressbar(stdscr, 0, STATUS_FIND_OFFSET, offset, disk_car, partition, *file_nbr, current_time-real_start_time, file_stats))
	  {
	    log_info("PhotoRec has been stopped\n");
	    current_search_space=list_search_space;
	  }
	}
      }
#endif
    }
  } /* end while(current_search_space!=list_search_space) */
  {
    uint64_t start_offset;
    *blocksize=find_blocksize(&list_file,disk_car->sector_size, &start_offset);
#ifdef HAVE_NCURSES
    if(expert>0)
      *blocksize=menu_choose_blocksize(*blocksize, disk_car->sector_size, &start_offset);
#endif
    update_blocksize(*blocksize,list_search_space, start_offset);
    free_list_search_space(&list_file);
  }
  free(buffer_start);
  return 0;
}

static int photorec_aux(disk_t *disk_car, partition_t *partition, const int verbose, const int paranoid, const char *recup_dir, const int interface, file_stat_t *file_stats, unsigned int *file_nbr, const unsigned int blocksize, alloc_data_t *list_search_space, const time_t real_start_time, unsigned int *dir_num, const photorec_status_t status, const unsigned int pass, const unsigned int lowmem)
{
  uint64_t offset=0;
  unsigned char *buffer_start;
  unsigned char *buffer_olddata;
  unsigned char *buffer;
  time_t start_time;
  time_t previous_time;
  int ind_stop=0;
  unsigned int buffer_size;
  const unsigned int read_size=((blocksize)>65536?(blocksize):65536);
  alloc_data_t *current_search_space;
  file_recovery_t file_recovery;
  buffer_size=(blocksize)+READ_SIZE;
  buffer_start=(unsigned char *)MALLOC(buffer_size);
  buffer_olddata=buffer_start;
  buffer=buffer_olddata+(blocksize);
  reset_file_recovery(&file_recovery);
  start_time=time(NULL);
  previous_time=start_time;
  memset(buffer_olddata,0,(blocksize));
  current_search_space=td_list_entry(list_search_space->list.next, alloc_data_t, list);
  if(current_search_space!=list_search_space)
    offset=current_search_space->start;
  if(verbose>0)
    info_list_search_space(list_search_space, current_search_space, disk_car->sector_size, 0, verbose);
  disk_car->read(disk_car,READ_SIZE, buffer, offset);
  while(current_search_space!=list_search_space)
  {
    int move_next=1;
    uint64_t old_offset=offset;
#ifdef DEBUG
    log_debug("sector %llu\n",
        (unsigned long long)((offset-partition->part_offset)/disk_car->sector_size));
    if(!(current_search_space->start<=offset && offset<=current_search_space->end))
    {
      log_critical("BUG: offset=%llu not in [%llu-%llu]\n",
          (unsigned long long)(offset/disk_car->sector_size),
          (unsigned long long)(current_search_space->start/disk_car->sector_size),
          (unsigned long long)(current_search_space->end/disk_car->sector_size));
      log_flush();
      exit(1);
    }
#endif
    {
      file_recovery_t file_recovery_new;
      if(file_recovery.file_stat!=NULL &&
          file_recovery.file_stat->file_hint->min_header_distance > 0 &&
          file_recovery.file_size<=file_recovery.file_stat->file_hint->min_header_distance)
      {
      }
      else if(file_recovery.file_stat!=NULL && file_recovery.file_stat->file_hint==&file_hint_tar &&
          header_check_tar(buffer-0x200,0x200,0,&file_recovery,&file_recovery_new))
      { /* Currently saving a tar, do not check the data for know header */
        if(verbose>1)
        {
          log_verbose("Currently saving a tar file, sector %lu.\n",
              (unsigned long)((offset-partition->part_offset)/disk_car->sector_size));
        }
      }
      else
      {
	struct td_list_head *tmpl;
        file_recovery_new.file_stat=NULL;
	td_list_for_each(tmpl, &file_check_list.list)
	{
	  struct td_list_head *tmp;
	  const file_check_list_t *pos=td_list_entry(tmpl, file_check_list_t, list);
	  td_list_for_each(tmp, &pos->file_checks[pos->has_value==0?0:buffer[pos->offset]].list)
	  {
	    const file_check_t *file_check=td_list_entry(tmp, file_check_t, list);
	    if((file_check->length==0 || memcmp(buffer + file_check->offset, file_check->value, file_check->length)==0) &&
		file_check->header_check(buffer, read_size, 0, &file_recovery, &file_recovery_new)!=0)
	    {
	      file_recovery_new.file_stat=file_check->file_stat;
	      break;
	    }
	  }
	  if(file_recovery_new.file_stat!=NULL)
	    break;
	}
        if(file_recovery_new.file_stat!=NULL && file_recovery_new.file_stat->file_hint!=NULL)
        {
	  file_recovery_new.location.start=offset;
          if(verbose>1)
            log_trace("A known header has been found, recovery of the previous file is finished\n");
          if(file_finish(&file_recovery,recup_dir,paranoid,file_nbr,blocksize,list_search_space,&current_search_space, &offset, dir_num,status,disk_car->sector_size,disk_car)>0)
            move_next=0;
          reset_file_recovery(&file_recovery);
          if(lowmem>0)
            forget(list_search_space,current_search_space);
          if(move_next!=0)
          {
	    file_recovery_cpy(&file_recovery, &file_recovery_new);
            if(verbose>1)
            {
              log_info("%s header found at sector %lu\n",
                  ((file_recovery.extension!=NULL && file_recovery.extension[0]!='\0')?
                   file_recovery.extension:file_recovery.file_stat->file_hint->description),
                  (unsigned long)((file_recovery.location.start-partition->part_offset)/disk_car->sector_size));
              log_info("file_recovery.location.start=%lu\n",
                  (unsigned long)(file_recovery.location.start/disk_car->sector_size));
            }

            if(file_recovery.file_stat->file_hint==&file_hint_dir && verbose>0)
            { /* FAT directory found, list the file */
              file_data_t *dir_list;
              dir_list=dir_fat_aux(buffer,read_size,0,0);
              if(dir_list!=NULL)
              {
		dir_aff_log(disk_car, partition, NULL, dir_list);
                delete_list_file(dir_list);
              }
            }
          }
        }
      }
      if(file_recovery.file_stat!=NULL && file_recovery.handle==NULL)
      {
	set_filename(&file_recovery, recup_dir, *dir_num, disk_car, partition,
	    (status==STATUS_EXT2_ON_SAVE_EVERYTHING||status==STATUS_EXT2_OFF_SAVE_EVERYTHING));
        if(file_recovery.file_stat->file_hint->recover==1)
        {
#if defined(__CYGWIN__) || defined(__MINGW32__)
          file_recovery.handle=fopen_with_retry(file_recovery.filename,"w+b");
#else
          file_recovery.handle=fopen(file_recovery.filename,"w+b");
#endif
          if(!file_recovery.handle)
          { 
            log_critical("Cannot create file %s: %s\n", file_recovery.filename, strerror(errno));
            ind_stop=2;
          }
        }
      }
    }
    /* try to skip ext2/ext3 indirect block */
      if((status==STATUS_EXT2_ON || status==STATUS_EXT2_ON_SAVE_EVERYTHING) &&
          file_recovery.file_stat!=NULL && file_recovery.file_size_on_disk>=12*(blocksize) &&
          ind_block(buffer,blocksize)!=0)
      {
        list_append_block(&file_recovery.location,offset,blocksize,0);
        file_recovery.file_size_on_disk+=blocksize;
        if(verbose>1)
        {
          log_verbose("Skipping sector %10lu/%lu\n",
              (unsigned long)((offset-partition->part_offset)/disk_car->sector_size),
              (unsigned long)(partition->part_size/disk_car->sector_size));
        }
        memcpy(buffer,buffer_olddata,(blocksize));
      }
      else
      {
        if(file_recovery.handle!=NULL)
        {
          if(fwrite(buffer,blocksize,1,file_recovery.handle)<1)
          { 
            log_critical("Cannot write file %s:%s\n", file_recovery.filename, strerror(errno));
            ind_stop=3;
          }
        }
        if(file_recovery.file_stat!=NULL)
        {
          int res=1;
          list_append_block(&file_recovery.location,offset,blocksize,1);
          if(file_recovery.data_check!=NULL)
            res=file_recovery.data_check(buffer_olddata,2*(blocksize),&file_recovery);
          file_recovery.file_size+=blocksize;
          file_recovery.file_size_on_disk+=blocksize;
          if(res==2)
          {
            if(verbose>1)
              log_trace("EOF found\n");
            if(file_finish(&file_recovery,recup_dir,paranoid,file_nbr, blocksize, list_search_space, &current_search_space, &offset, dir_num,status,disk_car->sector_size,disk_car)>0)
              move_next=0;
            reset_file_recovery(&file_recovery);
            if(lowmem>0)
              forget(list_search_space,current_search_space);
          }
        }
      }
    if(file_recovery.file_stat!=NULL && file_recovery.file_stat->file_hint->max_filesize>0 && file_recovery.file_size>=file_recovery.file_stat->file_hint->max_filesize)
    {
      log_verbose("File should not be bigger than %llu, stop adding data\n",
          (long long unsigned)file_recovery.file_stat->file_hint->max_filesize);
      if(file_finish(&file_recovery,recup_dir,paranoid,file_nbr,blocksize, list_search_space, &current_search_space, &offset, dir_num,status,disk_car->sector_size,disk_car)>0)
        move_next=0;
      reset_file_recovery(&file_recovery);
      if(lowmem>0)
        forget(list_search_space,current_search_space);
    }

    if(ind_stop>0)
    {
      log_info("PhotoRec has been stopped\n");
      current_search_space=list_search_space;
    }
    else if(move_next!=0)
    {
      get_next_sector(list_search_space, &current_search_space,&offset,blocksize);
    }
    else // if(move_next==0)
    {
      /* try to recover the previous file, otherwise stay at the current location */
      get_prev_file_header(list_search_space, &current_search_space, &offset);
    }
    if(current_search_space==list_search_space)
    {
#ifdef DEBUG_GET_NEXT_SECTOR
      log_trace("current_search_space==list_search_space=%p (prev=%p,next=%p)\n",
          current_search_space, current_search_space->list.prev, current_search_space->list.next);
      log_trace("End of media\n");
#endif
      if(file_finish(&file_recovery,recup_dir,paranoid,file_nbr,blocksize,list_search_space, &current_search_space, &offset, dir_num,status,disk_car->sector_size,disk_car)>0)
      {
        move_next=0;
        get_prev_file_header(list_search_space, &current_search_space, &offset);
      }
      reset_file_recovery(&file_recovery);
      if(lowmem>0)
        forget(list_search_space,current_search_space);
    }
    buffer_olddata+=blocksize;
    buffer+=blocksize;
    if(move_next==0 ||
        old_offset+blocksize!=offset ||
        buffer+read_size>buffer_start+buffer_size)
    {
      if(move_next==0)
        memset(buffer_start,0,(blocksize));
      else
        memcpy(buffer_start,buffer_olddata,blocksize);
      buffer_olddata=buffer_start;
      buffer=buffer_olddata+blocksize;
      if(verbose>1)
      {
        log_verbose("Reading sector %10lu/%lu\n",(unsigned long)((offset-partition->part_offset)/disk_car->sector_size),(unsigned long)((partition->part_size-1)/disk_car->sector_size));
      }
      if(disk_car->read(disk_car,READ_SIZE, buffer, offset)<0)
      {
#ifdef HAVE_NCURSES
        if(interface!=0)
        {
          wmove(stdscr,11,0);
          wclrtoeol(stdscr);
          wprintw(stdscr,"Error reading sector %10lu\n",
              (unsigned long)((offset-partition->part_offset)/disk_car->sector_size));
        }
#endif
      }
#ifdef HAVE_NCURSES
      if(interface!=0 && ind_stop==0)
      {
        time_t current_time;
        current_time=time(NULL);
        if(current_time>previous_time)
        {
          previous_time=current_time;
          ind_stop=photorec_progressbar(stdscr, pass, status, offset, disk_car, partition, *file_nbr, current_time-real_start_time, file_stats);
        }
      }
#endif
    }
  } /* end while(current_search_space!=list_search_space) */
  free(buffer_start);
#ifdef HAVE_NCURSES
  photorec_info(stdscr, file_stats);
#endif
  return ind_stop;
}

#ifdef HAVE_NCURSES
static void recovery_finished(const unsigned int file_nbr, const char *recup_dir, const int ind_stop, char **current_cmd)
{
  wmove(stdscr,9,0);
  wclrtoeol(stdscr);
  wprintw(stdscr,"%u files saved in %s directory.\n",file_nbr,recup_dir);
  wmove(stdscr,10,0);
  wclrtoeol(stdscr);
  switch(ind_stop)
  {
    case 0:
      wprintw(stdscr,"Recovery completed.");
      break;
    case 1:
      wprintw(stdscr,"Recovery aborted by the user.");
      break;
    case 2:
      wprintw(stdscr,"Cannot create file in current directory.");
      break;
    case 3:
      wprintw(stdscr,"Cannot write file, no space left.");
      break;
  }
  wmove(stdscr,22,0);
  wclrtoeol(stdscr);
  wattrset(stdscr, A_REVERSE);
  wprintw(stdscr,"[ Quit ]");
  wattroff(stdscr, A_REVERSE);
  wrefresh(stdscr);
  while(1)
  {
    switch(wgetch(stdscr))
    {
      case KEY_ENTER:
#ifdef PADENTER
      case PADENTER:
#endif
      case '\n':
      case '\r':
      case 'q':
      case 'Q':
	return;
    }
  }
}
#endif


void free_search_space(alloc_data_t *list_search_space)
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

#if defined(HAVE_NCURSES) && (defined(__CYGWIN__) || defined(__MINGW32__))
static int interface_cannot_create_file(void)
{
  static const struct MenuItem menuMain[]=
  {
    { 'C', "Continue", "Continue the recovery."},
    { 'Q', "Quit", "Abort the recovery."},
    { 0,NULL,NULL}
  };
  unsigned int menu=0;
  int car;
  aff_copy(stdscr);
  wmove(stdscr,4,0);
  wprintw(stdscr,"PhotoRec has been unable to create new file.");
  wmove(stdscr,5,0);
  wprintw(stdscr,"This problem may be due to antivirus blocking write access while scanning files created by PhotoRec.");
  wmove(stdscr,6,0);
  wprintw(stdscr,"If possible, temporary disable your antivirus live protection.");
  car= wmenuSelect_ext(stdscr, 23, INTER_MAIN_Y, INTER_MAIN_X, menuMain, 10,
      "CQ", MENU_VERT | MENU_VERT_WARN | MENU_BUTTON, &menu,NULL);
  if(car=='c' || car=='C')
    return 0;
  return 1;
}
#else
static int interface_cannot_create_file(void)
{
  return 1;
}
#endif

static file_stat_t * init_file_stats(file_enable_t *files_enable)
{
  file_stat_t *file_stats;
  file_enable_t *file_enable;
  unsigned int enable_count=1;	/* Lists are terminated by NULL */
  for(file_enable=files_enable;file_enable->file_hint!=NULL;file_enable++)
  {
    if(file_enable->enable>0)
    {
      enable_count++;
    }
  }
  file_stats=(file_stat_t *)MALLOC(enable_count * sizeof(file_stat_t));
  enable_count=0;
  for(file_enable=files_enable;file_enable->file_hint!=NULL;file_enable++)
  {
    if(file_enable->enable>0)
    {
      file_stats[enable_count].file_hint=file_enable->file_hint;
      file_stats[enable_count].not_recovered=0;
      file_stats[enable_count].recovered=0;
      if(file_enable->file_hint->register_header_check!=NULL)
	file_enable->file_hint->register_header_check(&file_stats[enable_count]);
      enable_count++;
    }
  }
  index_header_check();
  file_stats[enable_count].file_hint=NULL;
  return file_stats;
}

int photorec(disk_t *disk_car, partition_t *partition, const int verbose, const int paranoid, char *recup_dir, const int keep_corrupted_file, const int interface, file_enable_t *files_enable, unsigned int mode_ext2, char **current_cmd, alloc_data_t *list_search_space, unsigned int blocksize, const unsigned int expert, const unsigned int lowmem, const unsigned int carve_free_space_only)
{
  char *new_recup_dir=NULL;
  file_stat_t *file_stats;
  time_t real_start_time;
  unsigned int file_nbr=0;
  unsigned int dir_num=1;
  int ind_stop=0;
  unsigned int pass;
  unsigned int blocksize_is_known=0;
  photorec_status_t status;
  screen_buffer_reset();
  log_info("\nAnalyse\n");
  log_partition(disk_car,partition);
  if(blocksize==0)
    blocksize=disk_car->sector_size;
  else
    blocksize_is_known=1;
  file_stats=init_file_stats(files_enable);

  real_start_time=time(NULL);
  dir_num=photorec_mkdir(recup_dir,dir_num);
  status=STATUS_FIND_OFFSET;
  for(pass=0;status!=STATUS_QUIT;pass++)
  {
    unsigned int old_file_nbr=file_nbr;
    log_info("Pass %u (blocksize=%u) ",pass,blocksize);
    switch(status)
    {
      case STATUS_FIND_OFFSET:			log_info("STATUS_FIND_OFFSET\n");	break;
      case STATUS_EXT2_ON:			log_info("STATUS_EXT2_ON\n");	break;
      case STATUS_EXT2_ON_BF:			log_info("STATUS_EXT2_ON_BF\n");	break;
      case STATUS_EXT2_OFF:			log_info("STATUS_EXT2_OFF\n");	break;
      case STATUS_EXT2_OFF_BF:			log_info("STATUS_EXT2_OFF_BF\n");	break;
      case STATUS_EXT2_ON_SAVE_EVERYTHING:	log_info("STATUS_EXT2_ON_SAVE_EVERYTHING\n");	break;
      case STATUS_EXT2_OFF_SAVE_EVERYTHING:	log_info("STATUS_EXT2_OFF_SAVE_EVERYTHING\n");	break;
      case STATUS_QUIT :			log_info("STATUS_QUIT\n");			break;
    }
#ifdef HAVE_NCURSES
    if(interface)
    {
      aff_copy(stdscr);
      wmove(stdscr,4,0);
      wprintw(stdscr,"%s",disk_car->description_short(disk_car));
      mvwaddstr(stdscr,5,0,msg_PART_HEADER_LONG);
      wmove(stdscr,6,0);
      aff_part(stdscr,AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition);
      wmove(stdscr,22,0);
      wattrset(stdscr, A_REVERSE);
      waddstr(stdscr,"  Stop  ");
      wattroff(stdscr, A_REVERSE);
      wrefresh(stdscr);
    }
#endif
    if(status==STATUS_FIND_OFFSET && blocksize_is_known>0)
    {
#ifdef HAVE_NCURSES
      if(expert>0)
      {
	uint64_t offset=0;
	if(!td_list_empty(&list_search_space->list))
	{
	  alloc_data_t *tmp;
	  tmp=td_list_entry(list_search_space->list.next, alloc_data_t, list);
	  offset=tmp->start%blocksize;
	}
	blocksize=menu_choose_blocksize(blocksize, disk_car->sector_size, &offset);
	update_blocksize(blocksize,list_search_space, offset);
      }
#endif
      ind_stop=0;
    }
    else if(status==STATUS_EXT2_ON_BF || status==STATUS_EXT2_OFF_BF)
    {
      ind_stop=photorec_bf(disk_car, partition, verbose, paranoid, recup_dir, interface, file_stats, &file_nbr, &blocksize, list_search_space, real_start_time, &dir_num, status, pass);
      session_save(list_search_space, disk_car, partition, files_enable, blocksize, paranoid, keep_corrupted_file, mode_ext2, expert, lowmem, carve_free_space_only, verbose);
    }
    else if(status==STATUS_FIND_OFFSET)
    {
      ind_stop=photorec_find_blocksize(disk_car, partition, verbose, interface, file_stats, &file_nbr, &blocksize, list_search_space, real_start_time, expert);
    }
    else
    {
      ind_stop=photorec_aux(disk_car, partition, verbose, paranoid, recup_dir, interface, file_stats, &file_nbr, blocksize, list_search_space, real_start_time, &dir_num, status, pass, lowmem);
      session_save(list_search_space, disk_car, partition, files_enable, blocksize, paranoid, keep_corrupted_file, mode_ext2, expert, lowmem, carve_free_space_only, verbose);
    }
    if(ind_stop==3)
    { /* no more space */
#ifdef HAVE_NCURSES
      char *res;
      res=ask_location("Warning: no free space available. Do you want to save recovered files in %s%s ? [Y/N]\nDo not choose to write the files to the same partition they were stored on.","");
      if(res==NULL)
        status=STATUS_QUIT;
      else
      {
        free(new_recup_dir);
        new_recup_dir=(char *)MALLOC(strlen(res)+1+strlen(DEFAULT_RECUP_DIR)+1);
        strcpy(new_recup_dir,res);
        strcat(new_recup_dir,"/");
        strcat(new_recup_dir,DEFAULT_RECUP_DIR);
        recup_dir=new_recup_dir;
        free(res);
        /* Create the directory */
        dir_num=photorec_mkdir(recup_dir,dir_num);
      }
#else
      status=STATUS_QUIT;
#endif
    }
    else if(ind_stop==2)
    {
      if(interface_cannot_create_file()!=0)
	status=STATUS_QUIT;
    }
    else if(ind_stop>0)
    {
      status=STATUS_QUIT;
    }
    else if(paranoid>0)
    {
      switch(status)
      {
        case STATUS_FIND_OFFSET:
          status=(mode_ext2>0?STATUS_EXT2_ON:STATUS_EXT2_OFF);
          file_nbr=0;
          break;
        case STATUS_EXT2_ON:
          status=(paranoid>1?STATUS_EXT2_ON_BF:STATUS_EXT2_OFF);
          break;
        case STATUS_EXT2_ON_BF:
          status=STATUS_EXT2_OFF;
          break;
        case STATUS_EXT2_OFF:
          if(paranoid>1)
          {
            status=STATUS_EXT2_OFF_BF;
          }
          else
          {
            if(keep_corrupted_file>0)
              status=(mode_ext2>0?STATUS_EXT2_ON_SAVE_EVERYTHING:STATUS_EXT2_OFF_SAVE_EVERYTHING);
            else
            {
              status=STATUS_QUIT;
              unlink("photorec.ses");
            }
          }
          break;
        case STATUS_EXT2_OFF_BF:
          if(keep_corrupted_file>0)
            status=(mode_ext2>0?STATUS_EXT2_ON_SAVE_EVERYTHING:STATUS_EXT2_OFF_SAVE_EVERYTHING);
          else
          {
            status=STATUS_QUIT;
            unlink("photorec.ses");
          }
          break;
        case STATUS_EXT2_ON_SAVE_EVERYTHING:
          status=STATUS_EXT2_OFF_SAVE_EVERYTHING;
          break;
        default:
          status=STATUS_QUIT;
          unlink("photorec.ses");
          break;
      }
    }
    else
    {
      switch(status)
      {
        case STATUS_FIND_OFFSET:
          status=(mode_ext2>0?STATUS_EXT2_ON_SAVE_EVERYTHING:STATUS_EXT2_OFF_SAVE_EVERYTHING);
          file_nbr=0;
          break;
        default:
          status=STATUS_QUIT;
          unlink("photorec.ses");
          break;
      }
    }
    {
      time_t current_time;
      current_time=time(NULL);
      log_info("Elapsed time %uh%02um%02us\n",
          (unsigned)((current_time-real_start_time)/60/60),
          (unsigned)((current_time-real_start_time)/60%60),
          (unsigned)((current_time-real_start_time)%60));
    }
    update_stats(file_stats,list_search_space);
    log_info("Pass %u +%u file%s\n",pass,file_nbr-old_file_nbr,(file_nbr-old_file_nbr<=1?"":"s"));
    write_stats_log(file_stats);
    if(interface==0)
    {
      printf("Pass %u +%u file%s\n",pass,file_nbr-old_file_nbr,(file_nbr-old_file_nbr<=1?"":"s"));
      write_stats_stdout(file_stats);
      fflush(stdout);
    }
  }
  info_list_search_space(list_search_space, NULL, disk_car->sector_size, keep_corrupted_file, verbose);
  /* Free memory */
  free_search_space(list_search_space);
#ifdef HAVE_NCURSES
  if(interface && *current_cmd==NULL)
    recovery_finished(file_nbr, recup_dir, ind_stop, current_cmd);
#endif
  free(file_stats);
  free_header_check();
  free(new_recup_dir);
  return 0;
}

#ifdef HAVE_NCURSES
static void interface_options_photorec_ncurses(int *paranoid, int *allow_partial_last_cylinder, int *keep_corrupted_file, unsigned int *mode_ext2, unsigned int *expert, unsigned int *lowmem)
{
  unsigned int menu = 6;
  struct MenuItem menuOptions[]=
  {
    { 'P', NULL, "Check JPG files" },
    { 'A',NULL,"" },
    { 'K',NULL,"Keep corrupted files"},
    { 'S',NULL,"Try to skip indirect block"},
    { 'E',NULL,"Provide additional controls"},
    { 'L',NULL,"Low memory"},
    { 'Q',"Quit","Return to main menu"},
    { 0, NULL, NULL }
  };
  while (1)
  {
    int car;
    int real_key;
    switch(*paranoid)
    {
      case 0:
	menuOptions[0].name="Paranoid : No";
	break;
      case 1:
	menuOptions[0].name="Paranoid : Yes (Brute force disabled)";
	break;
      default:
	menuOptions[0].name="Paranoid : Yes (Brute force enabled)";
	break;
    }
    menuOptions[1].name=*allow_partial_last_cylinder?"Allow partial last cylinder : Yes":"Allow partial last cylinder : No";
    menuOptions[2].name=*keep_corrupted_file?"Keep corrupted files : Yes":"Keep corrupted files : No";
    menuOptions[3].name=*mode_ext2?"ext2/ext3 mode: Yes":"ext2/ext3 mode : No";
    menuOptions[4].name=*expert?"Expert mode : Yes":"Expert mode : No";
    menuOptions[5].name=*lowmem?"Low memory: Yes":"Low memory: No";
    /* Jpg
       Mov
       Mpg
       Minolta MRW
       Canon CRW
       Signa/Foveon X3F
       Fuji RAF
       Rollei RDC
       MP3

     */
    aff_copy(stdscr);
    car=wmenuSelect_ext(stdscr, 23, INTER_OPTION_Y, INTER_OPTION_X, menuOptions, 0, "PAKELQ", MENU_VERT|MENU_VERT_ARROW2VALID, &menu,&real_key);
    switch(car)
    {
      case 'p':
      case 'P':
	if(*paranoid<2)
	  (*paranoid)++;
	else
	  *paranoid=0;
	break;
      case 'a':
      case 'A':
	*allow_partial_last_cylinder=!*allow_partial_last_cylinder;
	break;
      case 'k':
      case 'K':
	*keep_corrupted_file=!*keep_corrupted_file;
	break;
      case 's':
      case 'S':
	*mode_ext2=!*mode_ext2;
	break;
      case 'e':
      case 'E':
	*expert=!*expert;
	break;
      case 'l':
      case 'L':
	*lowmem=!*lowmem;
	break;
      case key_ESC:
      case 'q':
      case 'Q':
	return;
    }
  }
}
#endif

void interface_options_photorec(int *paranoid, int *allow_partial_last_cylinder, int *keep_corrupted_file, unsigned int *mode_ext2, unsigned int *expert, unsigned int *lowmem, char **current_cmd)
{
  if(*current_cmd!=NULL)
  {
    int keep_asking=1;
    do
    {
      while(*current_cmd[0]==',')
	(*current_cmd)++;
      /* paranoid, longer option first */
      if(strncmp(*current_cmd,"paranoid_no",11)==0)
      {
	(*current_cmd)+=11;
	*paranoid=0;
      }
      else if(strncmp(*current_cmd,"paranoid_bf",11)==0)
      {
	(*current_cmd)+=11;
	*paranoid=2;
      }
      else if(strncmp(*current_cmd,"paranoid",8)==0)
      {
	(*current_cmd)+=8;
	*paranoid=1;
      }
      /* TODO: allow_partial_last_cylinder */
      /* keep_corrupted_file */
      else if(strncmp(*current_cmd,"keep_corrupted_file_no",22)==0)
      {
	(*current_cmd)+=22;
	*keep_corrupted_file=0;
      }
      else if(strncmp(*current_cmd,"keep_corrupted_file",19)==0)
      {
	(*current_cmd)+=19;
	*keep_corrupted_file=1;
      }
      /* mode_ext2 */
      else if(strncmp(*current_cmd,"mode_ext2",9)==0)
      {
	(*current_cmd)+=9;
	*mode_ext2=1;
      }
      /* expert */
      else if(strncmp(*current_cmd,"expert",6)==0)
      {
	(*current_cmd)+=6;
	*expert=1;
      }
      /* lowmem */
      else if(strncmp(*current_cmd,"lowmem",6)==0)
      {
	(*current_cmd)+=6;
	*lowmem=1;
      }
      else
	keep_asking=0;
    } while(keep_asking>0);
  }
  else
  {
#ifdef HAVE_NCURSES
    interface_options_photorec_ncurses(paranoid, allow_partial_last_cylinder, keep_corrupted_file, mode_ext2, expert, lowmem);
#endif
  }
  /* write new options to log file */
  log_info("New options :\n Paranoid : %s\n", *paranoid?"Yes":"No");
  log_info(" Brute force : %s\n", ((*paranoid)>1?"Yes":"No"));
  log_info(" Allow partial last cylinder : %s\n Keep corrupted files : %s\n ext2/ext3 mode : %s\n Expert mode : %s\n Low memory : %s\n",
      *allow_partial_last_cylinder?"Yes":"No",
      *keep_corrupted_file?"Yes":"No",
      *mode_ext2?"Yes":"No",
      *expert?"Yes":"No",
      *lowmem?"Yes":"No");
}

#ifdef HAVE_NCURSES
#define INTER_FSELECT_X	0
#define INTER_FSELECT_Y	(LINES-2)
#define INTER_FSELECT	(LINES-10)

static void interface_file_select_ncurses(file_enable_t *files_enable)
{
  int current_element_num=0;
  int offset=0;
  int old_LINES=0;	/* Screen will be cleared */
  unsigned int menu=0;
  int enable_status=files_enable[0].enable;
  static const struct MenuItem menuAdv[]=
  {
    {'q',"Quit","Return to main menu"},
    {0,NULL,NULL}
  };
  while(1)
  {
    int i;
    int command;
    if(old_LINES!=LINES)
    {
      aff_copy(stdscr);
      wmove(stdscr,4,0);
      wprintw(stdscr,"PhotoRec will try to locate the following files");
      current_element_num=0;
      offset=0;
      old_LINES=LINES;
    }
    wmove(stdscr,5,4);
    wclrtoeol(stdscr);
    if(offset>0)
      wprintw(stdscr,"Previous");
    for(i=offset;files_enable[i].file_hint!=NULL && i<offset+INTER_FSELECT;i++)
    {
      wmove(stdscr,6+i-offset,0);
      wclrtoeol(stdscr);	/* before addstr for BSD compatibility */
      if(i==current_element_num)
      {
	wattrset(stdscr, A_REVERSE);
	wprintw(stdscr,"[%c] %-4s %s", (files_enable[i].enable==0?' ':'X'),
	    (files_enable[i].file_hint->extension!=NULL?
	     files_enable[i].file_hint->extension:""),
	    files_enable[i].file_hint->description);
	wattroff(stdscr, A_REVERSE);
      }
      else
      {
	wprintw(stdscr,"[%c] %-4s %s", (files_enable[i].enable==0?' ':'X'),
	    (files_enable[i].file_hint->extension!=NULL?
	     files_enable[i].file_hint->extension:""),
	    files_enable[i].file_hint->description);
      }
    }
    wmove(stdscr,6+INTER_FSELECT,4);
    wclrtoeol(stdscr);	/* before addstr for BSD compatibility */
    if(files_enable[i].file_hint!=NULL)
      wprintw(stdscr,"Next");
    wmove(stdscr,6+INTER_FSELECT+1,0);
    wclrtoeol(stdscr);
    wprintw(stdscr,"Press ");
    if(has_colors())
      wbkgdset(stdscr,' ' | A_BOLD | COLOR_PAIR(0));
    wprintw(stdscr,"s");
    if(has_colors())
      wbkgdset(stdscr,' ' | COLOR_PAIR(0));
    if(enable_status==0)
      wprintw(stdscr," for default selection, ");
    else
      wprintw(stdscr," to disable all file famillies, ");
    if(has_colors())
      wbkgdset(stdscr,' ' | A_BOLD | COLOR_PAIR(0));
    wprintw(stdscr,"b");
    if(has_colors())
      wbkgdset(stdscr,' ' | COLOR_PAIR(0));
    wprintw(stdscr," to save the settings");
    command = wmenuSelect(stdscr, LINES-1, INTER_FSELECT_Y, INTER_FSELECT_X, menuAdv, 8,
	"q", MENU_BUTTON | MENU_ACCEPT_OTHERS, menu);
    switch(command)
    {
      case KEY_UP:
      case '8':
	if(current_element_num>0)
	  current_element_num--;
	break;
      case KEY_PPAGE:
      case '9':
	for(i=0; i<INTER_FSELECT-1 && current_element_num>0; i++)
	  current_element_num--;
	break;
      case KEY_DOWN:
      case '2':
	if(files_enable[current_element_num+1].file_hint!=NULL)
	  current_element_num++;
	break;
      case KEY_NPAGE:
      case '3':
	for(i=0; i<INTER_FSELECT-1 && files_enable[current_element_num+1].file_hint!=NULL; i++)
	  current_element_num++;
	break;
      case KEY_RIGHT:
      case '+':
      case ' ':
      case KEY_LEFT:
      case '-':
      case 'x':
      case 'X':
      case '4':
      case '5':
      case '6':
	files_enable[current_element_num].enable=1-files_enable[current_element_num].enable;
	break;
      case 's':
      case 'S':
	{
	  enable_status=1-enable_status;
	  if(enable_status==0)
	  {
	    file_enable_t *file_enable;
	    for(file_enable=&files_enable[0];file_enable->file_hint!=NULL;file_enable++)
	      file_enable->enable=0;
	  }
	  else
	    reset_list_file_enable(files_enable);
	}
	break;
      case 'b':
      case 'B':
	if(file_options_save(files_enable)<0)
	{
	  display_message("Failed to save the settings.");
	}
	else
	{
	  display_message("Settings recorded successfully.");
	}
	break;
      case 'q':
      case 'Q':
	return;
    }
    if(current_element_num<offset)
      offset=current_element_num;
    if(current_element_num>=offset+INTER_FSELECT)
      offset=current_element_num-INTER_FSELECT+1;
  }
}
#endif

void interface_file_select(file_enable_t *files_enable, char**current_cmd)
{
  log_info("\nInterface File Select\n");
  if(*current_cmd!=NULL)
  {
    int keep_asking;
    do
    {
      file_enable_t *file_enable;
      keep_asking=0;
      while(*current_cmd[0]==',')
	(*current_cmd)++;
      if(strncmp(*current_cmd,"everything",10)==0)
      {
	int enable_status;
	keep_asking=1;
	(*current_cmd)+=10;
	while(*current_cmd[0]==',')
	  (*current_cmd)++;
	if(strncmp(*current_cmd,"enable",6)==0)
	{
	  (*current_cmd)+=6;
	  enable_status=1;
	}
	else if(strncmp(*current_cmd,"disable",7)==0)
	{
	  (*current_cmd)+=7;
	  enable_status=0;
	}
	else
	{
	  log_critical("Syntax error %s\n",*current_cmd);
	  return;
	}
	for(file_enable=&files_enable[0];file_enable->file_hint!=NULL;file_enable++)
	  file_enable->enable=enable_status;
      }
      else
      {
	unsigned int cmd_length=0;
	while((*current_cmd)[cmd_length]!='\0' && (*current_cmd)[cmd_length]!=',')
	  cmd_length++;
	for(file_enable=&files_enable[0];file_enable->file_hint!=NULL;file_enable++)
	{
	  if(file_enable->file_hint->extension!=NULL &&
	      strlen(file_enable->file_hint->extension)==cmd_length &&
	      memcmp(file_enable->file_hint->extension,*current_cmd,cmd_length)==0)
	  {
	    keep_asking=1;
	    (*current_cmd)+=cmd_length;
	    while(*current_cmd[0]==',')
	      (*current_cmd)++;
	    if(strncmp(*current_cmd,"enable",6)==0)
	    {
	      (*current_cmd)+=6;
	      file_enable->enable=1;
	    }
	    else if(strncmp(*current_cmd,"disable",7)==0)
	    {
	      (*current_cmd)+=7;
	      file_enable->enable=0;
	    }
	    else
	    {
	      log_critical("Syntax error %s\n",*current_cmd);
	      return;
	    }
	  }
	}
      }
    } while(keep_asking>0);
    return;
  }
#ifdef HAVE_NCURSES
  interface_file_select_ncurses(files_enable);
#endif
}

#ifdef DEBUG_GET_NEXT_SECTOR
void bug(void)
{
  log_critical("bug\n");
}
#endif
