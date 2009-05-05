/*

    File: phbf.c

    Copyright (C) 1998-2009 Christophe GRENIER <grenier@cgsecurity.org>

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
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include "types.h"
#include "common.h"
#include "intrf.h"
#ifdef HAVE_NCURSES
#include "intrfn.h"
#else
#include <stdio.h>
#endif
#include <errno.h>
#ifdef HAVE_WINDEF_H
#include <windef.h>
#endif
#ifdef HAVE_WINBASE_H
#include <stdarg.h>
#include <winbase.h>
#endif
#include "dir.h"
#include "fat_dir.h"
#include "list.h"
#include "lang.h"
#include "filegen.h"
#include "photorec.h"
#include "sessionp.h"
#include "phrecn.h"
#include "log.h"
#include "log_part.h"
#include "file_tar.h"
#include "phcfg.h"
#include "pblocksize.h"
#include "pnext.h"
#include "phbf.h"
#include "phnc.h"

#define READ_SIZE 1024*512
extern file_check_list_t file_check_list;

static int photorec_bf_aux(disk_t *disk_car, partition_t *partition, const int paranoid, const char *recup_dir, const int interface, file_stat_t *file_stats, unsigned int *file_nbr, file_recovery_t *file_recovery, const unsigned int blocksize, alloc_data_t *list_search_space, alloc_data_t *current_search_space, const time_t real_start_time, unsigned int *dir_num, const photorec_status_t status);

static inline void file_recovery_cpy(file_recovery_t *dst, file_recovery_t *src)
{
  memcpy(dst, src, sizeof(*dst));
  dst->location.list.prev=&dst->location.list;
  dst->location.list.next=&dst->location.list;
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

int photorec_bf(disk_t *disk_car, partition_t *partition, const int verbose, const int paranoid, const char *recup_dir, const int interface, file_stat_t *file_stats, unsigned int *file_nbr, const unsigned int blocksize, alloc_data_t *list_search_space, const time_t real_start_time, unsigned int *dir_num, const photorec_status_t status, const unsigned int pass)
{
  struct td_list_head *search_walker = NULL;
  struct td_list_head *n= NULL;
  unsigned char *buffer_start;
  const unsigned int read_size=(blocksize>65536?blocksize:65536);
  unsigned int buffer_size;
  int ind_stop=0;
  int pass2=pass;
  buffer_size=blocksize+READ_SIZE;
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
    buffer=buffer_olddata+blocksize;
    reset_file_recovery(&file_recovery);
    memset(buffer_olddata, 0, blocksize);
    disk_car->pread(disk_car, buffer, READ_SIZE, offset);
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
	set_filename(&file_recovery, recup_dir, *dir_num, disk_car, partition, 0);
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
	if(file_recovery.handle!=NULL)
	{
	  if(fwrite(buffer,blocksize,1,file_recovery.handle)<1)
	  { 
	    log_critical("Cannot write to file %s:%s\n", file_recovery.filename, strerror(errno));
	    ind_stop=3;
	  }
	}
	if(file_recovery.file_stat!=NULL)
	{
	  int res=1;
	  list_append_block(&file_recovery.location, offset, blocksize,1);
	  if(file_recovery.data_check!=NULL)
	    res=file_recovery.data_check(buffer_olddata, 2*blocksize, &file_recovery);
	  file_recovery.file_size+=blocksize;
	  file_recovery.file_size_on_disk+=blocksize;
	  if(res==2)
	  { /* EOF found */
	    need_to_check_file=1;
	  }
	}
	if(file_recovery.file_stat!=NULL && file_recovery.file_stat->file_hint->max_filesize>0 && file_recovery.file_size>=file_recovery.file_stat->file_hint->max_filesize)
	{
	  log_verbose("File should not be bigger than %llu, stop adding data\n",
	      (long long unsigned)file_recovery.file_stat->file_hint->max_filesize);
          need_to_check_file=1;
        }
      }
      get_next_sector(list_search_space, &current_search_space, &offset, blocksize);
      if(current_search_space==list_search_space)
        need_to_check_file=1;
      if(need_to_check_file==0)
      {
        buffer_olddata+=blocksize;
        buffer+=blocksize;
        if(old_offset+blocksize!=offset || buffer+read_size>buffer_start+buffer_size)
        {
          memcpy(buffer_start, buffer_olddata, blocksize);
          buffer_olddata=buffer_start;
          buffer=buffer_olddata+blocksize;
          if(verbose>1)
          {
            log_verbose("Reading sector %10lu/%lu\n",
                (unsigned long)((offset-partition->part_offset)/disk_car->sector_size),
                (unsigned long)((partition->part_size-1)/disk_car->sector_size));
          }
          disk_car->pread(disk_car, buffer, READ_SIZE, offset);
        }
      }
    } while(need_to_check_file==0);
    if(need_to_check_file==1)
    {
      if(file_finish(&file_recovery,recup_dir,paranoid,file_nbr, blocksize, list_search_space, &current_search_space, &offset, dir_num,status,disk_car)<0)
      { /* BF */
        current_search_space=td_list_entry(search_walker, alloc_data_t, list);
        ind_stop=photorec_bf_aux(disk_car, partition, paranoid, recup_dir, interface, file_stats, file_nbr, &file_recovery, blocksize, list_search_space, current_search_space, real_start_time, dir_num, status);
        pass2++;
      }
    }
  }
  free(buffer_start);
#ifdef HAVE_NCURSES
  photorec_info(stdscr, file_stats);
#endif
  return ind_stop;
}

static int photorec_bf_aux(disk_t *disk_car, partition_t *partition, const int paranoid, const char *recup_dir, const int interface, file_stat_t *file_stats, unsigned int *file_nbr, file_recovery_t *file_recovery, const unsigned int blocksize, alloc_data_t *list_search_space, alloc_data_t *start_search_space, const time_t real_start_time, unsigned int *dir_num, const photorec_status_t status)
{
  uint64_t offset;
  uint64_t original_offset_error;
  long int save_seek;
  unsigned char *block_buffer;
  unsigned int i;
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
    disk_car->pread(disk_car, block_buffer, blocksize, offset);
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
    uint64_t file_offset;
    ind_stop=0;
    for(file_offset=(original_offset_error+blocksize-1)/blocksize*blocksize;
        file_offset >= blocksize && (original_offset_error+blocksize-1)/blocksize*blocksize<file_offset+8*512 && ind_stop==0;
        file_offset -= blocksize)
    {
      alloc_data_t *extractblock_search_space;
      uint64_t extrablock_offset;
      unsigned int blocs_to_skip;
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
              file_finish(file_recovery, recup_dir, paranoid, file_nbr, blocksize, list_search_space, &current_search_space, &offset, dir_num, status, disk_car);
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
        for(i=0; i<blocs_to_skip; i++)
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
              disk_car->pread(disk_car, block_buffer, blocksize, offset);
              fwrite(block_buffer, blocksize, 1, file_recovery->handle);
              list_append_block(&file_recovery->location, offset, blocksize, 1);
              get_next_sector(list_search_space, &current_search_space, &offset, blocksize);
            }
            save_seek=ftell(file_recovery->handle);
#ifdef DEBUG_BF
            log_trace("BF ");
            list_space_used(file_recovery, blocksize);
#endif
            file_recovery->offset_error=0;
            file_recovery->calculated_file_size=0;
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
          file_finish(file_recovery,recup_dir,paranoid,file_nbr,blocksize,list_search_space,&current_search_space, &offset, dir_num,status,disk_car);
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
  file_finish(file_recovery,recup_dir,paranoid,file_nbr,blocksize,list_search_space,&current_search_space, &offset, dir_num,status,disk_car);
  free(block_buffer);
  return ind_stop;
}


