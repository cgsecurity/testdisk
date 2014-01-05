/*

    File: qpsearch.cpp

    Copyright (C) 1998-2013 Christophe GRENIER <grenier@cgsecurity.org>

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
#ifdef HAVE_UNISTD_H
#include <unistd.h>
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
#ifdef HAVE_WINDEF_H
#include <windef.h>
#endif
#ifdef HAVE_WINBASE_H
#include <stdarg.h>
#include <winbase.h>
#endif
#include <QCoreApplication>
#include "types.h"
#include "common.h"
#include "intrf.h"
#include <errno.h>
#include "dir.h"
#include "fat.h"
#include "fat_dir.h"
#include "list.h"
#include "filegen.h"
#include "photorec.h"
#include "sessionp.h"
#include "log.h"
#include "file_tar.h"
#include "pnext.h"
#include "file_found.h"
#include "psearch.h"
#include "qphotorec.h"

#define READ_SIZE 1024*512
extern const file_hint_t file_hint_tar;
extern const file_hint_t file_hint_dir;
extern file_check_list_t file_check_list;

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
#ifdef __MINGW32__
  Sleep(1000);
#else
  sleep(1);
#endif
  if((handle=fopen(path, mode))!=NULL)
    return handle;
#ifdef __MINGW32__
  Sleep(2000);
#else
  sleep(2);
#endif
  if((handle=fopen(path, mode))!=NULL)
    return handle;
  return NULL;
}
#endif

pstatus_t QPhotorec::photorec_aux(alloc_data_t *list_search_space)
{
  uint64_t offset;
  unsigned char *buffer_start;
  unsigned char *buffer_olddata;
  unsigned char *buffer;
  time_t start_time;
  time_t previous_time;
  time_t next_checkpoint;
  pstatus_t ind_stop=PSTATUS_OK;
  unsigned int buffer_size;
  const unsigned int blocksize=params->blocksize; 
  const unsigned int read_size=(blocksize>65536?blocksize:65536);
  uint64_t offset_before_back=0;
  unsigned int back=0;
  alloc_data_t *current_search_space;
  file_recovery_t file_recovery;
  memset(&file_recovery, 0, sizeof(file_recovery));
  reset_file_recovery(&file_recovery);
  file_recovery.blocksize=blocksize;
  buffer_size=blocksize + READ_SIZE;
  buffer_start=(unsigned char *)MALLOC(buffer_size);
  buffer_olddata=buffer_start;
  buffer=buffer_olddata+blocksize;
  start_time=time(NULL);
  previous_time=start_time;
  next_checkpoint=start_time+5*60;
  memset(buffer_olddata,0,blocksize);
  current_search_space=td_list_entry(list_search_space->list.next, alloc_data_t, list);
  offset=set_search_start(params, &current_search_space, list_search_space);
  if(options->verbose > 0)
    info_list_search_space(list_search_space, current_search_space, params->disk->sector_size, 0, options->verbose);
  if(options->verbose > 1)
  {
    log_verbose("Reading sector %10llu/%llu\n",
	(unsigned long long)((offset-params->partition->part_offset)/params->disk->sector_size),
	(unsigned long long)((params->partition->part_size-1)/params->disk->sector_size));
  }
  params->disk->pread(params->disk, buffer, READ_SIZE, offset);
  while(current_search_space!=list_search_space)
  {
    data_check_t res=DC_SCAN;
    int file_recovered=0;
    uint64_t old_offset=offset;
#ifdef DEBUG
    log_debug("sector %llu\n",
        (unsigned long long)((offset-params->partition->part_offset)/params->disk->sector_size));
    if(!(current_search_space->start<=offset && offset<=current_search_space->end))
    {
      log_critical("BUG: offset=%llu not in [%llu-%llu]\n",
          (unsigned long long)(offset/params->disk->sector_size),
          (unsigned long long)(current_search_space->start/params->disk->sector_size),
          (unsigned long long)(current_search_space->end/params->disk->sector_size));
      log_close();
      exit(1);
    }
#endif
    {
      file_recovery_t file_recovery_new;
      file_recovery_new.blocksize=blocksize;
      if(file_recovery.file_stat!=NULL &&
          file_recovery.file_stat->file_hint->min_header_distance > 0 &&
          file_recovery.file_size<=file_recovery.file_stat->file_hint->min_header_distance)
      {
      }
      else if(file_recovery.file_stat!=NULL && file_recovery.file_stat->file_hint==&file_hint_tar &&
          header_check_tar(buffer-0x200,0x200,0,&file_recovery,&file_recovery_new))
      { /* Currently saving a tar, do not check the data for know header */
        if(options->verbose > 1)
        {
          log_verbose("Currently saving a tar file, sector %lu.\n",
              (unsigned long)((offset-params->partition->part_offset)/params->disk->sector_size));
        }
      }
      else
      {
	struct td_list_head *tmpl;
        file_recovery_new.file_stat=NULL;
	td_list_for_each(tmpl, &file_check_list.list)
	{
	  struct td_list_head *tmp;
	  const file_check_list_t *tmp2=td_list_entry(tmpl, file_check_list_t, list);
	  td_list_for_each(tmp, &tmp2->file_checks[buffer[tmp2->offset]].list)
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
	  if(file_recovery.file_stat!=NULL)
	  {
	    if(options->verbose > 1)
	      log_trace("A known header has been found, recovery of the previous file is finished\n");
	    file_recovered=file_finish2(&file_recovery, params, options->paranoid, list_search_space);
	    if(options->lowmem > 0)
	      forget(list_search_space,current_search_space);
	  }
          if(file_recovered==0)
          {
	    file_recovery_cpy(&file_recovery, &file_recovery_new);
            if(options->verbose > 1)
            {
              log_info("%s header found at sector %lu\n",
                  ((file_recovery.extension!=NULL && file_recovery.extension[0]!='\0')?
                   file_recovery.extension:file_recovery.file_stat->file_hint->description),
                  (unsigned long)((file_recovery.location.start-params->partition->part_offset)/params->disk->sector_size));
              log_info("file_recovery.location.start=%lu\n",
                  (unsigned long)(file_recovery.location.start/params->disk->sector_size));
            }

            if(file_recovery.file_stat->file_hint==&file_hint_dir && options->verbose > 0)
            { /* FAT directory found, list the file */
	      file_info_t dir_list = {
		.list = TD_LIST_HEAD_INIT(dir_list.list),
		.name = NULL
	      };
	      dir_fat_aux(buffer, read_size, 0, &dir_list);
	      if(!td_list_empty(&dir_list.list))
              {
		log_info("Sector %lu\n",
		    (unsigned long)(file_recovery.location.start/params->disk->sector_size));
		dir_aff_log(NULL, &dir_list);
                delete_list_file(&dir_list);
              }
            }
          }
        }
      }
      if(file_recovery.file_stat!=NULL && file_recovery.handle==NULL)
      {
	set_filename(&file_recovery, params);
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
            ind_stop=PSTATUS_EACCES;
	    params->offset=offset;
          }
        }
      }
    }
    if(file_recovery.file_stat!=NULL)
    {
    /* try to skip ext2/ext3 indirect block */
      if((params->status==STATUS_EXT2_ON || params->status==STATUS_EXT2_ON_SAVE_EVERYTHING) &&
          file_recovery.file_size >= 12*blocksize &&
          ind_block(buffer,blocksize)!=0)
      {
	file_block_append(&file_recovery, list_search_space, &current_search_space, &offset, blocksize, 0);
	res=DC_CONTINUE;
        if(options->verbose > 1)
        {
          log_verbose("Skipping sector %10lu/%lu\n",
              (unsigned long)((offset-params->partition->part_offset)/params->disk->sector_size),
              (unsigned long)((params->partition->part_size-1)/params->disk->sector_size));
        }
        memcpy(buffer, buffer_olddata, blocksize);
      }
      else
      {
	if(file_recovery.handle!=NULL)
	{
	  if(fwrite(buffer,blocksize,1,file_recovery.handle)<1)
	  { 
	    log_critical("Cannot write to file %s: %s\n", file_recovery.filename, strerror(errno));
	    if(errno==EFBIG)
	    {
	      /* File is too big for the destination filesystem */
	      res=DC_STOP;
	    }
	    else
	    {
	      /* Warn the user */
	      ind_stop=PSTATUS_ENOSPC;
	      params->offset=file_recovery.location.start;
	    }
	  }
	}
	if(ind_stop==PSTATUS_OK)
	{
	  file_block_append(&file_recovery, list_search_space, &current_search_space, &offset, blocksize, 1);
	  if(file_recovery.data_check!=NULL)
	    res=file_recovery.data_check(buffer_olddata,2*blocksize,&file_recovery);
	  else
	    res=DC_CONTINUE;
	  file_recovery.file_size+=blocksize;
	  if(res==DC_STOP)
	  {
	    if(options->verbose > 1)
	      log_trace("EOF found\n");
	  }
	}
      }
      if(res!=DC_STOP && res!=DC_ERROR && file_recovery.file_stat->file_hint->max_filesize>0 && file_recovery.file_size>=file_recovery.file_stat->file_hint->max_filesize)
      {
	res=DC_STOP;
	log_verbose("File should not be bigger than %llu, stop adding data\n",
	    (long long unsigned)file_recovery.file_stat->file_hint->max_filesize);
      }
      if(res!=DC_STOP && res!=DC_ERROR &&  file_recovery.file_size + blocksize >= PHOTOREC_MAX_SIZE_32 && is_fat(params->partition))
      {
      	res=DC_STOP;
	log_verbose("File should not be bigger than %llu, stop adding data\n",
	    (long long unsigned)file_recovery.file_stat->file_hint->max_filesize);
      }
      if(res==DC_STOP || res==DC_ERROR)
      {
	file_recovered=file_finish2(&file_recovery, params, options->paranoid, list_search_space);
	if(options->lowmem > 0)
	  forget(list_search_space,current_search_space);
      }
    }
    if(ind_stop!=PSTATUS_OK)
    {
      log_info("PhotoRec has been stopped\n");
      current_search_space=list_search_space;
    }
    else if(file_recovered==0)
    {
      if(res==DC_SCAN)
      {
	get_next_sector(list_search_space, &current_search_space,&offset,blocksize);
	if(offset > offset_before_back)
	  back=0;
      }
    }
    else if(file_recovered>0)
    {
      /* try to recover the previous file, otherwise stay at the current location */
      offset_before_back=offset;
      if(back < 10 &&
	  get_prev_file_header(list_search_space, &current_search_space, &offset)==0)
	back++;
      else
	back=0;
    }
    if(current_search_space==list_search_space)
    {
#ifdef DEBUG_GET_NEXT_SECTOR
      log_trace("current_search_space==list_search_space=%p (prev=%p,next=%p)\n",
	  current_search_space, current_search_space->list.prev, current_search_space->list.next);
      log_trace("End of media\n");
#endif
      file_recovered=file_finish2(&file_recovery, params, options->paranoid, list_search_space);
      if(options->lowmem > 0)
	forget(list_search_space,current_search_space);
    }
    buffer_olddata+=blocksize;
    buffer+=blocksize;
    if(file_recovered==1 ||
        old_offset+blocksize!=offset ||
        buffer+read_size>buffer_start+buffer_size)
    {
      if(file_recovered==1)
        memset(buffer_start,0,blocksize);
      else
        memcpy(buffer_start,buffer_olddata,blocksize);
      buffer_olddata=buffer_start;
      buffer=buffer_olddata + blocksize;
      if(options->verbose > 1)
      {
        log_verbose("Reading sector %10llu/%llu\n",
	    (unsigned long long)((offset-params->partition->part_offset)/params->disk->sector_size),
	    (unsigned long long)((params->partition->part_size-1)/params->disk->sector_size));
      }
      if(params->disk->pread(params->disk, buffer, READ_SIZE, offset) != READ_SIZE)
      {
      }
      if(ind_stop==PSTATUS_OK)
      {
        const time_t current_time=time(NULL);
        if(current_time > previous_time)
        {
          previous_time=current_time;
	  QCoreApplication::processEvents();
	  if(stop_the_recovery)
	    ind_stop=PSTATUS_STOP;
	  if(file_recovery.file_stat!=NULL)
	    params->offset=file_recovery.location.start;
	  else
	    params->offset=offset;
	  if(current_time >= next_checkpoint)
	  {
	    /* Save current progress */
	    session_save(list_search_space, params, options);
	    next_checkpoint=current_time+5*60;
	  }
        }
      }
    }
  } /* end while(current_search_space!=list_search_space) */
  free(buffer_start);
  return ind_stop;
}
