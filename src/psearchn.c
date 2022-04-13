/*

    File: psearchn.c

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

#if defined(DISABLED_FOR_FRAMAC)
#undef HAVE_NCURSES
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
#ifdef HAVE_NCURSES
#include "intrfn.h"
#include "phnc.h"
#endif
#include "psearchn.h"
#include "photorec_check_header.h"
#define READ_SIZE 1024*512
extern int need_to_stop;

pstatus_t photorec_aux(struct ph_param *params, const struct ph_options *options, alloc_data_t *list_search_space)
{
  pstatus_t ind_stop=PSTATUS_OK;
#ifndef DISABLED_FOR_FRAMAC
  uint64_t offset;
  unsigned char *buffer_start;
  unsigned char *buffer_olddata;
  unsigned char *buffer;
  time_t start_time;
  time_t previous_time;
  time_t next_checkpoint;
  const unsigned int blocksize=params->blocksize; 
  const unsigned int buffer_size=blocksize + READ_SIZE;
  /*@ assert buffer_size==blocksize + READ_SIZE; */
  const unsigned int read_size=(blocksize>65536?blocksize:65536);
  uint64_t offset_before_back=0;
  unsigned int back=0;
  /*@ assert blocksize == 512; */
  /*@ assert buffer_size == blocksize + READ_SIZE ; */
#ifdef DISABLED_FOR_FRAMAC
  char buffer_start_tmp[512+READ_SIZE];
#endif
  pfstatus_t file_recovered_old=PFSTATUS_BAD;
  alloc_data_t *current_search_space;
  file_recovery_t file_recovery;
  memset(&file_recovery, 0, sizeof(file_recovery));
  reset_file_recovery(&file_recovery);
  file_recovery.blocksize=blocksize;
  /*@ assert valid_file_recovery(&file_recovery); */
#ifndef DISABLED_FOR_FRAMAC
  buffer_start=(unsigned char *)MALLOC(buffer_size);
#else
  buffer_start=&buffer_start_tmp;
#endif
  /*@ assert \valid((char *)buffer_start + (0 .. buffer_size-1)); */
  buffer_olddata=buffer_start;
  buffer=buffer_olddata+blocksize;
  /*@ assert \valid(buffer_start + (0 .. blocksize + READ_SIZE-1)); */
  /*@ assert \valid(buffer + (0 .. READ_SIZE-1)); */
  start_time=time(NULL);
  previous_time=start_time;
  next_checkpoint=start_time+5*60;
  memset(buffer_olddata,0,blocksize);
  current_search_space=td_list_first_entry(&list_search_space->list, alloc_data_t, list);
  offset=set_search_start(params, &current_search_space, list_search_space);
  if(options->verbose > 0)
    info_list_search_space(list_search_space, current_search_space, params->disk->sector_size, 0, options->verbose);
#ifndef DISABLED_FOR_FRAMAC
  if(options->verbose > 1)
  {
    log_verbose("Reading sector %10llu/%llu\n",
	(unsigned long long)((offset-params->partition->part_offset)/params->disk->sector_size),
	(unsigned long long)((params->partition->part_size-1)/params->disk->sector_size));
  }
#endif
  params->disk->pread(params->disk, buffer, READ_SIZE, offset);
  header_ignored(NULL);
#ifndef DISABLED_FOR_FRAMAC
  /*@ loop invariant valid_file_recovery(&file_recovery); */
  while(current_search_space!=list_search_space)
#else
  if(current_search_space!=list_search_space)
#endif
  {
    pfstatus_t file_recovered=PFSTATUS_BAD;
    uint64_t old_offset=offset;
    data_check_t data_check_status=DC_SCAN;
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
    /*@ assert valid_file_recovery(&file_recovery); */
    ind_stop=photorec_check_header(&file_recovery, params, options, list_search_space, buffer, &file_recovered, offset);
    /*@ assert valid_file_recovery(&file_recovery); */
    if(file_recovery.file_stat!=NULL)
    {
    /* try to skip ext2/ext3 indirect block */
      if((params->status==STATUS_EXT2_ON || params->status==STATUS_EXT2_ON_SAVE_EVERYTHING) &&
          file_recovery.file_size >= 12*blocksize &&
          ind_block(buffer,blocksize)!=0)
      {
	/*@ assert valid_file_recovery(&file_recovery); */
	file_block_append(&file_recovery, list_search_space, &current_search_space, &offset, blocksize, 0);
	/*@ assert valid_file_recovery(&file_recovery); */
	data_check_status=DC_CONTINUE;
#ifndef DISABLED_FOR_FRAMAC
        if(options->verbose > 1)
        {
          log_verbose("Skipping sector %10lu/%lu\n",
              (unsigned long)((offset-params->partition->part_offset)/params->disk->sector_size),
              (unsigned long)((params->partition->part_size-1)/params->disk->sector_size));
        }
#endif
        memcpy(buffer, buffer_olddata, blocksize);
      }
      else
      {
	if(file_recovery.handle!=NULL)
	{
	  if(fwrite(buffer,blocksize,1,file_recovery.handle)<1)
	  { 
#ifndef DISABLED_FOR_FRAMAC
	    log_critical("Cannot write to file %s after %llu bytes: %s\n", file_recovery.filename, (long long unsigned)file_recovery.file_size, strerror(errno));
#endif
	    if(errno==EFBIG)
	    {
	      /* File is too big for the destination filesystem */
	      data_check_status=DC_STOP;
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
	  /*@ assert valid_file_recovery(&file_recovery); */
	  file_block_append(&file_recovery, list_search_space, &current_search_space, &offset, blocksize, 1);
	  /*@ assert valid_file_recovery(&file_recovery); */
	  if(file_recovery.data_check!=NULL)
	    data_check_status=file_recovery.data_check(buffer_olddata,2*blocksize,&file_recovery);
	  else
	    data_check_status=DC_CONTINUE;
	  file_recovery.file_size+=blocksize;
#ifndef DISABLED_FOR_FRAMAC
	  if(data_check_status==DC_STOP)
	  {
	    if(options->verbose > 1)
	      log_trace("EOF found\n");
	  }
#endif
	}
      }
      if(data_check_status!=DC_STOP && data_check_status!=DC_ERROR && file_recovery.file_stat->file_hint->max_filesize>0 && file_recovery.file_size>=file_recovery.file_stat->file_hint->max_filesize)
      {
	data_check_status=DC_STOP;
#ifndef DISABLED_FOR_FRAMAC
	log_verbose("File should not be bigger than %llu, stopped adding data\n",
	    (long long unsigned)file_recovery.file_stat->file_hint->max_filesize);
#endif
      }
      if(data_check_status!=DC_STOP && data_check_status!=DC_ERROR && file_recovery.file_size + blocksize >= PHOTOREC_MAX_SIZE_32 && is_fat(params->partition))
      {
	data_check_status=DC_STOP;
#ifndef DISABLED_FOR_FRAMAC
	log_verbose("File should not be bigger than %llu, stopped adding data\n",
	    (long long unsigned)file_recovery.file_stat->file_hint->max_filesize);
#endif
      }
      if(data_check_status==DC_STOP || data_check_status==DC_ERROR)
      {
	if(data_check_status==DC_ERROR)
	  file_recovery.file_size=0;
	file_recovered=file_finish2(&file_recovery, params, options->paranoid, list_search_space);
	if(options->lowmem > 0)
	  forget(list_search_space,current_search_space);
      }
    }
    if(ind_stop!=PSTATUS_OK)
    {
#ifndef DISABLED_FOR_FRAMAC
      log_info("PhotoRec has been stopped\n");
#endif
      /*@ assert valid_file_recovery(&file_recovery); */
      file_recovery_aborted(&file_recovery, params, list_search_space);
      /*@ assert valid_file_recovery(&file_recovery); */
#ifndef DISABLED_FOR_FRAMAC
      free(buffer_start);
#endif
      return ind_stop;
    }
    if(file_recovered==PFSTATUS_BAD)
    {
      if(data_check_status==DC_SCAN)
      {
	if(file_recovered_old==PFSTATUS_OK)
	{
	  offset_before_back=offset;
	  if(back < 5 &&
	      get_prev_file_header(list_search_space, &current_search_space, &offset)==0)
	  {
	    back++;
	  }
	  else
	  {
	    back=0;
	    get_prev_location_smart(list_search_space, &current_search_space, &offset, file_recovery.location.start);
	  }
	}
	else
	{
	  get_next_sector(list_search_space, &current_search_space,&offset,blocksize);
	  if(offset > offset_before_back)
	    back=0;
	}
      }
    }
    else if(file_recovered==PFSTATUS_OK_TRUNCATED)
    {
      /* try to recover the previous file, otherwise stay at the current location */
      offset_before_back=offset;
      if(back < 5 &&
	  get_prev_file_header(list_search_space, &current_search_space, &offset)==0)
      {
	back++;
      }
      else
      {
	back=0;
	get_prev_location_smart(list_search_space, &current_search_space, &offset, file_recovery.location.start);
      }
    }
    if(current_search_space==list_search_space)
    {
#ifdef DEBUG_GET_NEXT_SECTOR
      log_trace("current_search_space==list_search_space=%p (prev=%p,next=%p)\n",
	  current_search_space, current_search_space->list.prev, current_search_space->list.next);
      log_trace("End of media\n");
#endif
      file_recovered=file_finish2(&file_recovery, params, options->paranoid, list_search_space);
      if(file_recovered!=PFSTATUS_BAD)
	get_prev_location_smart(list_search_space, &current_search_space, &offset, file_recovery.location.start);
      if(options->lowmem > 0)
	forget(list_search_space,current_search_space);
    }
    buffer_olddata+=blocksize;
    buffer+=blocksize;
    if(file_recovered!=PFSTATUS_BAD ||
        old_offset+blocksize!=offset ||
        buffer+read_size>buffer_start+buffer_size)
    {
      if(file_recovered!=PFSTATUS_BAD)
        memset(buffer_start,0,blocksize);
      else
        memcpy(buffer_start,buffer_olddata,blocksize);
      buffer_olddata=buffer_start;
      buffer=buffer_olddata + blocksize;
#ifndef DISABLED_FOR_FRAMAC
      if(options->verbose > 1)
      {
        log_verbose("Reading sector %10llu/%llu\n",
	    (unsigned long long)((offset-params->partition->part_offset)/params->disk->sector_size),
	    (unsigned long long)((params->partition->part_size-1)/params->disk->sector_size));
      }
#endif
      if(params->disk->pread(params->disk, buffer, READ_SIZE, offset) != READ_SIZE)
      {
#ifdef HAVE_NCURSES
	wmove(stdscr,11,0);
	wclrtoeol(stdscr);
	wprintw(stdscr,"Error reading sector %10lu\n",
	    (unsigned long)((offset-params->partition->part_offset)/params->disk->sector_size));
#endif
      }
      if(ind_stop==PSTATUS_OK)
      {
        const time_t current_time=time(NULL);
        if(current_time>previous_time)
        {
          previous_time=current_time;
#ifdef HAVE_NCURSES
          ind_stop=photorec_progressbar(stdscr, params->pass, params, offset, current_time);
#endif
	  params->offset=offset;
	  if(need_to_stop!=0 || ind_stop!=PSTATUS_OK)
	  {
#ifndef DISABLED_FOR_FRAMAC
	    log_info("PhotoRec has been stopped\n");
#endif
	    file_recovery_aborted(&file_recovery, params, list_search_space);
#ifndef DISABLED_FOR_FRAMAC
	    free(buffer_start);
#endif
	    return PSTATUS_STOP;
	  }
	  if(current_time >= next_checkpoint)
	    next_checkpoint=regular_session_save(list_search_space, params, options, current_time);
        }
      }
    }
    file_recovered_old=file_recovered;
  } /* end while(current_search_space!=list_search_space) */
#ifndef DISABLED_FOR_FRAMAC
  free(buffer_start);
#endif
#endif
#ifdef HAVE_NCURSES
  photorec_info(stdscr, params->file_stats);
#endif
  return ind_stop;
}
