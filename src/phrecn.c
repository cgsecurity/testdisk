/*

    File: phrecn.c

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
#include "fat.h"
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
#include "askloc.h"
#include "fat_unformat.h"
#include "pnext.h"
#include "phbf.h"
#include "phnc.h"
#include "phbs.h"
#include "file_found.h"
#include "dfxml.h"

/* #define DEBUG */
/* #define DEBUG_BF */
#define READ_SIZE 1024*512
#define DEFAULT_IMAGE_NAME "image_remaining.dd"

extern const file_hint_t file_hint_tar;
extern const file_hint_t file_hint_dir;
extern file_check_list_t file_check_list;

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

static inline void file_recovery_cpy(file_recovery_t *dst, file_recovery_t *src)
{
  memcpy(dst, src, sizeof(*dst));
  dst->location.list.prev=&dst->location.list;
  dst->location.list.next=&dst->location.list;
}

/* ==================== INLINE FUNCTIONS ========================= */

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

static alloc_data_t *file_add_data(alloc_data_t *data, const uint64_t offset, const unsigned int content)
{
  if(!(data->start <= offset && offset <= data->end))
  {
    log_critical("file_add_data: bug\n");
    return data;
  }
  if(data->start==offset)
  {
    data->data=content;
    return data;
  }
  if(data->data==content)
    return data;
  {
    alloc_data_t *datanext=(alloc_data_t*)MALLOC(sizeof(*datanext));
    memcpy(datanext, data, sizeof(*datanext));
    data->end=offset-1;
    datanext->start=offset;
    datanext->file_stat=NULL;
    datanext->data=content;
    td_list_add(&datanext->list, &data->list);
    return datanext;
  }
}

/* photorec_aux()
 * @param struct ph_param *params
 * @param const struct ph_options *options
 * @param alloc_data_t *list_search_space
 *
 * @returns:
 * 0: Completed
 * 1: Stop by user request
 * 2: Cannot create file
 * 3: No space left
 * >0: params->offset is set
 */

static int photorec_aux(struct ph_param *params, const struct ph_options *options, alloc_data_t *list_search_space)
{
  uint64_t offset;
  unsigned char *buffer_start;
  unsigned char *buffer_olddata;
  unsigned char *buffer;
  time_t start_time;
  time_t previous_time;
  int ind_stop=0;
  unsigned int buffer_size;
  const unsigned int blocksize=params->blocksize; 
  const unsigned int read_size=(blocksize>65536?blocksize:65536);
  alloc_data_t *current_search_space;
  file_recovery_t file_recovery;
  reset_file_recovery(&file_recovery);
  file_recovery.blocksize=blocksize;
  buffer_size=blocksize + READ_SIZE;
  buffer_start=(unsigned char *)MALLOC(buffer_size);
  buffer_olddata=buffer_start;
  buffer=buffer_olddata+blocksize;
  start_time=time(NULL);
  previous_time=start_time;
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
	  const file_check_list_t *pos=td_list_entry(tmpl, file_check_list_t, list);
	  td_list_for_each(tmp, &pos->file_checks[buffer[pos->offset]].list)
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
	  current_search_space=file_found(current_search_space, offset, file_recovery_new.file_stat);
	  file_recovery_new.loc=current_search_space;
	  file_recovery_new.location.start=offset;
          if(options->verbose > 1)
            log_trace("A known header has been found, recovery of the previous file is finished\n");
	  {
	    file_recovered=file_finish2(&file_recovery, params, options, list_search_space, &current_search_space, &offset);
	  }
          reset_file_recovery(&file_recovery);
          if(options->lowmem > 0)
            forget(list_search_space,current_search_space);
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
              file_data_t *dir_list;
              dir_list=dir_fat_aux(buffer,read_size,0,0);
              if(dir_list!=NULL)
              {
		log_info("Sector %lu\n",
		    (unsigned long)(file_recovery.location.start/params->disk->sector_size));
		dir_aff_log(NULL, dir_list);
                delete_list_file(dir_list);
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
            ind_stop=2;
	    params->offset=offset;
          }
        }
      }
    }
    if(file_recovery.file_stat!=NULL)
    {
      int res=1;
    /* try to skip ext2/ext3 indirect block */
      if((params->status==STATUS_EXT2_ON || params->status==STATUS_EXT2_ON_SAVE_EVERYTHING) &&
          file_recovery.file_size_on_disk>=12*blocksize &&
          ind_block(buffer,blocksize)!=0)
      {
	current_search_space=file_add_data(current_search_space, offset, 0);
        file_recovery.file_size_on_disk+=blocksize;
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
	    log_critical("Cannot write to file %s:%s\n", file_recovery.filename, strerror(errno));
	    if(errno==EFBIG)
	    {
	      /* File is too big for the destination filesystem */
	      res=2;
	    }
	    else
	    {
	      /* Warn the user */
	      ind_stop=3;
	      params->offset=file_recovery.location.start;
	    }
	  }
	}
	if(ind_stop==0)
	{
	  current_search_space=file_add_data(current_search_space, offset, 1);
	  if(file_recovery.data_check!=NULL)
	    res=file_recovery.data_check(buffer_olddata,2*blocksize,&file_recovery);
	  file_recovery.file_size+=blocksize;
	  file_recovery.file_size_on_disk+=blocksize;
	  if(res==2)
	  {
	    if(options->verbose > 1)
	      log_trace("EOF found\n");
	  }
	}
      }
      if(res!=2 && file_recovery.file_stat->file_hint->max_filesize>0 && file_recovery.file_size>=file_recovery.file_stat->file_hint->max_filesize)
      {
	res=2;
	log_verbose("File should not be bigger than %llu, stop adding data\n",
	    (long long unsigned)file_recovery.file_stat->file_hint->max_filesize);
      }
      if(res!=2 &&  file_recovery.file_size + blocksize >= PHOTOREC_MAX_SIZE_32 && is_fat(params->partition))
      {
      	res=2;
	log_verbose("File should not be bigger than %llu, stop adding data\n",
	    (long long unsigned)file_recovery.file_stat->file_hint->max_filesize);
      }
      if(res==2)
      {
	file_recovered=file_finish2(&file_recovery, params, options, list_search_space, &current_search_space, &offset);
	reset_file_recovery(&file_recovery);
	if(options->lowmem > 0)
	  forget(list_search_space,current_search_space);
      }
    }
    if(ind_stop>0)
    {
      log_info("PhotoRec has been stopped\n");
      current_search_space=list_search_space;
    }
    else if(file_recovered==0)
    {
      get_next_sector(list_search_space, &current_search_space,&offset,blocksize);
    }
    else if(file_recovered>0)
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
      file_recovered=file_finish2(&file_recovery, params, options, list_search_space, &current_search_space, &offset);
      reset_file_recovery(&file_recovery);
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
#ifdef HAVE_NCURSES
	wmove(stdscr,11,0);
	wclrtoeol(stdscr);
	wprintw(stdscr,"Error reading sector %10lu\n",
	    (unsigned long)((offset-params->partition->part_offset)/params->disk->sector_size));
#endif
      }
#ifdef HAVE_NCURSES
      if(ind_stop==0)
      {
        time_t current_time;
        current_time=time(NULL);
        if(current_time>previous_time)
        {
          previous_time=current_time;
          ind_stop=photorec_progressbar(stdscr, params->pass, params, offset, current_time);
	  if(file_recovery.file_stat!=NULL)
	    params->offset=file_recovery.location.start;
	  else
	    params->offset=offset;
        }
      }
#endif
    }
  } /* end while(current_search_space!=list_search_space) */
  free(buffer_start);
#ifdef HAVE_NCURSES
  photorec_info(stdscr, params->file_stats);
#endif
  return ind_stop;
}

#ifdef HAVE_NCURSES
static void recovery_finished(disk_t *disk, const partition_t *partition, const unsigned int file_nbr, const char *recup_dir, const int ind_stop)
{
  aff_copy(stdscr);
  wmove(stdscr,4,0);
  wprintw(stdscr,"%s", disk->description_short(disk));
  mvwaddstr(stdscr,5,0,msg_PART_HEADER_LONG);
  wmove(stdscr,6,0);
  aff_part(stdscr,AFF_PART_ORDER|AFF_PART_STATUS, disk, partition);
  wmove(stdscr,9,0);
  wclrtoeol(stdscr);
  wprintw(stdscr,"%u files saved in %s directory.\n", file_nbr, recup_dir);
  wmove(stdscr,10,0);
  wclrtoeol(stdscr);
  switch(ind_stop)
  {
    case 0:
      wprintw(stdscr,"Recovery completed.");
      if(file_nbr > 0)
      {
	wmove(stdscr, 12, 0);
	wprintw(stdscr, "You are welcome to donate to support further development and encouragement");
	wmove(stdscr, 13, 0);
	wprintw(stdscr, "http://www.cgsecurity.org/wiki/Donation");
      }
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
  waddstr(stdscr,"[ Quit ]");
  wattroff(stdscr, A_REVERSE);
  wrefresh(stdscr);
  log_flush();
  while(1)
  {
    switch(wgetch(stdscr))
    {
#if defined(KEY_MOUSE) && defined(ENABLE_MOUSE)
      case KEY_MOUSE:
	{
	  MEVENT event;
	  if(getmouse(&event) == OK)
	  {	/* When the user clicks left mouse button */
	    if((event.bstate & BUTTON1_CLICKED) || (event.bstate & BUTTON1_DOUBLE_CLICKED))
	    {
	      if(event.x < sizeof("[ Quit ]") && event.y==22)
		return ;
	    }
	  }
	}
	break;
#endif
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

static void gen_image(const char *filename, disk_t *disk, const alloc_data_t *list_search_space)
{
  struct td_list_head *search_walker = NULL;
  const unsigned int buffer_size=64*512;
  FILE *out;
  unsigned char *buffer;
  if(td_list_empty(&list_search_space->list))
    return ;
  if(!(out=fopen(filename,"w+b")))
    return ;
  buffer=(unsigned char *)MALLOC(buffer_size);
  td_list_for_each(search_walker, &list_search_space->list)
  {
    uint64_t offset;
    alloc_data_t *current_search_space;
    current_search_space=td_list_entry(search_walker, alloc_data_t, list);
    for(offset=current_search_space->start; offset <= current_search_space->end; offset+=buffer_size)
    {
      const unsigned int read_size=(current_search_space->end - offset + 1 < buffer_size ?
	  current_search_space->end - offset + 1 : buffer_size);
      disk->pread(disk, buffer, read_size, offset);
      if(fwrite(buffer, read_size, 1, out)<1)
      {
	log_critical("Cannot write to file %s:%s\n", filename, strerror(errno));
	free(buffer);
	fclose(out);
	return ;
      }
    }
  }
  free(buffer);
  fclose(out);
}

#if 0
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

static void test_files_aux(file_recovery_t *file_recovery, struct ph_param *params, const uint64_t start, const uint64_t end)
{
  uint64_t datasize=end-start+1;
  unsigned char *buffer=(unsigned char *) MALLOC(datasize);
  params->disk->pread(params->disk, buffer, datasize, start);
  if(file_recovery->file_stat==NULL)
  {
    struct td_list_head *tmpl;
    td_list_for_each(tmpl, &file_check_list.list)
    {
      struct td_list_head *tmp;
      const file_check_list_t *pos=td_list_entry(tmpl, file_check_list_t, list);
      td_list_for_each(tmp, &pos->file_checks[buffer[pos->offset]].list)
      {
	const file_check_t *file_check=td_list_entry(tmp, file_check_t, list);
	if((file_check->length==0 || memcmp(buffer + file_check->offset, file_check->value, file_check->length)==0) &&
	    file_check->header_check(buffer, datasize, 0, file_recovery, file_recovery)!=0)
	{
	  file_recovery->file_stat=file_check->file_stat;
	  break;
	}
      }
      if(file_recovery->file_stat!=NULL)
	break;
    }
    if(file_recovery->file_stat==NULL)
    {
      free(buffer);
      return ;
    }
    /* file_recovery->loc is used by file_truncate */
    file_recovery->loc=NULL;
    /* list_free_add, list_space_used, update_search_space, list_truncate, free_list_allocation */
    file_recovery->location.start=start;
  }
  if(file_recovery->handle==NULL)
  {
    set_filename(file_recovery, params);
    file_recovery->handle=fopen(file_recovery->filename, "w+b");
    if(file_recovery->handle==NULL)
    {
      log_critical("Cannot create file %s: %s\n", file_recovery->filename, strerror(errno));
      free(buffer);
      return;
    }
  }
  if(fwrite(buffer, datasize, 1, file_recovery->handle)<1)
  {
    log_critical("Cannot write to file %s:%s\n", file_recovery->filename, strerror(errno));
    fclose(file_recovery->handle);
    file_recovery->handle=NULL;
    free(buffer);
    return;
  }
  list_append_block(&file_recovery->location, start, datasize, 1);
  file_recovery->calculated_file_size=0;
  file_recovery->file_size+=datasize;
  file_recovery->file_size_on_disk+=datasize;
  free(buffer);
}

static void test_files(alloc_data_t *list_search_space, struct ph_param *params)
{
  alloc_data_t *current_search_space=list_search_space;
  uint64_t offset;
  file_recovery_t file_recovery;
  reset_file_recovery(&file_recovery);
  file_recovery.blocksize=512;
  offset=current_search_space->start;
  /* Recover a file with a known location */
  test_files_aux(&file_recovery, params, 1289*512, (1304+1)*512-1);
  test_files_aux(&file_recovery, params, 2881*512, (3259+1)*512-1);
  file_finish(&file_recovery, params, list_search_space, &current_search_space, &offset);

  /* Exclude some sectors from the search space */
  del_search_space(list_search_space, 121407*512, (121416+1)*512-1);
  del_search_space(list_search_space, 121445*512, (121448+1)*512-1);
  del_search_space(list_search_space, 121865*512, (122195+1)*512-1);
}
#endif

int photorec(struct ph_param *params, const struct ph_options *options, alloc_data_t *list_search_space, const unsigned int carve_free_space_only)
{
  int ind_stop=0;
  const unsigned int blocksize_is_known=params->blocksize;
  params->file_nbr=0;
  params->status=STATUS_FIND_OFFSET;
  params->real_start_time=time(NULL);
  params->dir_num=1;
  params->file_stats=init_file_stats(options->list_file_format);
  params->offset=-1;
  if(params->cmd_run!=NULL && params->cmd_run[0]!='\0')
  {
    while(params->cmd_run[0]==',')
      params->cmd_run++;
    if(strncmp(params->cmd_run,"status=unformat",15)==0)
    {
      params->status=STATUS_UNFORMAT;
      params->cmd_run+=15;
    }
    else if(strncmp(params->cmd_run,"status=find_offset",18)==0)
    {
      params->status=STATUS_FIND_OFFSET;
      params->cmd_run+=18;
    }
    else if(strncmp(params->cmd_run,"status=ext2_on_bf",17)==0)
    {
      params->status=STATUS_EXT2_ON_BF;
      params->cmd_run+=17;
    }
    else if(strncmp(params->cmd_run,"status=ext2_on_save_everything",33)==0)
    {
      params->status=STATUS_EXT2_ON_SAVE_EVERYTHING;
      params->cmd_run+=33;
    }
    else if(strncmp(params->cmd_run,"status=ext2_on",14)==0)
    {
      params->status=STATUS_EXT2_ON;
      params->cmd_run+=14;
    }
    else if(strncmp(params->cmd_run,"status=ext2_off_bf",18)==0)
    {
      params->status=STATUS_EXT2_OFF_BF;
      params->cmd_run+=18;
    }
    else if(strncmp(params->cmd_run,"status=ext2_off_save_everything",34)==0)
    {
      params->status=STATUS_EXT2_OFF_SAVE_EVERYTHING;
      params->cmd_run+=34;
    }
    else if(strncmp(params->cmd_run,"status=ext2_off",15)==0)
    {
      params->status=STATUS_EXT2_OFF;
      params->cmd_run+=15;
    }
  }
  else
  {
#ifdef HAVE_NCURSES
    if(options->expert>0 &&
	ask_confirmation("Try to unformat a FAT filesystem (Y/N)")!=0)
      params->status=STATUS_UNFORMAT;
#endif
  }

  screen_buffer_reset();
  log_info("\nAnalyse\n");
  log_partition(params->disk, params->partition);
  if(params->blocksize==0)
    params->blocksize=params->disk->sector_size;

  /* make the first recup_dir */
  params->dir_num=photorec_mkdir(params->recup_dir, params->dir_num);

#ifdef ENABLE_DFXML
  /* Open the XML output file */
  xml_open(params->recup_dir, params->dir_num);
  xml_setup(params->disk, params->partition);
#endif
  
  for(params->pass=0; params->status!=STATUS_QUIT; params->pass++)
  {
    unsigned int old_file_nbr=params->file_nbr;
    log_info("Pass %u (blocksize=%u) ", params->pass, params->blocksize);
    switch(params->status)
    {
      case STATUS_UNFORMAT:			log_info("STATUS_UNFORMAT\n");	break;
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
    aff_copy(stdscr);
    wmove(stdscr, 4, 0);
    wprintw(stdscr, "%s", params->disk->description_short(params->disk));
    mvwaddstr(stdscr, 5, 0, msg_PART_HEADER_LONG);
    wmove(stdscr, 6, 0);
    aff_part(stdscr, AFF_PART_ORDER|AFF_PART_STATUS, params->disk, params->partition);
    wmove(stdscr, 22, 0);
    wattrset(stdscr, A_REVERSE);
    waddstr(stdscr, "  Stop  ");
    wattroff(stdscr, A_REVERSE);
    wrefresh(stdscr);
#endif
    if(params->status==STATUS_UNFORMAT)
    {
      ind_stop=fat_unformat(params, options, list_search_space);
      params->blocksize=blocksize_is_known;
    }
    else if(params->status==STATUS_FIND_OFFSET)
    {
      uint64_t start_offset=0;
      if(blocksize_is_known>0)
      {
	ind_stop=0;
	if(!td_list_empty(&list_search_space->list))
	  start_offset=(td_list_entry(list_search_space->list.next, alloc_data_t, list))->start % params->blocksize;
      }
      else
      {
	ind_stop=photorec_find_blocksize(params, options, list_search_space);
	params->blocksize=find_blocksize(list_search_space, params->disk->sector_size, &start_offset);
      }
#ifdef HAVE_NCURSES
      if(options->expert>0)
	params->blocksize=menu_choose_blocksize(params->blocksize, params->disk->sector_size, &start_offset);
#endif
      update_blocksize(params->blocksize, list_search_space, start_offset);
    }
    else if(params->status==STATUS_EXT2_ON_BF || params->status==STATUS_EXT2_OFF_BF)
    {
      ind_stop=photorec_bf(params, options, list_search_space);
    }
    else
    {
      ind_stop=photorec_aux(params, options, list_search_space);
    }
    session_save(list_search_space, params, options, carve_free_space_only);

    if(ind_stop==3)
    { /* no more space */
#ifdef HAVE_NCURSES
      char *dst;
      char *res;
      dst=strdup(params->recup_dir);
      if(dst!=NULL)
      {
	res=strrchr(dst, '/');
	if(res!=NULL)
	  *res='\0';
      }
      res=ask_location("Warning: no free space available. Please select a destination to save the recovered files.\nDo not choose to write the files to the same partition they were stored on.", "", dst);
      free(dst);
      if(res==NULL)
        params->status=STATUS_QUIT;
      else
      {
        free(params->recup_dir);
        params->recup_dir=(char *)MALLOC(strlen(res)+1+strlen(DEFAULT_RECUP_DIR)+1);
        strcpy(params->recup_dir,res);
        strcat(params->recup_dir,"/");
        strcat(params->recup_dir,DEFAULT_RECUP_DIR);
        free(res);
        /* Create the directory */
        params->dir_num=photorec_mkdir(params->recup_dir,params->dir_num);
      }
#else
      params->status=STATUS_QUIT;
#endif
    }
    else if(ind_stop==2)
    {
      if(interface_cannot_create_file()!=0)
	params->status=STATUS_QUIT;
    }
    else if(ind_stop==1)
    {
      if(session_save(list_search_space, params, options, carve_free_space_only) < 0)
      {
	/* Failed to save the session! */
#ifdef HAVE_NCURSES
	if(ask_confirmation("PhotoRec has been unable to save its session status. Answer Y to really Quit, N to resume the recovery")!=0)
	  params->status=STATUS_QUIT;
#endif
      }
      else
      {
#ifdef HAVE_NCURSES
	if(ask_confirmation("Answer Y to really Quit, N to resume the recovery")!=0)
	  params->status=STATUS_QUIT;
#endif
      }
    }

    if(ind_stop==0)
    {
      params->offset=-1;
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
	  {
	    params->status=STATUS_QUIT;
	    unlink("photorec.ses");
	  }
	  break;
	case STATUS_EXT2_ON_BF:
	  if(options->keep_corrupted_file>0)
	    params->status=STATUS_EXT2_ON_SAVE_EVERYTHING;
	  else
	  {
	    params->status=STATUS_QUIT;
	    unlink("photorec.ses");
	  }
	  break;
	case STATUS_EXT2_OFF:
	  if(options->paranoid>1)
	    params->status=STATUS_EXT2_OFF_BF;
	  else if(options->paranoid==1 && options->keep_corrupted_file>0)
	    params->status=STATUS_EXT2_OFF_SAVE_EVERYTHING;
	  else
	  {
	    params->status=STATUS_QUIT;
	    unlink("photorec.ses");
	  }
	  break;
	case STATUS_EXT2_OFF_BF:
	  if(options->keep_corrupted_file>0)
	    params->status=STATUS_EXT2_OFF_SAVE_EVERYTHING;
	  else
	  {
	    params->status=STATUS_QUIT;
	    unlink("photorec.ses");
	  }
	  break;
	default:
	  params->status=STATUS_QUIT;
	  unlink("photorec.ses");
	  break;
      }
    }
    {
      const time_t current_time=time(NULL);
      log_info("Elapsed time %uh%02um%02us\n",
          (unsigned)((current_time-params->real_start_time)/60/60),
          (unsigned)((current_time-params->real_start_time)/60%60),
          (unsigned)((current_time-params->real_start_time)%60));
    }
    update_stats(params->file_stats, list_search_space);
    if(params->pass>0)
    {
      log_info("Pass %u +%u file%s\n",params->pass,params->file_nbr-old_file_nbr,(params->file_nbr-old_file_nbr<=1?"":"s"));
      write_stats_log(params->file_stats);
    }
    log_flush();
  }
#ifdef HAVE_NCURSES
  if(options->expert>0 && !td_list_empty(&list_search_space->list))
  {
    char msg[256];
    uint64_t data_size=0;
    struct td_list_head *search_walker = NULL;
    td_list_for_each(search_walker, &list_search_space->list)
    {
      alloc_data_t *current_search_space;
      current_search_space=td_list_entry(search_walker, alloc_data_t, list);
      data_size += current_search_space->end - current_search_space->start + 1;
    }
    snprintf(msg, sizeof(msg),
	"Create an image_remaining.dd (%u MB) file with the unknown data (Answer N if not sure) (Y/N)",
	(unsigned int)(data_size/1000/1000));
    if(ask_confirmation("%s", msg)!=0)
    {
      char *filename;
      char *res;
      char *dst_path=strdup(params->recup_dir);
      res=strrchr(dst_path, '/');
      if(res!=NULL)
	*res='\0';
      else
      {
	dst_path[0]='.';
	dst_path[1]='\0';
      }
      filename=(char *)MALLOC(strlen(dst_path) + 1 + strlen(DEFAULT_IMAGE_NAME) + 1);
      strcpy(filename, dst_path);
      strcat(filename, "/");
      strcat(filename, DEFAULT_IMAGE_NAME);
      gen_image(filename, params->disk, list_search_space);
      free(filename);
      free(dst_path);
    }
  }
#endif
  info_list_search_space(list_search_space, NULL, params->disk->sector_size, options->keep_corrupted_file, options->verbose);
  /* Free memory */
  free_search_space(list_search_space);
#ifdef HAVE_NCURSES
  if(params->cmd_run==NULL)
    recovery_finished(params->disk, params->partition, params->file_nbr, params->recup_dir, ind_stop);
#endif
  free(params->file_stats);
  params->file_stats=NULL;
  free_header_check();
#ifdef ENABLE_DFXML
  xml_shutdown();
  xml_close();
#endif
  return 0;
}

#ifdef HAVE_NCURSES
static void interface_options_photorec_ncurses(struct ph_options *options)
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
    switch(options->paranoid)
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
    menuOptions[1].name=options->allow_partial_last_cylinder?"Allow partial last cylinder : Yes":"Allow partial last cylinder : No";
    menuOptions[2].name=options->keep_corrupted_file?"Keep corrupted files : Yes":"Keep corrupted files : No";
    menuOptions[3].name=options->mode_ext2?"ext2/ext3 mode: Yes":"ext2/ext3 mode : No";
    menuOptions[4].name=options->expert?"Expert mode : Yes":"Expert mode : No";
    menuOptions[5].name=options->lowmem?"Low memory: Yes":"Low memory: No";
    aff_copy(stdscr);
    car=wmenuSelect_ext(stdscr, 23, INTER_OPTION_Y, INTER_OPTION_X, menuOptions, 0, "PAKELQ", MENU_VERT|MENU_VERT_ARROW2VALID, &menu,&real_key);
    switch(car)
    {
      case 'p':
      case 'P':
	if(options->paranoid<2)
	  options->paranoid++;
	else
	  options->paranoid=0;
	break;
      case 'a':
      case 'A':
	options->allow_partial_last_cylinder=!options->allow_partial_last_cylinder;
	break;
      case 'k':
      case 'K':
	options->keep_corrupted_file=!options->keep_corrupted_file;
	break;
      case 's':
      case 'S':
	options->mode_ext2=!options->mode_ext2;
	break;
      case 'e':
      case 'E':
	options->expert=!options->expert;
	break;
      case 'l':
      case 'L':
	options->lowmem=!options->lowmem;
	break;
      case key_ESC:
      case 'q':
      case 'Q':
	return;
    }
  }
}
#endif

void interface_options_photorec(struct ph_options *options, char **current_cmd)
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
	options->paranoid=0;
      }
      else if(strncmp(*current_cmd,"paranoid_bf",11)==0)
      {
	(*current_cmd)+=11;
	options->paranoid=2;
      }
      else if(strncmp(*current_cmd,"paranoid",8)==0)
      {
	(*current_cmd)+=8;
	options->paranoid=1;
      }
      /* TODO: allow_partial_last_cylinder */
      /* keep_corrupted_file */
      else if(strncmp(*current_cmd,"keep_corrupted_file_no",22)==0)
      {
	(*current_cmd)+=22;
	options->keep_corrupted_file=0;
      }
      else if(strncmp(*current_cmd,"keep_corrupted_file",19)==0)
      {
	(*current_cmd)+=19;
	options->keep_corrupted_file=1;
      }
      /* mode_ext2 */
      else if(strncmp(*current_cmd,"mode_ext2",9)==0)
      {
	(*current_cmd)+=9;
	options->mode_ext2=1;
      }
      /* expert */
      else if(strncmp(*current_cmd,"expert",6)==0)
      {
	(*current_cmd)+=6;
	options->expert=1;
      }
      /* lowmem */
      else if(strncmp(*current_cmd,"lowmem",6)==0)
      {
	(*current_cmd)+=6;
	options->lowmem=1;
      }
      else
	keep_asking=0;
    } while(keep_asking>0);
  }
  else
  {
#ifdef HAVE_NCURSES
    interface_options_photorec_ncurses(options);
#endif
  }
  /* write new options to log file */
  log_info("New options :\n Paranoid : %s\n", options->paranoid?"Yes":"No");
  log_info(" Brute force : %s\n", ((options->paranoid)>1?"Yes":"No"));
  log_info(" Allow partial last cylinder : %s\n Keep corrupted files : %s\n ext2/ext3 mode : %s\n Expert mode : %s\n Low memory : %s\n",
      options->allow_partial_last_cylinder?"Yes":"No",
      options->keep_corrupted_file?"Yes":"No",
      options->mode_ext2?"Yes":"No",
      options->expert?"Yes":"No",
      options->lowmem?"Yes":"No");
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
#if defined(KEY_MOUSE) && defined(ENABLE_MOUSE)
  mousemask(ALL_MOUSE_EVENTS, NULL);
#endif
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
	wprintw(stdscr,">[%c] %-4s %s", (files_enable[i].enable==0?' ':'X'),
	    (files_enable[i].file_hint->extension!=NULL?
	     files_enable[i].file_hint->extension:""),
	    files_enable[i].file_hint->description);
	wattroff(stdscr, A_REVERSE);
      }
      else
      {
	wprintw(stdscr," [%c] %-4s %s", (files_enable[i].enable==0?' ':'X'),
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
#if defined(KEY_MOUSE) && defined(ENABLE_MOUSE)
    if(command == KEY_MOUSE)
    {
      MEVENT event;
      if(getmouse(&event) == OK)
      {	/* When the user clicks left mouse button */
	if((event.bstate & BUTTON1_CLICKED) || (event.bstate & BUTTON1_DOUBLE_CLICKED))
	{
	  if(event.y >=6 && event.y<6+INTER_FSELECT)
	  {
	    if(((event.bstate & BUTTON1_CLICKED) && current_element_num == event.y-6-offset) ||
	      (event.bstate & BUTTON1_DOUBLE_CLICKED))
	      command='+';
	    /* Disk selection */
	    while(current_element_num > event.y-(6-offset) && current_element_num>0)
	    {
		current_element_num--;
	    }
	    while(current_element_num < event.y-(6-offset) && files_enable[current_element_num+1].file_hint!=NULL)
	    {
		current_element_num++;
	    }
	  }
	  else if(event.y==5 && event.x>=4 && event.x<=4+sizeof("Previous") &&
	      offset>0)
	    command=KEY_PPAGE;
	  else if(event.y==6+INTER_FSELECT && event.x>=4 && event.x<=4+sizeof("Next") &&
	      files_enable[i].file_hint!=NULL)
	    command=KEY_NPAGE;
	  else
	    command = menu_to_command(LINES-1, INTER_FSELECT_Y, INTER_FSELECT_X, menuAdv, 8,
		"q", MENU_BUTTON | MENU_ACCEPT_OTHERS, event.y, event.x);
	}
      }
    }
#endif
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
