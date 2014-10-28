/*

    File: phbf.c

    Copyright (C) 1998-2014 Christophe GRENIER <grenier@cgsecurity.org>

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
#include <unistd.h>	/* unlink */
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

//#define DEBUG_BF
//#define DEBUG_BF2
#define READ_SIZE 1024*512
extern file_check_list_t file_check_list;
extern uint64_t free_list_allocation_end;

typedef enum { BF_OK=0, BF_STOP=1, BF_EACCES=2, BF_ENOSPC=3, BF_FRAG_FOUND=4, BF_EOF=5, BF_ENOENT=6, BF_ERANGE=7} bf_status_t;

static pstatus_t photorec_bf_aux(struct ph_param *params, file_recovery_t *file_recovery, alloc_data_t *list_search_space, const int phase);
static bf_status_t photorec_bf_frag(struct ph_param *params, file_recovery_t *file_recovery, alloc_data_t *list_search_space, alloc_data_t *start_search_space, const int phase, alloc_data_t **current_search_space, uint64_t *offset, unsigned char *buffer, unsigned char *block_buffer, const unsigned int frag);

static inline void file_recovery_cpy(file_recovery_t *dst, file_recovery_t *src)
{
  memcpy(dst, src, sizeof(*dst));
  dst->location.list.prev=&dst->location.list;
  dst->location.list.next=&dst->location.list;
}

static struct td_list_head *next_file(struct td_list_head *search_walker, const alloc_data_t *list_search_space)
{
  struct td_list_head *tmp_walker;
  for(tmp_walker=search_walker->next;
      tmp_walker!=&list_search_space->list;
      tmp_walker=tmp_walker->next)
  {
    const alloc_data_t *tmp;
    tmp=td_list_entry_const(tmp_walker, const alloc_data_t, list);
    if(tmp->file_stat!=NULL && tmp->file_stat->file_hint!=NULL)
      return tmp_walker;
  }
  return search_walker;
}

static uint64_t get_offset_next_file(const struct td_list_head *search_walker, const alloc_data_t *list_search_space)
{
  const struct td_list_head *tmp_walker;
  for(tmp_walker=search_walker->next;
      tmp_walker!=&list_search_space->list;
      tmp_walker=tmp_walker->next)
  {
    const alloc_data_t *tmp;
    tmp=td_list_entry_const(tmp_walker, const alloc_data_t, list);
    if(tmp->file_stat!=NULL && tmp->file_stat->file_hint!=NULL)
      return tmp->start;
  }
  return 0;
}

pstatus_t photorec_bf(struct ph_param *params, const struct ph_options *options, alloc_data_t *list_search_space)
{
  struct td_list_head *search_walker = NULL;
  struct td_list_head *p= NULL;
  unsigned char *buffer_start;
  const unsigned int blocksize=params->blocksize;
  const unsigned int read_size=(blocksize>65536?blocksize:65536);
  unsigned int buffer_size;
  pstatus_t ind_stop=PSTATUS_OK;
  int pass2=params->pass;
  int phase;
  buffer_size=blocksize+READ_SIZE;
  buffer_start=(unsigned char *)MALLOC(buffer_size);
  for(phase=0; phase<2; phase++)
  {
    const unsigned int file_nbr_phase_old=params->file_nbr;
    for(search_walker=list_search_space->list.prev, p=search_walker->prev;
	search_walker!=&list_search_space->list && ind_stop==PSTATUS_OK;
	p=search_walker->prev)
    {
      alloc_data_t *current_search_space;
      unsigned char *buffer;
      unsigned char *buffer_olddata;
      uint64_t offset;
      int need_to_check_file;
      int go_backward=1;
      file_recovery_t file_recovery;
//      memset(&file_recovery, 0, sizeof(file_recovery_t));
      reset_file_recovery(&file_recovery);
      file_recovery.blocksize=blocksize;
      current_search_space=td_list_entry(search_walker, alloc_data_t, list);
      offset=current_search_space->start;
      buffer_olddata=buffer_start;
      buffer=buffer_olddata + blocksize;
      memset(buffer_olddata, 0, blocksize);
      params->disk->pread(params->disk, buffer, READ_SIZE, offset);
      info_list_search_space(list_search_space, current_search_space, params->disk->sector_size, 0, options->verbose);
#ifdef DEBUG_BF
#endif
      log_flush();

      do
      {
	const uint64_t old_offset=offset;
	need_to_check_file=0;
	if(offset==current_search_space->start)
	{
	  const struct td_list_head *tmpl;
	  file_recovery_t file_recovery_new;
//	  memset(&file_recovery_new, 0, sizeof(file_recovery_t));
	  file_recovery_new.blocksize=blocksize;
	  file_recovery_new.file_stat=NULL;
	  td_list_for_each(tmpl, &file_check_list.list)
	  {
	    const struct td_list_head *tmp;
	    const file_check_list_t *pos=td_list_entry_const(tmpl, const file_check_list_t, list);
	    td_list_for_each(tmp, &pos->file_checks[buffer[pos->offset]].list)
	    {
	      const file_check_t *file_check=td_list_entry_const(tmp, const file_check_t, list);
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
	    if(options->verbose>0)
	    {
	      log_info("%s header found at sector %lu\n",
		  ((file_recovery_new.extension!=NULL && file_recovery_new.extension[0]!='\0')?
		   file_recovery_new.extension:file_recovery_new.file_stat->file_hint->description),
		  (unsigned long)((offset - params->partition->part_offset) / params->disk->sector_size));
	    }
	    if(file_recovery.file_stat==NULL)
	    { /* Header found => file found */
	      file_recovery_cpy(&file_recovery, &file_recovery_new);
	    }
	    else if(file_recovery_new.file_stat->file_hint!=NULL)
	    {
	      if(options->verbose>0)
		log_verbose("New file found => stop the recovery of current file\n");
	      need_to_check_file=1;
	    }
	  }
	  else if(file_recovery.file_stat==NULL)
	    need_to_check_file=1;	/* No header found => no file => stop */
	}
	if(file_recovery.file_stat!=NULL && file_recovery.handle==NULL)
	{ /* Create new file */
	  set_filename(&file_recovery, params);
	  if(file_recovery.file_stat->file_hint->recover==1)
	  {
	    if(!(file_recovery.handle=fopen(file_recovery.filename,"w+b")))
	    { 
	      log_critical("Cannot create file %s: %s\n", file_recovery.filename, strerror(errno));
	      ind_stop=PSTATUS_EACCES;
	    }
	  }
	}
	if(need_to_check_file==0 && file_recovery.handle!=NULL && file_recovery.file_stat!=NULL)
	{
	  if(fwrite(buffer,blocksize,1,file_recovery.handle)<1)
	  { 
	    log_critical("Cannot write to file %s: %s\n", file_recovery.filename, strerror(errno));
	    ind_stop=PSTATUS_ENOSPC;
	  }
	  {
	    data_check_t res=DC_CONTINUE;
	    //	  log_info("add sector %llu\n", (long long unsigned)(offset/512));
	    file_block_append(&file_recovery, list_search_space, &current_search_space, &offset, blocksize, 1);
	    if(file_recovery.data_check!=NULL)
	      res=file_recovery.data_check(buffer_olddata, 2*blocksize, &file_recovery);
	    file_recovery.file_size+=blocksize;
	    if(res==DC_STOP || res==DC_ERROR)
	    { /* EOF found */
	      need_to_check_file=1;
	    }
	  }
	  if(file_recovery.file_stat->file_hint->max_filesize>0 && file_recovery.file_size>=file_recovery.file_stat->file_hint->max_filesize)
	  {
	    log_verbose("File should not be bigger than %llu, stop adding data\n",
		(long long unsigned)file_recovery.file_stat->file_hint->max_filesize);
	    need_to_check_file=1;
	  }
	}
	else
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
	    if(options->verbose>1)
	    {
	      log_verbose("Reading sector %10llu/%llu\n",
		  (unsigned long long)((offset - params->partition->part_offset) / params->disk->sector_size),
		  (unsigned long long)((params->partition->part_size-1) / params->disk->sector_size));
	    }
	    params->disk->pread(params->disk, buffer, READ_SIZE, offset);
	  }
	}
      } while(need_to_check_file==0);
      if(need_to_check_file==1)
      {
	const uint64_t offset_next_file=get_offset_next_file(&current_search_space->list, list_search_space);
	const unsigned int file_nbr_old=params->file_nbr;
	file_recovery.flags=1;
	if(file_finish_bf(&file_recovery, params, list_search_space) < 0)
	{ /* BF */
	  ind_stop=photorec_bf_aux(params, &file_recovery, list_search_space, phase);
	  pass2++;
	  if(file_nbr_old < params->file_nbr && free_list_allocation_end > offset_next_file)
	    go_backward=0;
#ifdef DEBUG_BF
	  log_info("file_nbr_old %u, file_nbr=%u\n", file_nbr_old, params->file_nbr);
	  log_info("free_list_allocation_end %llu, offset_next_file %llu\n",
	      (long long unsigned)free_list_allocation_end,
	      (long long unsigned)offset_next_file);
#endif
	}
      }
      if(file_recovery.handle!=NULL)
      {
	fclose(file_recovery.handle);
	file_recovery.handle=NULL;
	unlink(file_recovery.filename);
      }
      search_walker=p;
      if(go_backward==0)
      {
#ifdef DEBUG_BF
	log_info("go_backward==0\n");
#endif
	search_walker=next_file(search_walker, list_search_space);
      }
    }
    log_info("phase=%d +%u\n", phase, params->file_nbr - file_nbr_phase_old);
  }
  free(buffer_start);
#ifdef HAVE_NCURSES
  photorec_info(stdscr, params->file_stats);
#endif
  return ind_stop;
}

static bf_status_t photorec_bf_pad(struct ph_param *params, file_recovery_t *file_recovery, alloc_data_t *list_search_space, const int phase, const uint64_t file_offset, alloc_data_t **current_search_space, uint64_t *offset, unsigned char *buffer, unsigned char *block_buffer)
{
  const unsigned int blocksize=params->blocksize;
  { /* Add remaining data blocs */
    unsigned int nbr;
    uint64_t offset_error_tmp;
    file_recovery->offset_error=file_offset;
    do
    {
      uint64_t file_size_backup;
      nbr=0;
      offset_error_tmp=file_recovery->offset_error;
#ifdef HAVE_FSEEKO
      if(fseeko(file_recovery->handle, file_recovery->file_size, SEEK_SET) < 0)
#else
      if(fseek(file_recovery->handle, file_recovery->file_size, SEEK_SET) < 0)
#endif
	return BF_ENOENT;
#if 1
      if(file_recovery->data_check!=NULL)
      {
	int stop=0;
	memset(buffer, 0, blocksize);
	while(*current_search_space != list_search_space &&
	    stop==0 &&
	    file_recovery->file_size < file_recovery->offset_error+1000*blocksize)
	{
	  if(
	      ((*current_search_space)->start!=*offset && phase!=1) ||
	      (*current_search_space)->file_stat==NULL ||
	      (*current_search_space)->file_stat->file_hint==NULL)
	  {
	    params->disk->pread(params->disk, block_buffer, blocksize, *offset);
	    if(file_recovery->data_check(buffer, 2*blocksize, file_recovery)!=DC_CONTINUE)
	    {
	      stop=1;
	    }
	    if(fwrite(block_buffer, blocksize, 1, file_recovery->handle)<1)
	    {
	      log_critical("Cannot write to file %s: %s\n", file_recovery->filename, strerror(errno));
	      fclose(file_recovery->handle);
	      file_recovery->handle=NULL;
	      return BF_ENOSPC;
	    }
	    file_block_append(file_recovery, list_search_space, current_search_space, offset, blocksize, 1);
	    file_recovery->file_size+=blocksize;
	    nbr++;
	    memcpy(buffer, block_buffer, blocksize);
	  }
	  else
	    get_next_sector(list_search_space, current_search_space, offset, blocksize);
	}
      }
      else
#endif
      {
	while(*current_search_space != list_search_space &&
	    file_recovery->file_size < file_recovery->offset_error+100*blocksize)
	{
	  if((*current_search_space)->start!=*offset ||
	      (*current_search_space)->file_stat==NULL ||
	      (*current_search_space)->file_stat->file_hint==NULL)
	  {
	    params->disk->pread(params->disk, block_buffer, blocksize, *offset);
	    if(fwrite(block_buffer, blocksize, 1, file_recovery->handle)<1)
	    {
	      log_critical("Cannot write to file %s: %s\n", file_recovery->filename, strerror(errno));
	      fclose(file_recovery->handle);
	      file_recovery->handle=NULL;
	      return BF_ENOSPC;
	    }
	    file_block_append(file_recovery, list_search_space, current_search_space, offset, blocksize, 1);
	    file_recovery->file_size+=blocksize;
	    nbr++;
	  }
	  else
	    get_next_sector(list_search_space, current_search_space, offset, blocksize);
	}
      }
#ifdef DEBUG_BF
      log_trace("BF ");
      file_block_log(file_recovery, 512);
#endif
      file_size_backup=file_recovery->file_size;
      file_recovery->flags=1;
      file_recovery->offset_error=0;
      file_recovery->offset_ok=0;
      file_recovery->calculated_file_size=0;
      file_recovery->file_check(file_recovery);
      file_recovery->file_size=file_size_backup;
#ifdef DEBUG_BF
      log_trace("offset_error=%llu offset_error_tmp=%llu nbr=%u blocksize=%u\n",
	  (long long unsigned) file_recovery->offset_error,
	  (long long unsigned) offset_error_tmp,
	  nbr,
	  blocksize);
#endif
    } while(file_recovery->offset_error > offset_error_tmp + nbr /2 * blocksize);
  }
#ifdef DEBUG_BF
  log_info("photorec_bf_aux %s split file at %llu, error %llu\n",
      file_recovery->filename,
      (long long unsigned)file_offset,
      (long long unsigned)file_recovery->offset_error);
#endif
  if(file_recovery->offset_error==0)
  { /* Recover the file */
#ifdef DEBUG_BF
    log_info("photorec_bf_aux, call file_finish\n");
#endif
    file_finish_bf(file_recovery, params, list_search_space);
    return BF_OK;
  }
  /* FIXME +4096 => +blocksize*/
  /* 21/11/2009: 2 blocksize */
  else if(file_recovery->offset_error / blocksize * blocksize >= (file_offset / blocksize * blocksize + 2 * blocksize))
  { /* Try to recover file composed of multiple fragments */
#ifdef DEBUG_BF
    log_info("%s multiple fragment %llu -> %llu, blocksize %u\n",
	file_recovery->filename,
	(unsigned long long)file_offset,
	(unsigned long long)file_recovery->offset_error,
	blocksize);
    file_block_log(file_recovery, 512);
#endif
    return BF_FRAG_FOUND;
  }
  return BF_ENOENT;
}

static bf_status_t photorec_bf_frag_fast(struct ph_param *params, file_recovery_t *file_recovery, alloc_data_t *list_search_space, alloc_data_t *start_search_space, const int phase, alloc_data_t **current_search_space, uint64_t *offset, unsigned char *buffer, unsigned char *block_buffer, const unsigned int frag)
{
  const unsigned int blocksize=params->blocksize;
  const uint64_t original_offset_error=file_recovery->offset_error;
  const uint64_t original_offset_ok=file_recovery->offset_ok;
  const unsigned int blocs_to_skip=file_recovery->extra / blocksize;
  unsigned int i;
  log_info("photorec_bf_frag_fast %s, original_offset_ok=%llu, original_offset_error=%llu, blocs_to_skip=%d, extra=%llu\n",
      file_recovery->filename,
      (long long unsigned)original_offset_ok,
      (long long unsigned)original_offset_error,
      blocs_to_skip,
      (long long unsigned)file_recovery->extra);
#ifdef DEBUG_BF
  log_info("Frag %u\n", frag);
#endif
/*
 * offset_ok=0
 * offset_error=2
 * blocksize=3
 * 0 1 2 3 4 5 6 7
 * 0 1 5 6 7
 * 0 2 5 6 7
 * 0 3 5 6 7
 * 0 4 5 6 7
 *
 */
  file_recovery->extra=0;
  for(i=0; i<blocs_to_skip; i++)
  {
    unsigned int j,k;
    bf_status_t res;
    *current_search_space=start_search_space;
    *offset=start_search_space->start;
    file_recovery->checkpoint_status=0;
    file_recovery->checkpoint_offset=original_offset_ok/blocksize*blocksize;
    file_recovery->calculated_file_size=0;

    file_recovery->file_size=original_offset_ok/blocksize*blocksize;
    file_block_truncate_and_move(file_recovery, list_search_space, blocksize,
	current_search_space, offset, buffer);

    for(j=0; j<i; j++)
    {
      get_next_sector(list_search_space, current_search_space, offset, blocksize);
    }
    for(k=original_offset_ok/blocksize+1; k<original_offset_error/blocksize; k++)
    {
      params->disk->pread(params->disk, block_buffer, blocksize, *offset);
      if(file_recovery->data_check(buffer, 2*blocksize, file_recovery)!=DC_CONTINUE)
      {
	/* TODO handle this problem */
      }
      if(fwrite(block_buffer, blocksize, 1, file_recovery->handle)<1)
      {
	log_critical("Cannot write to file %s: %s\n", file_recovery->filename, strerror(errno));
	fclose(file_recovery->handle);
	file_recovery->handle=NULL;
	return BF_ENOSPC;
      }
      file_block_append(file_recovery, list_search_space, current_search_space, offset, blocksize, 1);
      file_recovery->file_size+=blocksize;
      memcpy(buffer, block_buffer, blocksize);
    }
    for(; j<blocs_to_skip; j++)
    {
      get_next_sector(list_search_space, current_search_space, offset, blocksize);
    }
    res=photorec_bf_pad(params, file_recovery, list_search_space, phase, file_recovery->offset_error, current_search_space, offset, buffer, block_buffer);
    if(res==BF_FRAG_FOUND)
    {
      if(frag>5)
	return BF_ENOENT;
      res=photorec_bf_frag(params, file_recovery, list_search_space, start_search_space, phase, current_search_space, offset, buffer, block_buffer, frag+1);
    }
    switch(res)
    {
      case BF_OK:
      case BF_STOP:
      case BF_EACCES:
      case BF_ENOSPC:
	return res;
      case BF_EOF:
      case BF_ERANGE:
	return BF_ENOENT;
      default:
	break;
    }
  }
  return BF_ENOENT;
}

static bf_status_t photorec_bf_frag(struct ph_param *params, file_recovery_t *file_recovery, alloc_data_t *list_search_space, alloc_data_t *start_search_space, const int phase, alloc_data_t **current_search_space, uint64_t *offset, unsigned char *buffer, unsigned char *block_buffer, const unsigned int frag)
{
  uint64_t file_offset;
  const uint64_t original_offset_error=file_recovery->offset_error;
  const unsigned int blocksize=params->blocksize;
  int testbf=0;
#if 1
  if(file_recovery->extra > 0 &&
      file_recovery->offset_error / blocksize > file_recovery->offset_ok / blocksize &&
      file_recovery->offset_ok > 0)
  {
    const bf_status_t res=photorec_bf_frag_fast(params, file_recovery, list_search_space, start_search_space, phase, current_search_space, offset, buffer, block_buffer, frag);
//    if(res==BF_ERANGE)
//      res=photorec_bf_frag(params, file_recovery, list_search_space, start_search_space, phase, current_search_space, offset, buffer, block_buffer, frag);
    if(res!=BF_ENOENT)
      return res;
  }
#endif
  log_info("photorec_bf_frag %s, original_offset_ok=%llu, original_offset_error=%llu, blocs_to_skip=%llu\n",
      file_recovery->filename,
      (long long unsigned)file_recovery->offset_ok,
      (long long unsigned)file_recovery->offset_error,
      (long long unsigned)file_recovery->extra);
#ifdef DEBUG_BF
  log_info("Frag %u\n", frag);
#endif
  for(file_offset=original_offset_error/blocksize*blocksize;
      file_offset >= blocksize &&
      (original_offset_error <= file_offset+6*512 ||
       original_offset_error < file_offset+2*blocksize);
      file_offset -= blocksize)
  {
    alloc_data_t *extractblock_search_space;
    uint64_t extrablock_offset;
    int blocs_to_skip;
    file_recovery_t file_recovery_backup;
//    memset(&file_recovery_backup, 0, sizeof(file_recovery_t));
    file_recovery->checkpoint_status=0;
    file_recovery->checkpoint_offset = file_offset;
    file_recovery->file_size=file_offset;
    file_block_truncate_and_move(file_recovery, list_search_space, blocksize,
	current_search_space, offset, buffer);

    /* Set extractblock_search_space & extrablock_offset to the begining of the potential extra block */
    /* FIXME */
#ifdef DEBUG_BF
    log_debug("Set extractblock_search_space & extrablock_offset to the begining of the potential extra block\n");
    log_info("photorec_bf_aux %s split file at %llu\n",
	file_recovery->filename,
	(long long unsigned)file_offset);
    //      file_block_log(file_recovery, 512);
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
    file_recovery->offset_error=0;
#ifdef DEBUG_BF
    log_info("extrablock_offset=%llu sectors\n", (long long unsigned)(extrablock_offset/512));
#endif
    memcpy(&file_recovery_backup, file_recovery, sizeof(file_recovery_backup));
    /* FIXME 16 100 250 */
    for(blocs_to_skip=-2;
	blocs_to_skip<5000 &&
	(file_recovery->offset_error==0 ||
	 (phase==0 && (file_recovery->offset_error >= file_offset || blocs_to_skip<16)) ||
	 (phase==1 && (file_recovery->offset_error + blocksize >= file_offset || blocs_to_skip<100)) ||
	 (phase==2 && blocs_to_skip<10)
	);
	blocs_to_skip++,testbf++)
    {
      bf_status_t res;
      memcpy(file_recovery, &file_recovery_backup, sizeof(file_recovery_backup));
      *current_search_space=extractblock_search_space;
      *offset=extrablock_offset;
#ifdef DEBUG_BF
      log_info("photorec_bf_aux %s split file at %llu, skip=%u\n",
	  file_recovery->filename,
	  (long long unsigned)file_offset, blocs_to_skip);
#endif

      file_block_truncate_and_move(file_recovery, list_search_space, blocksize,
	  current_search_space, offset, buffer);
      {
	static time_t previous_time=0;
	time_t current_time;
	current_time=time(NULL);
	if(current_time>previous_time)
	{
	  pstatus_t ind_stop=PSTATUS_OK;
	  previous_time=current_time;
#ifdef HAVE_NCURSES
	  ind_stop=photorec_progressbar(stdscr, testbf, params,
	      file_recovery->location.start, current_time);
#endif
	  if(ind_stop!=PSTATUS_OK)
	  {
	    file_recovery->flags=0;
	    file_finish_bf(file_recovery, params, list_search_space);
	    log_info("photorec_bf_aux, user choose to stop\n");
	    return BF_STOP;
	  }
	}
      }
      /* Skip extra blocs */
#ifdef DEBUG_BF
      log_debug("Skip %u extra blocs\n", blocs_to_skip);
#endif
      //	log_info("%s Skip %u extra blocs\n", file_recovery->filename, blocs_to_skip);
      if(blocs_to_skip < 0)
      {
	int i;
	for(i=0; i< 2+blocs_to_skip; i++)
	{
	  get_next_header(list_search_space, current_search_space, offset);
	}
      }
      else
      {
	int i;
	for(i=0; i<blocs_to_skip; i++)
	{
	  get_next_sector(list_search_space, current_search_space, offset, blocksize);
	  if(*current_search_space==list_search_space)
	    return BF_ENOENT;
	}
      }

      res=photorec_bf_pad(params, file_recovery, list_search_space, phase, file_offset, current_search_space, offset, buffer, block_buffer);
      if(res==BF_FRAG_FOUND)
      {
	if(frag>5)
	  return BF_ENOENT;
	res=photorec_bf_frag(params, file_recovery, list_search_space, start_search_space, phase, current_search_space, offset, buffer, block_buffer, frag+1);
	if(res==BF_ERANGE)
	  return BF_ENOENT;
	if(res==BF_ENOENT)
	{
#if 0
	  /* TODO: Continue to iterate blocs_to_skip */
	  if(file_recovery->offset_error/blocksize*blocksize >= (file_offset / blocksize * blocksize + 30 * blocksize))
	    return BF_ENOENT;
#else
	  return BF_ENOENT;
#endif
	}
      }
      switch(res)
      {
	case BF_OK:
	case BF_STOP:
	case BF_ENOSPC:
	case BF_EACCES:
	  return res;
	case BF_EOF:
	  return BF_ENOENT;
	default:
	  break;
      }
    }
    if(file_recovery->offset_error > 0 && file_recovery->offset_error < file_offset)
      return BF_ERANGE;
#ifdef DEBUG_BF
    log_info("blocs_to_skip=%u offset_error=0x%llx file_offset=0x%llx\n",
	blocs_to_skip,
	(long long unsigned)file_recovery->offset_error, (long long unsigned)file_offset);
#endif
  }
  return BF_ENOENT;
}

static pstatus_t photorec_bf_aux(struct ph_param *params, file_recovery_t *file_recovery, alloc_data_t *list_search_space, const int phase)
{
  bf_status_t ind_stop;
  alloc_data_t *current_search_space=NULL;
  uint64_t offset=0;
  unsigned char *buffer;
  unsigned char *block_buffer;
  const unsigned int blocksize=params->blocksize;
  buffer=(unsigned char *) MALLOC(2*blocksize);
  block_buffer=&buffer[blocksize];
  file_recovery->file_size=file_recovery->offset_error / blocksize * blocksize;
  file_recovery->offset_error=file_recovery->file_size;
  file_block_truncate_and_move(file_recovery, list_search_space, blocksize,
      &current_search_space, &offset, buffer);
  ind_stop=photorec_bf_frag(params, file_recovery, list_search_space, current_search_space, phase, &current_search_space, &offset, buffer, block_buffer, 0);
  free(buffer);
  (void)file_finish2(file_recovery, params, 1, list_search_space);
  switch(ind_stop)
  {
    case BF_STOP:
    	return PSTATUS_STOP;
    case BF_EACCES:
	return PSTATUS_EACCES;
    case BF_ENOSPC:
	return PSTATUS_ENOSPC;
    default:
	return PSTATUS_OK;
  }
}
