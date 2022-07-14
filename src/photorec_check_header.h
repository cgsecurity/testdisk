/*

    File: photorec_check_header.h

    Copyright (C) 2002-2018 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifndef _PHOTOREC_CHECK_HEADER_H
#define _PHOTOREC_CHECK_HEADER_H
#ifdef __cplusplus
extern "C" {
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_tar)
extern const file_hint_t file_hint_tar;
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dir)
extern const file_hint_t file_hint_dir;
#endif
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

/*@
  @ requires \valid_read(buffer + (0 .. read_size-1));
  @*/
static void photorec_dir_fat(const unsigned char *buffer, const unsigned int read_size, const unsigned long long sector)
{
  file_info_t dir_list;
  TD_INIT_LIST_HEAD(&dir_list.list);
  dir_fat_aux(buffer, read_size, 0, &dir_list);
  if(!td_list_empty(&dir_list.list))
  {
#ifndef __FRAMAC__
    log_info("Sector %llu\n", sector);
#endif
    dir_aff_log(NULL, &dir_list);
    delete_list_file(&dir_list);
  }
}

/*@
  @ requires \valid_read(file_recovery_new);
  @ requires valid_file_recovery(file_recovery_new);
  @ requires \valid(file_recovery);
  @ requires valid_file_recovery(file_recovery);
  @ requires \valid(params);
  @ requires \valid(params->disk);
  @ requires \valid_read(options);
  @ requires \valid(list_search_space);
  @ requires \valid_read(buffer + (0 .. params->blocksize -1));
  @ requires params->disk->sector_size > 0;
  @ requires \separated(file_recovery_new, file_recovery, params, options, list_search_space, buffer+(..), file_recovered, &errno);
  @ ensures \result == PSTATUS_OK || \result == PSTATUS_EACCES;
  @*/
// ensures *file_recovered == PFSTATUS_BAD || *file_recovered == PFSTATUS_OK || *file_recovered == PFSTATUS_OK_TRUNCATED;
static pstatus_t photorec_header_found(const file_recovery_t *file_recovery_new, file_recovery_t *file_recovery, struct ph_param *params, const struct ph_options *options, alloc_data_t *list_search_space, const unsigned char *buffer, pfstatus_t *file_recovered, const uint64_t offset)
{
  *file_recovered=PFSTATUS_BAD;
  if(file_recovery_new->file_stat==NULL || file_recovery_new->file_stat->file_hint==NULL)
    return PSTATUS_OK;
  if(file_recovery->file_stat!=NULL)
  {
    /*@ assert valid_file_stat(file_recovery->file_stat); */
#ifndef __FRAMAC__
    if(options->verbose > 1)
      log_trace("A known header has been found, recovery of the previous file is finished\n");
#endif
    *file_recovered=file_finish2(file_recovery, params, options->paranoid, list_search_space);
    if(*file_recovered==PFSTATUS_OK_TRUNCATED)
      return PSTATUS_OK;
  }
  file_recovery_cpy(file_recovery, file_recovery_new);
#ifndef __FRAMAC__
  if(options->verbose > 1)
  {
    log_info("%s header found at sector %lu\n",
	((file_recovery->extension!=NULL && file_recovery->extension[0]!='\0')?
	 file_recovery->extension:file_recovery->file_stat->file_hint->description),
	(unsigned long)((file_recovery->location.start-params->partition->part_offset)/params->disk->sector_size));
    log_info("file_recovery->location.start=%lu\n",
	(unsigned long)(file_recovery->location.start/params->disk->sector_size));
  }
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dir)
  if(file_recovery->file_stat->file_hint==&file_hint_dir && options->verbose > 0)
  { /* FAT directory found, list the file */
    const unsigned int blocksize=params->blocksize;
    const unsigned int read_size=(blocksize>65536?blocksize:65536);
    photorec_dir_fat(buffer, read_size, file_recovery->location.start/params->disk->sector_size);
  }
#endif
  set_filename(file_recovery, params);
  if(file_recovery->file_stat->file_hint->recover==1)
  {
#if defined(__CYGWIN__) || defined(__MINGW32__)
    file_recovery->handle=fopen_with_retry(file_recovery->filename,"w+b");
#else
    file_recovery->handle=fopen(file_recovery->filename,"w+b");
#endif
    if(!file_recovery->handle)
    {
#ifndef __FRAMAC__
      log_critical("Cannot create file %s: %s\n", file_recovery->filename, strerror(errno));
#endif
      params->offset=offset;
      return PSTATUS_EACCES;
    }
  }
  return PSTATUS_OK;
}

/*@
  @ requires \valid(file_recovery);
  @ requires valid_file_recovery(file_recovery);
  @ requires \valid(params);
  @ requires valid_ph_param(params);
  @ requires \valid_read(options);
  @ requires valid_list_search_space(list_search_space);
  @ requires \valid_read(buffer + (0 .. params->blocksize -1));
  @ requires \valid(file_recovered);
  @ requires \separated(file_recovery, params, options, list_search_space, buffer, file_recovered);
  @ decreases 0;
  @ ensures  valid_file_recovery(file_recovery);
  @*/
// ensures  valid_list_search_space(list_search_space);
inline static pstatus_t photorec_check_header(file_recovery_t *file_recovery, struct ph_param *params, const struct ph_options *options, alloc_data_t *list_search_space, const unsigned char *buffer, pfstatus_t *file_recovered, const uint64_t offset)
{
  const struct td_list_head *tmpl;
  const unsigned int blocksize=params->blocksize;
  const unsigned int read_size=(blocksize>65536?blocksize:65536);
  file_recovery_t file_recovery_new;
  /*@ assert valid_file_recovery(file_recovery); */
  file_recovery_new.blocksize=blocksize;
  file_recovery_new.location.start=offset;
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_tar)
  if(file_recovery->file_stat!=NULL && file_recovery->file_stat->file_hint==&file_hint_tar &&
      is_valid_tar_header((const struct tar_posix_header *)(buffer-0x200)))
  { /* Currently saving a tar, do not check the data for know header */
#ifndef __FRAMAC__
    if(options->verbose > 1)
    {
      log_verbose("Currently saving a tar file, sector %lu.\n",
	  (unsigned long)((offset-params->partition->part_offset)/params->disk->sector_size));
    }
#endif
    /*@ assert valid_file_recovery(file_recovery); */
    return PSTATUS_OK;
  }
#endif
  file_recovery_new.file_stat=NULL;
  file_recovery_new.location.start=offset;
  /*@ loop invariant valid_file_recovery(file_recovery); */
  td_list_for_each(tmpl, &file_check_list.list)
  {
    const struct td_list_head *tmp;
    const file_check_list_t *pos=td_list_entry_const(tmpl, const file_check_list_t, list);
    td_list_for_each(tmp, &pos->file_checks[buffer[pos->offset]].list)
    {
      const file_check_t *file_check=td_list_entry_const(tmp, const file_check_t, list);
      /*@ assert \valid_function(file_check->header_check); */
      /*@ assert valid_file_check_node(file_check); */
      if((file_check->length==0 || memcmp(buffer + file_check->offset, file_check->value, file_check->length)==0) &&
	  file_check->header_check(buffer, read_size, 0, file_recovery, &file_recovery_new)!=0)
      {
	file_recovery_new.file_stat=file_check->file_stat;
	/*@ assert valid_file_recovery(&file_recovery_new); */
	return photorec_header_found(&file_recovery_new, file_recovery, params, options, list_search_space, buffer, file_recovered, offset);
      }
    }
  }
  /*@ assert valid_file_recovery(file_recovery); */
  return PSTATUS_OK;
}
#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
