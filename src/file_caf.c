/*

    File: file_caf.c

    Copyright (C) 2011 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_caf)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "filegen.h"
#include "common.h"
//#define DEBUG_CAF
#ifdef DEBUG_CAF
#include "log.h"
#endif

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_caf(file_stat_t *file_stat);

const file_hint_t file_hint_caf= {
  .extension="caf",
  .description="Core Audio Format",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_caf
};

/* https://developer.apple.com/library/archive/documentation/MusicAudio/Reference/CAFSpec/CAF_spec/CAF_spec.html */

struct chunk_struct
{
  uint32_t type;
  /* The correct type is int64_t but */
  uint64_t  size;
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires file_recovery->data_check==&data_check_caf;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ terminates \true;
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ assigns file_recovery->calculated_file_size,file_recovery->data_check,file_recovery->file_check;
  @*/
static data_check_t data_check_caf(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@
    @ loop assigns file_recovery->calculated_file_size;
    @ loop variant file_recovery->file_size + buffer_size/2 - (file_recovery->calculated_file_size + 12);
    @*/
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 12 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size + buffer_size/2 - file_recovery->file_size;
    /*@ assert 0 <= i < buffer_size - 12; */
    const struct chunk_struct *chunk=(const struct chunk_struct*)&buffer[i];
    const uint64_t chunk_size=be64(chunk->size);
#ifdef DEBUG_CAF
    log_trace("file_caf.c: %s chunk %c%c%c%c (0x%02x%02x%02x%02x) size %llu, calculated_file_size %llu (0x%llx)\n",
	file_recovery->filename,
        buffer[i],buffer[i+1],buffer[i+2],buffer[i+3],
        buffer[i],buffer[i+1],buffer[i+2],buffer[i+3],
        (long long unsigned)chunk_size,
        (long long unsigned)file_recovery->calculated_file_size,
        (long long unsigned)file_recovery->calculated_file_size);
#endif
    if(buffer[i]==0)
    {
      /* Always true */
      if(file_recovery->calculated_file_size > 0)
	file_recovery->calculated_file_size--;
      return DC_STOP;
    }
    /* The correct type is int64_t, 0x7ffffffffffffff >= PHOTOREC_MAX_FILE_SIZE  */
    if(chunk_size>PHOTOREC_MAX_FILE_SIZE)
    {
      file_recovery->data_check=NULL;
      file_recovery->file_check=NULL;
      return DC_STOP;
    }
    file_recovery->calculated_file_size+=(uint64_t)12+chunk_size;
  }
#ifdef DEBUG_CAF
  log_trace("file_caf.c: new calculated_file_size %llu\n",
      (long long unsigned)file_recovery->calculated_file_size);
#endif
  return DC_CONTINUE;
}

/*@
  @ requires separation: \separated(&file_hint_caf, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ ensures  \result!=0 && file_recovery_new->data_check==&data_check_caf ==> file_recovery_new->calculated_file_size == 8;
  @ assigns  *file_recovery_new;
  @*/
static int header_check_caf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct chunk_struct *chunk=(const struct chunk_struct*)&buffer[8];
  const uint64_t chunk_size=be64(chunk->size);
  if(chunk_size >= PHOTOREC_MAX_FILE_SIZE)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_caf.extension;
  file_recovery_new->min_filesize=8+12;
  if(file_recovery_new->blocksize >= 12)
  {
    file_recovery_new->data_check=&data_check_caf;
    file_recovery_new->file_check=&file_check_size;
    file_recovery_new->calculated_file_size=8;
  }
  /*@ assert file_recovery_new->data_check==&data_check_caf ==> file_recovery_new->calculated_file_size == 8; */
  return 1;
}

static void register_header_check_caf(file_stat_t *file_stat)
{
  static const unsigned char caf_header[12]=  {
    'c' , 'a' , 'f' , 'f' , 0x00, 0x01, 0x00, 0x00,
    'd' , 'e' , 's' , 'c'
  };
  register_header_check(0, caf_header, sizeof(caf_header), &header_check_caf, file_stat);
}
#endif
