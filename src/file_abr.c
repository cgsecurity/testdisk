/*

    File: file_abr.c

    Copyright (C) 2012,2016 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_abr)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include <assert.h>
#include "types.h"
#include "filegen.h"
#include "common.h"

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_abr(file_stat_t *file_stat);

struct abr_header
{
  char magic[4];
  char info[4];
  uint32_t size;
} __attribute__ ((gcc_struct, __packed__));

const file_hint_t file_hint_abr= {
  .extension="abr",
  .description="Adobe Brush",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_abr
};

/*@
  @ requires file_recovery->data_check==&data_check_abr;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ assigns  file_recovery->calculated_file_size;
  @*/
static data_check_t data_check_abr(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@
    @ loop invariant buffer_size <= 2 * PHOTOREC_MAX_BLOCKSIZE;
    @ loop assigns file_recovery->calculated_file_size;
    @ loop variant file_recovery->file_size + buffer_size/2 - (file_recovery->calculated_file_size + 12);
    @*/
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 12 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size + buffer_size/2 - file_recovery->file_size;
    /*@ assert 0 <= i < buffer_size - 12 ; */
    const struct abr_header *hdr=(const struct abr_header*)&buffer[i];
    /*@ assert \valid_read(hdr); */
    if(memcmp(hdr->magic, "8BIM", 4)!=0)
      return DC_STOP;
    file_recovery->calculated_file_size+=(uint64_t)12 + be32(hdr->size);
  }
  return DC_CONTINUE;
}

/*@
  @ requires buffer_size >= 4 + sizeof(struct abr_header) ;
  @ requires separation: \separated(&file_hint_abr, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns *file_recovery_new;
  @*/
static int header_check_abr(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct abr_header *hdr=(const struct abr_header*)&buffer[4];
  uint64_t i=4;
  assert(buffer_size >= 12);
  /*@
    @ loop assigns i;
    @ loop variant 512 - 12 - i;
    @*/
  while(i < buffer_size - 12 && i < 512 - 12)
  {
    const struct abr_header *h=(const struct abr_header*)&buffer[i];
    if(memcmp(h->magic, "8BIM", 4)!=0)
      return 0;
    i+=(uint64_t)12 + be32(h->size);
  }
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_abr.extension;
  file_recovery_new->min_filesize=(uint64_t)4+12+be32(hdr->size);
  file_recovery_new->calculated_file_size=(uint64_t)4+12+be32(hdr->size);
  if(file_recovery_new->blocksize < 12)
    return 1;
  file_recovery_new->data_check=&data_check_abr;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static void register_header_check_abr(file_stat_t *file_stat)
{
  static const unsigned char abr_header[11]=  {
    0x00, 0x02, '8' , 'B' , 'I' , 'M' , 's' , 'a' ,
    'm' , 'p' , 0x00
  };
  register_header_check(2, abr_header, sizeof(abr_header), &header_check_abr, file_stat);
}
#endif
