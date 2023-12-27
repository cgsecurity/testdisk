/*

    File: file_clip.c

    Copyright (C) 2021 Christophe GRENIER <grenier@cgsecurity.org>

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_clip)
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

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_clip(file_stat_t *file_stat);

const file_hint_t file_hint_clip= {
  .extension="clip",
  .description="Clip Studio Paint",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_clip
};

struct clip_header
{
  char header[8];
  uint64_t size;
} __attribute__ ((gcc_struct, __packed__));

struct clip_chunk
{
  char chunk[4];	/* CHNK */
  char type[4];
  uint64_t length;
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires file_recovery->data_check==&data_check_clip;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ assigns  file_recovery->calculated_file_size;
  @*/
static data_check_t data_check_clip(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@
    @ loop assigns file_recovery->calculated_file_size;
    @ loop variant file_recovery->file_size + buffer_size/2 - (file_recovery->calculated_file_size + 16);
    @*/
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 16 <= file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size + buffer_size/2 - file_recovery->file_size;
    /*@ assert 0 <= i <= buffer_size - 16; */
    const struct clip_chunk *chunk=(const struct clip_chunk *)&buffer[i];
    const uint64_t length=be64(chunk->length);
    if(length >= 0x100000000 ||
	memcmp(&buffer[i], "CHNK", 4)!=0)
      return DC_ERROR;
    file_recovery->calculated_file_size+=(uint64_t)0x10 + length;
    if(length==0)
      return DC_STOP;
  }
  return DC_CONTINUE;
}


/*@
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_clip(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct clip_header *hdr=(const struct clip_header *)buffer;
  const uint64_t size=be64(hdr->size);
  if(size <= 0x18 || size > 0x100000000)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_clip.extension;
  file_recovery_new->data_check=&data_check_clip;
  file_recovery_new->file_check=&file_check_size;
  file_recovery_new->calculated_file_size=0x18;
  file_recovery_new->min_filesize=size;
  return 1;
}

static void register_header_check_clip(file_stat_t *file_stat)
{
  register_header_check(0, "CSFCHUNK", 8, &header_check_clip, file_stat);
}
#endif
