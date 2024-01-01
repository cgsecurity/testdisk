/*

    File: file_psp.c

    Copyright (C) 2008,2011 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_psp)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "common.h"
#include "filegen.h"

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_psp(file_stat_t *file_stat);

const file_hint_t file_hint_psp= {
  .extension="psp",
  .description="Paint Shop Pro Image File",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_psp
};

struct psp_chunk {
  char header[4];
  uint16_t id;
  uint32_t size;
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires file_recovery->data_check==&data_check_psp;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ assigns file_recovery->calculated_file_size;
  @*/
static data_check_t data_check_psp(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@
    @ loop assigns file_recovery->calculated_file_size;
    @ loop variant file_recovery->file_size + buffer_size/2 - (file_recovery->calculated_file_size + 10);
    @*/
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 10 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size + buffer_size/2 - file_recovery->file_size;
    /*@ assert 0 <= i < buffer_size - 10; */
    const struct psp_chunk *chunk=(const struct psp_chunk *)&buffer[i];
    if(memcmp(&buffer[i], "~BK\0", 4) != 0)
      return DC_STOP;
    /* chunk: header, id, total_length */
    file_recovery->calculated_file_size+=10;
    file_recovery->calculated_file_size+=le32(chunk->size);
  }
  return DC_CONTINUE;
}

/*@
  @ requires buffer_size >= 0x28;
  @ requires separation: \separated(&file_hint_psp, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_psp(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const unsigned int ver_major=buffer[0x20]+(buffer[0x21]<<8);
  if(memcmp(&buffer[0x24], "~BK\0", 4)!=0)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_psp.extension;
  if(ver_major>=4 && file_recovery_new->blocksize >= 16)
  {
    file_recovery_new->calculated_file_size=0x24;
    file_recovery_new->data_check=&data_check_psp;
    file_recovery_new->file_check=&file_check_size;
  }
  return 1;
}

static void register_header_check_psp(file_stat_t *file_stat)
{
  register_header_check(0, "Paint Shop Pro Image File\n\032\0\0\0\0\0",  32,  &header_check_psp, file_stat);
}
#endif
