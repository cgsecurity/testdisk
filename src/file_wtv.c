/*

    File: file_wtv.c

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_wtv)
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
static void register_header_check_wtv(file_stat_t *file_stat);

const file_hint_t file_hint_wtv = {
  .extension = "wtv",
  .description = "Windows Media Center TV",
  .max_filesize = PHOTOREC_MAX_FILE_SIZE,
  .recover = 1,
  .enable_by_default = 1,
  .register_header_check = &register_header_check_wtv
};

/*@
  @ requires buffer_size >= 0x60;
  @ requires separation: \separated(&file_hint_wtv, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @*/
static int header_check_wtv(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const uint32_t *block_ptr = (const uint32_t *)(&buffer[0x5c]);
  const uint32_t block = le32(*block_ptr);
  if(block == 0)
    return 0;
  if(file_recovery->file_stat != NULL && file_recovery->file_stat->file_hint == &file_hint_wtv && file_recovery->file_size <= 0x3000)
  {
    if(header_ignored_adv(file_recovery, file_recovery_new) == 0)
      return 0;
  }
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension = file_hint_wtv.extension;
  file_recovery_new->calculated_file_size=(uint64_t)block<<12;
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static void register_header_check_wtv(file_stat_t *file_stat)
{
  static const unsigned char wtv_header[16] = {
    0xb7, 0xd8, 0x00, ' ', '7', 'I', 0xda, 0x11,
    0xa6, 'N', 0x00, 0x07, 0xe9, 0x5e, 0xad, 0x8d
  };
  register_header_check(0, wtv_header, sizeof(wtv_header), &header_check_wtv, file_stat);
}
#endif
