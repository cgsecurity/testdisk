/*

    File: file_3ds.c

    Copyright (C) 2019 Christophe GRENIER <grenier@cgsecurity.org>

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_3ds)
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
static void register_header_check_3ds(file_stat_t *file_stat);

const file_hint_t file_hint_3ds= {
  .extension="3ds",
  .description="3d Studio",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_3ds
};

struct chunk_3ds
{
  uint16_t chunk_id;
  uint32_t next_chunk;
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires buffer_size >= sizeof(struct chunk_3ds);
  @ requires separation: \separated(&file_hint_3ds, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_3ds(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  uint64_t fs;
  const struct chunk_3ds *hdr=(const struct chunk_3ds *)buffer;
  if(buffer_size < 0x12)
    return 0;
  if(buffer[0]!=0x4d || buffer[1]!=0x4d || buffer[0x10]!=0x3d || buffer[0x11]!=0x3d)
    return 0;
  fs=le32(hdr->next_chunk);
  if(fs <= 0x12)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_3ds.extension;
  file_recovery_new->calculated_file_size=fs;
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static void register_header_check_3ds(file_stat_t *file_stat)
{
  static const unsigned char header_3ds[4]=  { 0x02, 0x00, 0x0a, 0x00 };
  register_header_check(6, header_3ds, sizeof(header_3ds), &header_check_3ds, file_stat);
}
#endif
