/*

    File: file_dst.c

    Copyright (C) 2016 Christophe GRENIER <grenier@cgsecurity.org>

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dst)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "filegen.h"

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_dst(file_stat_t *file_stat);

const file_hint_t file_hint_dst= {
  .extension="dst",
  .description="Tajima",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_dst
};

/*@
  @ requires buffer_size >= 512;
  @ requires separation: \separated(&file_hint_dst, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_dst(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  unsigned int stitch_count=0;
  char buf[8];
  memcpy(&buf, &buffer[23], 7);
  buf[7]='\0';
  if(memcmp(buffer, "LA:",3)!=0 || memcmp(&buffer[30], "\rCO:", 4)!=0)
    return 0;
  if(sscanf(&buf[0], "%u", &stitch_count) < 0)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_dst.extension;
  /* https://community.kde.org/Projects/Liberty/File_Formats/Tajima_Ternary */
  /* The header is 512 bytes */
  file_recovery_new->calculated_file_size=(uint64_t)512 + (uint64_t)3*stitch_count;
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static void register_header_check_dst(file_stat_t *file_stat)
{
  register_header_check(0x13, "\rST:", 4, &header_check_dst, file_stat);
}
#endif
