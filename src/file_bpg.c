/*

    File: file_bpg.c

    Copyright (C) 1998-2007 Christophe GRENIER <grenier@cgsecurity.org>
    Copyright (C) 2016 Dmitry Brant <me@dmitrybrant.com>
  
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
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "filegen.h"

static void register_header_check_bpg(file_stat_t *file_stat);

const file_hint_t file_hint_bpg= {
  .extension="bpg",
  .description="Better Portable Graphics image",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_bpg
};

static int getue32(const unsigned char *buffer, const unsigned int buffer_size, unsigned int *buf_ptr)
{
  unsigned int value = 0;
  unsigned int b;
  int bitsRead = 0;
  while (*buf_ptr < buffer_size)
  {
    b = buffer[*buf_ptr];
    *buf_ptr = *buf_ptr + 1;
    value <<= 7;
    value |= (b & 0x7F);
    if ((b & 0x80) == 0)
      break;
    bitsRead += 7;
    if (bitsRead >= 32)
      break;
  }
  return value;
}

static int header_check_bpg(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  unsigned int buf_ptr = 6;
  // get image width, and throw it away
  int width = getue32(buffer, buffer_size, &buf_ptr);
  printf(">>>> width...%d\n", width);
  // get image height, and throw it away
  int height = getue32(buffer, buffer_size, &buf_ptr);
  printf(">>>> height...%d\n", height);
  int size = getue32(buffer, buffer_size, &buf_ptr);
  printf(">>>> size...%d\n", size);

  reset_file_recovery(file_recovery_new);
  file_recovery_new->calculated_file_size=size;
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  file_recovery_new->extension=file_hint_bpg.extension;
  return 1;
}

static void register_header_check_bpg(file_stat_t *file_stat)
{
  static const unsigned char bpg_header[4]= {'B','P','G',0xFB};
  register_header_check(0, bpg_header,sizeof(bpg_header), &header_check_bpg, file_stat);
}
