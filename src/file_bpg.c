/*

    File: file_bpg.c

    Copyright (C) 1998-2007 Christophe GRENIER <grenier@cgsecurity.org>
    Contribution by Dmitry Brant <me@dmitrybrant.com>
  
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
#include "common.h"

static void register_header_check_bpg(file_stat_t *file_stat);
static int header_check_bpg(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_bpg= {
  .extension="bpg",
  .description="Better Portable Graphics (BPG) image",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_bpg
};

static const unsigned char bpg_header[4]= {'B','P','G',0xFB};

static void register_header_check_bpg(file_stat_t *file_stat)
{
  register_header_check(0, bpg_header, sizeof(bpg_header), &header_check_bpg, file_stat);
}

static int getue32(const unsigned char *buffer, const unsigned int buffer_size, unsigned int *buf_ptr)
{
  unsigned int value = 0;
  unsigned int b;
  int bitsRead = 0;
  while (*buf_ptr < buffer_size)
  {
    b = buffer[*buf_ptr++];
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
  if(buffer[0]=='B' && buffer[1]=='P' && buffer[2]=='G' && buffer[3]==0xFB)
  {
    unsigned int buf_ptr = 6;
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_bpg.extension;
    file_recovery_new->min_filesize=100;
	// get image width, and throw it away
	getue32(buffer, buffer_size, &buf_ptr);
	// get image height, and throw it away
	getue32(buffer, buffer_size, &buf_ptr);
    file_recovery_new->calculated_file_size=(uint64_t)getue32(buffer, buffer_size, &buf_ptr);
    file_recovery_new->data_check=&data_check_size;
    file_recovery_new->file_check=&file_check_size;
    return 1;
  }
  return 0;
}
