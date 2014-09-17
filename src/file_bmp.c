/*

    File: file_bmp.c

    Copyright (C) 1998-2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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

static void register_header_check_bmp(file_stat_t *file_stat);
static int header_check_bmp(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_bmp= {
  .extension="bmp",
  .description="BMP bitmap image",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_bmp
};

static const unsigned char bmp_header[2]= {'B','M'};

static void register_header_check_bmp(file_stat_t *file_stat)
{
  register_header_check(0, bmp_header,sizeof(bmp_header), &header_check_bmp, file_stat);
}

struct bmp_header
{
  uint16_t magic;
  uint32_t size;
  uint32_t reserved;
  uint32_t offset;
} __attribute__ ((__packed__));

static int header_check_bmp(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct bmp_header *bm=(const struct bmp_header *)buffer;
  if(buffer[0]=='B' && buffer[1]=='M' && bm->reserved==0 &&
      (buffer[14]==12 || buffer[14]==64 || buffer[14]==40 || buffer[14]==52 ||
       buffer[14]==56 || buffer[14]==108 || buffer[14]==124) &&
      buffer[15]==0 && buffer[16]==0 && buffer[17]==0 &&
      le32(bm->offset) < le32(bm->size) &&
      le32(bm->size) >= 65)
  {
    /* See http://en.wikipedia.org/wiki/BMP_file_format */
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_bmp.extension;
    file_recovery_new->min_filesize=65;
    file_recovery_new->calculated_file_size=(uint64_t)le32(bm->size);
    file_recovery_new->data_check=&data_check_size;
    file_recovery_new->file_check=&file_check_size;
    return 1;
  }
  return 0;
}
