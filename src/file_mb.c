/*

    File: file_mb.c

    Copyright (C) 2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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

static void register_header_check_mb(file_stat_t *file_stat);
static int header_check_mb(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_mb= {
  .extension="mb",
  .description="Maya",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_mb
};

static const unsigned char mb_header[8]= {'M','a','y','a','F','O','R','4'};
static const unsigned char mb_header2[8]= {'M','A','Y','A','F','O','R','4'};
static const unsigned char mp_header[8]= {'M','P','L','E','F','O','R','4'};

static void register_header_check_mb(file_stat_t *file_stat)
{
  register_header_check(8, mb_header, sizeof(mb_header), &header_check_mb, file_stat);
  register_header_check(8, mb_header2, sizeof(mb_header2), &header_check_mb, file_stat);
  register_header_check(8, mp_header, sizeof(mp_header), &header_check_mb, file_stat);
}

static int header_check_mb(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(&buffer[8], mb_header, sizeof(mb_header))==0 ||
      memcmp(&buffer[8], mb_header2, sizeof(mb_header2))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_mb.extension;
    file_recovery_new->min_filesize=8;
    file_recovery_new->calculated_file_size=(uint64_t)(buffer[4]<<24)+(buffer[5]<<16)+(buffer[6]<<8)+buffer[7]+8;
    file_recovery_new->data_check=&data_check_size;
    file_recovery_new->file_check=&file_check_size;
    return 1;
  }
  if(memcmp(&buffer[8], mp_header, sizeof(mp_header))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension="mp";
    file_recovery_new->min_filesize=8;
    return 1;
  }
  return 0;
}
