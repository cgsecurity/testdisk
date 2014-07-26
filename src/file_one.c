/*

    File: file_one.c

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

static void register_header_check_one(file_stat_t *file_stat);

const file_hint_t file_hint_one= {
  .extension="one",
  .description="Microsoft OneNote",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_one
};

static int header_check_one(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const uint64_t size=(buffer[196]<<0)+(buffer[197]<<8)+(buffer[198]<<16)+((uint64_t)buffer[199]<<24);
  if(size < 200)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_one.extension;
  file_recovery_new->min_filesize=200;
  file_recovery_new->calculated_file_size=size;
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static void register_header_check_one(file_stat_t *file_stat)
{
  static const unsigned char one_header[16]= {
    0xe4, 0x52, 0x5c, 0x7b, 0x8c, 0xd8, 0xa7, 0x4d,
    0xae, 0xb1, 0x53, 0x78, 0xd0, 0x29, 0x96, 0xd3 };
  register_header_check(0, one_header,sizeof(one_header), &header_check_one, file_stat);
}
