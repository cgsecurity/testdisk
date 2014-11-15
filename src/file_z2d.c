/*

    File: file_z2d.c

    Copyright (C) 2012 Christophe GRENIER <grenier@cgsecurity.org>
  
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

static void register_header_check_z2d(file_stat_t *file_stat);

const file_hint_t file_hint_z2d= {
  .extension="z2d",
  .description="ZeroCad",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_z2d
};

static const unsigned char z2d_header[2]=  { 0xc3, 0x40 };

static int header_check_z2d(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(buffer[0x28]==0xc3 && buffer[0x29]==0x40 &&
      buffer[0x30]==0xc3 && buffer[0x31]==0x40 &&
      buffer[0x38]==0xbf && buffer[0x39]==0x40 &&
      buffer[0x40]==0xbf && buffer[0x41]==0x40 &&
      buffer[0x48]==0xb7 && buffer[0x49]==0x40)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_z2d.extension;
    return 1;
  }
  return 0;
}

static void register_header_check_z2d(file_stat_t *file_stat)
{
  register_header_check(0x28, z2d_header, sizeof(z2d_header), &header_check_z2d, file_stat);
}
