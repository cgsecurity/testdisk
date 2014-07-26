/*

    File: file_xpt.c

    Copyright (C) 2009 Christophe GRENIER <grenier@cgsecurity.org>
  
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

static void register_header_check_xpt(file_stat_t *file_stat);

const file_hint_t file_hint_xpt= {
  .extension="xpt",
  .description="Mozilla XPCOM Type Library",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_xpt
};


/* Read http://www.mozilla.org/scriptable/typelib_file.html
 * for more information about this file format */
struct TypeLibHeader {
  char                     magic[16];
  uint8_t                  major_version;
  uint8_t                  minor_version;
  uint16_t                 num_interfaces;
  uint32_t                 file_length;
} __attribute__ ((__packed__));

static int header_check_xpt(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct TypeLibHeader *xpt=(const struct TypeLibHeader*)buffer;
  if(be32(xpt->file_length) < 65)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_xpt.extension;
  file_recovery_new->min_filesize=65;
  file_recovery_new->calculated_file_size=be32(xpt->file_length);
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static void register_header_check_xpt(file_stat_t *file_stat)
{
  static const unsigned char xpt_header[16]={
    'X', 'P', 'C', 'O', 'M', '\n', 'T', 'y',
    'p', 'e', 'L', 'i', 'b', '\r', '\n', 0x1a
  };
  register_header_check(0, xpt_header,sizeof(xpt_header), &header_check_xpt, file_stat);
}
