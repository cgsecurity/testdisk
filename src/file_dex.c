/*

    File: file_dex.c

    Copyright (C) 2010 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include <ctype.h>
#include "types.h"
#include "filegen.h"
#include "common.h"

static void register_header_check_dex(file_stat_t *file_stat);

const file_hint_t file_hint_dex= {
  .extension="dex",
  .description="Dalvik",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_dex
};

/* More information can be found at https://source.android.com/devices/tech/dalvik/dex-format.html */
struct dex_header
{
  unsigned char magic[8];
  uint32_t	checksum;
  unsigned char signature[20];
  uint32_t	file_size;
  uint32_t	header_size;
  uint32_t	endian_tag;
  uint32_t	link_size;
  uint32_t	link_off;
  uint32_t	map_off;
  uint32_t	strings_ids_size;
  uint32_t	strings_ids_off;
  uint32_t	type_ids_size;
  uint32_t	type_ids_off;
  uint32_t	proto_ids_size;
  uint32_t	proto_ids_off;
  uint32_t	field_ids_size;
  uint32_t	field_ids_off;
  uint32_t	method_ids_size;
  uint32_t	method_ids_off;
  uint32_t	class_def_size;
  uint32_t	class_def_off;
  uint32_t	data_size;
  uint32_t	data_off;
} __attribute__ ((__packed__));

static int header_check_dex(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct dex_header *dex=(const struct dex_header*)buffer;
  if(!isdigit(buffer[4]) || !isdigit(buffer[5]) || !isdigit(buffer[6]) || buffer[7]!=0x00)
    return 0;
  if(le32(dex->header_size) < 0x28)
    return 0;
  if(le32(dex->header_size) >= le32(dex->file_size))
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_dex.extension;
  file_recovery_new->calculated_file_size=le32(dex->file_size);
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static void register_header_check_dex(file_stat_t *file_stat)
{
  static const unsigned char dex_header[4]= {'d','e','x','\n'};
  register_header_check(0, dex_header,sizeof(dex_header), &header_check_dex, file_stat);
}
