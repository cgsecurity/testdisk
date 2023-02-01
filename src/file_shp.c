/*

    File: file_shp.c

    Copyright (C) 2023 Grzegorz Szymaszek <gszymaszek@short.pl>

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_shp)
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

static void register_header_check_shp(file_stat_t *file_stat);

const file_hint_t file_hint_shp= {
  .extension="shp",
  .description="Shapefile",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_shp
};

static const uint8_t shp_header[4] = {0x00, 0x00, 0x27, 0x0a};

/* https://en.wikipedia.org/wiki/Shapefile */
struct shp_header
{
  int32_t magic;
  int32_t reserved[5];
  int32_t size;
  int32_t version;
  int32_t shape_type;
} __attribute__ ((gcc_struct, __packed__));

static int header_check_shp(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct shp_header *shp=(const struct shp_header *)buffer;
  (void) buffer_size;
  (void) safe_header_only;
  (void) file_recovery;

  if(buffer[0]!=0 || buffer[1]!=0 || buffer[2]!=0x27 || buffer[3]!=0x0a)
    return 0;
  if(be32(shp->size) >= 100)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_shp.extension;
    file_recovery_new->min_filesize=100;
    file_recovery_new->calculated_file_size=(uint64_t)be32(shp->size);
    file_recovery_new->data_check=&data_check_size;
    file_recovery_new->file_check=&file_check_size;
    return 1;
  }
  return 0;
}

static void register_header_check_shp(file_stat_t *file_stat)
{
  register_header_check(0, shp_header, sizeof(shp_header), &header_check_shp, file_stat);
}
#endif
