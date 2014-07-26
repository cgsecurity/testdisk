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
#include "common.h"

static void register_header_check_mb(file_stat_t *file_stat);

const file_hint_t file_hint_mb= {
  .extension="mb",
  .description="Maya",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_mb
};

struct maya_header
{
  char magic[4];
  uint32_t size;
  char magic2[8];
} __attribute__ ((__packed__));

static int header_check_mb(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct maya_header *hdr=(const struct maya_header *)buffer;
  if(memcmp(buffer,"FOR4",4)!=0 || be32(hdr->size) < 8)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_mb.extension;
  file_recovery_new->min_filesize=16;
  file_recovery_new->calculated_file_size=be32(hdr->size)+8;
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static int header_check_mp(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(buffer,"FOR4",4)!=0)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension="mp";
  file_recovery_new->min_filesize=16;
  return 1;
}

static void register_header_check_mb(file_stat_t *file_stat)
{
  register_header_check(8, "MayaFOR4", 8, &header_check_mb, file_stat);
  register_header_check(8, "MAYAFOR4", 8, &header_check_mb, file_stat);
  register_header_check(8, "MPLEFOR4", 8, &header_check_mp, file_stat);
}
