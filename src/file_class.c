/*

    File: file_class.c

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
#include "common.h"
#include "filegen.h"

static void register_header_check_class(file_stat_t *file_stat);
static int header_check_class(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_class= {
  .extension="class",
  .description="Java Class",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_class
};

/* http://en.wikipedia.org/wiki/Class_(file_format) */
static const unsigned char class_magic[4]= { 0xCA, 0xFE, 0xBA, 0xBE };

struct class_header {
  uint32_t magic_number;
  uint16_t minor_version;
  uint16_t major_version;
  uint16_t constant_pool_count;
};

static void register_header_check_class(file_stat_t *file_stat)
{
  register_header_check(0, class_magic, sizeof(class_magic), &header_check_class, file_stat);
}

static int header_check_class(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct class_header *cafe=(const struct class_header *)buffer;
  if(be32(cafe->magic_number)==0xCafeBabe &&
      be16(cafe->major_version) >= 45 && be16(cafe->major_version) <= 100 &&
      be16(cafe->constant_pool_count) > 0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_class.extension;
    return 1;
  }
  return 0;
}
