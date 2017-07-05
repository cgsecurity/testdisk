/*

    File: file_afdesign.c

    Copyright (C) 2017 Christophe GRENIER <grenier@cgsecurity.org>

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
#include "log.h"

static void register_header_check_afdesign(file_stat_t *file_stat);

const file_hint_t file_hint_afdesign= {
  .extension="afdesign",
  .description="afdesign",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_afdesign
};

/* http://nickbeeuwsaert.github.io/AFDesignLoad/file_format.html */
struct afdesign_header
{
  uint32_t signature;
  uint32_t version;
  char     prsn[4];
  char 	   info[4];
  uint64_t fat_offset;
  uint64_t fat_length;
  uint64_t zlib_length;
  uint64_t unused1;
  uint32_t creation;
  uint32_t unused2;
  uint64_t fat_entries;
  uint64_t fil_entries;
};

static int header_check_afdesign(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct afdesign_header *hdr=(const struct afdesign_header*)buffer;
  if(memcmp(hdr->prsn, "nsrP", 4)!=0)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_afdesign.extension;
  file_recovery_new->min_filesize=le64(hdr->zlib_length);
  return 1;
}

static void register_header_check_afdesign(file_stat_t *file_stat)
{
  static const unsigned char afdesign_header[4]=  { 0x00, 0xff, 'K' , 'A'   };
  register_header_check(0, afdesign_header, sizeof(afdesign_header), &header_check_afdesign, file_stat);
}
