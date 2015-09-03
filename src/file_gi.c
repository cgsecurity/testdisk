/*

    File: file_gi.c

    Copyright (C) 2015 Christophe GRENIER <grenier@cgsecurity.org>

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

static void register_header_check_gi(file_stat_t *file_stat);

const file_hint_t file_hint_gi= {
  .extension="gi",
  .description="Roxio Creator",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_gi
};

struct header_gi
{
  char magic[12];
  uint64_t size;
} __attribute__ ((gcc_struct, __packed__));

static int header_check_gi(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct header_gi *hdr=(const struct header_gi *)buffer;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_gi.extension;
  file_recovery_new->calculated_file_size=le64(hdr->size)+20;
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static void register_header_check_gi(file_stat_t *file_stat)
{
  static const unsigned char gi_header[12]=  {
    0xda, 0xda, 0xfe, 0xfe, 0x00, 0x06, 0x1c, 0x04,
    0x00, 0x04, 0x00, 0x00
  };
  register_header_check(0, gi_header, sizeof(gi_header), &header_check_gi, file_stat);
}
