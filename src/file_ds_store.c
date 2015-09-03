/*

    File: file_ds_store.c

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

static void register_header_check_ds_store(file_stat_t *file_stat);

const file_hint_t file_hint_ds_store= {
  .extension="DS_Store",
  .description="Apple Desktop Services Store",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_ds_store
};

struct ds_store_header
{
  uint32_t magic1;
  uint32_t magic;
  uint32_t offset;
  uint32_t size;
  uint32_t offset2;
  char     unk2[16];
};

static int header_check_ds_store(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct ds_store_header *hdr=(const struct ds_store_header *)buffer;
  if(hdr->offset!=hdr->offset2)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_ds_store.extension;
  file_recovery_new->min_filesize=be32(hdr->offset)+be32(hdr->size);
  return 1;
}

static void register_header_check_ds_store(file_stat_t *file_stat)
{
  static const unsigned char ds_store_header[8]=  {
    0x00, 0x00, 0x00, 0x01, 'B' , 'u' , 'd' , '1'
  };
  register_header_check(0, ds_store_header, sizeof(ds_store_header), &header_check_ds_store, file_stat);
}
