/*

    File: file_hds.c

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

static void register_header_check_hds(file_stat_t *file_stat);

const file_hint_t file_hint_hds= {
  .extension="hds",
  .description="Parallels disk image",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_hds
};

// always little-endian
struct parallels_header {
    char magic[16]; // "WithoutFreeSpace"
    uint32_t version;
    uint32_t heads;
    uint32_t cylinders;
    uint32_t tracks;
    uint32_t catalog_entries;
    uint32_t nb_sectors;
    char padding[24];
} __attribute__((packed));

static int header_check_hds(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct parallels_header *hdr=(const struct parallels_header *)buffer;
  if(le32(hdr->heads)==0 ||
      le32(hdr->cylinders)==0 ||
      le32(hdr->tracks)==0 ||
      le32(hdr->nb_sectors)==0)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_hds.extension;
  return 1;
}

static void register_header_check_hds(file_stat_t *file_stat)
{
  static const unsigned char hds_header[20]= {
    'W','i','t','h','o','u','t','F','r','e','e','S','p','a','c','e',
    0x02, 0x00, 0x00, 0x00
  };
  register_header_check(0, hds_header,sizeof(hds_header), &header_check_hds, file_stat);
}
