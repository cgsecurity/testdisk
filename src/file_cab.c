/*

    File: file_cab.c

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
#include "common.h"
#include "filegen.h"

static void register_header_check_cab(file_stat_t *file_stat);

const file_hint_t file_hint_cab= {
  .extension="cab",
  .description="Microsoft Cabinet archive",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_cab
};

struct cab_header {
  uint32_t magic;
  uint32_t hdr_checksum;
  uint32_t filesize;
  uint32_t fld_checksum;
  uint32_t off_file;
  uint32_t files_checksum;
  uint16_t cab_version;
  uint16_t nb_folder;
  uint16_t nb_files;
  uint16_t flags;
  uint16_t setid;
  uint16_t number;
} __attribute__ ((__packed__));

static int header_check_cab(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct cab_header *cab_hdr=(const struct cab_header*)buffer;
  if(le16(cab_hdr->cab_version)==0x0103 && le32(cab_hdr->filesize) >= sizeof(struct cab_header))
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_cab.extension;
    file_recovery_new->calculated_file_size=(uint64_t)le32(cab_hdr->filesize);
    file_recovery_new->data_check=&data_check_size;
    file_recovery_new->file_check=&file_check_size;
    return 1;
  }
  return 0;
}

static void register_header_check_cab(file_stat_t *file_stat)
{
  static const unsigned char cab_header[4]  = { 'M','S','C','F'};
  register_header_check(0, cab_header,sizeof(cab_header), &header_check_cab, file_stat);
}
