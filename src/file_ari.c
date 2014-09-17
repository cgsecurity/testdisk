/*

    File: file_ari.c

    Copyright (C) 2014 Christophe GRENIER <grenier@cgsecurity.org>
  
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

static void register_header_check_ari(file_stat_t *file_stat);

const file_hint_t file_hint_ari= {
  .extension="ari",
  .description="ARRI Raw Video",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_ari
};

struct arri_header
{
  uint32_t magic;
  uint32_t endian;
  uint32_t header_size;
  uint32_t version;	/* ie. 3 */
  uint32_t unk1;
  uint32_t width;
  uint32_t height;
  uint32_t cam_hwr_rev;
} __attribute__ ((__packed__));

static int header_check_ari(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct arri_header *hdr=(const struct arri_header *)buffer;
  if(le32(hdr->version)==0 ||
    le32(hdr->width)==0 ||
    le32(hdr->height)==0)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_ari.extension;
  file_recovery_new->min_filesize=4096;
  return 1;
}

static void register_header_check_ari(file_stat_t *file_stat)
{
  static const unsigned char ari_header[12]=  {
    'A' , 'R' , 'R' , 'I' , 0x12, 0x34, 0x56, 0x78,
    0x00, 0x10, 0x00, 0x00};
  register_header_check(0, ari_header, sizeof(ari_header), &header_check_ari, file_stat);
}
