/*

    File: file_vdi.c

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
#include "types.h"
#include "filegen.h"
#include "common.h"

static void register_header_check_vdi(file_stat_t *file_stat);

const file_hint_t file_hint_vdi= {
  .extension="vdi",
  .description="Virtual desktop infrastructure 1.1",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_vdi
};

/* Image version. */
#define VDI_VERSION_1_1 0x00010001

/* Image type. */
#define VDI_TYPE_DYNAMIC 1
#define VDI_TYPE_STATIC  2

typedef unsigned char uuid_t[16];

typedef struct {
    char text[0x40];
    uint32_t signature;
    uint32_t version;
    uint32_t header_size;
    uint32_t image_type;
    uint32_t image_flags;
    char description[256];
    uint32_t offset_bmap;
    uint32_t offset_data;
    uint32_t cylinders;         /* disk geometry, unused here */
    uint32_t heads;             /* disk geometry, unused here */
    uint32_t sectors;           /* disk geometry, unused here */
    uint32_t sector_size;
    uint32_t unused1;
    uint64_t disk_size;
    uint32_t block_size;
    uint32_t block_extra;       /* unused here */
    uint32_t blocks_in_image;
    uint32_t blocks_allocated;
    uuid_t uuid_image;
    uuid_t uuid_last_snap;
    uuid_t uuid_link;
    uuid_t uuid_parent;
    uint64_t unused2[7];
} VdiHeader;

static int header_check_vdi(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const VdiHeader *header=(const VdiHeader *)buffer;
  if(le32(header->version) == VDI_VERSION_1_1)
  {
    if(le32(header->offset_data) < sizeof(VdiHeader))
      return 0;
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_vdi.extension;
    if(le32(header->image_type) == VDI_TYPE_STATIC)
    {
      file_recovery_new->calculated_file_size=(uint64_t) le32(header->offset_data) + le32(header->blocks_in_image) * le32(header->block_size);
      file_recovery_new->data_check=&data_check_size;
      file_recovery_new->file_check=&file_check_size;
    }
    return 1;
  }
  return 0;
}

static void register_header_check_vdi(file_stat_t *file_stat)
{
  static const unsigned char vdi_header[4]= {0x7f, 0x10, 0xda, 0xbe};
  register_header_check(0x40, vdi_header,sizeof(vdi_header), &header_check_vdi, file_stat);
}
