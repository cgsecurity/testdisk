/*

    File: file_vmdk.c

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

static void register_header_check_vmdk(file_stat_t *file_stat);

const file_hint_t file_hint_vmdk= {
  .extension="vmdk",
  .description="VMWare",
  .min_header_distance=0,
  .max_filesize=(uint64_t)2048*1024*1024*1024,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_vmdk
};

/* http://www.vmware.com/app/vmdk/?src=vmdk */
typedef struct {
  uint32_t magic;
  uint32_t version;
  uint32_t flags;
  uint32_t disk_sectors;
  uint32_t granularity;
  uint32_t l1dir_offset;
  uint32_t l1dir_size;
  uint32_t file_sectors;
  uint32_t cylinders;
  uint32_t heads;
  uint32_t sectors_per_track;
} VMDK3Header;

typedef struct {
  uint32_t magic;
  uint32_t version;
  uint32_t flags;
  int64_t capacity;
  int64_t granularity;
  int64_t desc_offset;
  int64_t desc_size;
  int32_t num_gtes_per_gte;
  int64_t rgd_offset;
  int64_t gd_offset;
  int64_t grain_offset;
  char filler[1];
  char check_bytes[4];
} __attribute__((packed)) VMDK4Header;

static int header_check_vmdk3(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const VMDK3Header *hdr=(const VMDK3Header *)buffer;
  const unsigned int cluster_sectors = le32(hdr->granularity);
  if(cluster_sectors==0)
    return 0;
  reset_file_recovery(file_recovery_new);
#ifdef DJGPP
  file_recovery_new->extension="vmd";
#else
  file_recovery_new->extension=file_hint_vmdk.extension;
#endif
  file_recovery_new->min_filesize=512;
  return 1;
}

static int header_check_vmdk4(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const VMDK4Header *hdr=(const VMDK4Header *)buffer;
  const unsigned int cluster_sectors = le64(hdr->granularity);
  const unsigned int l2_size = le32(hdr->num_gtes_per_gte);
  const uint32_t l1_entry_sectors = l2_size * cluster_sectors;
  if (l1_entry_sectors <= 0)
    return 0;
  reset_file_recovery(file_recovery_new);
#ifdef DJGPP
  file_recovery_new->extension="vmd";
#else
  file_recovery_new->extension=file_hint_vmdk.extension;
#endif
  file_recovery_new->min_filesize=512;
  return 1;
}

static void register_header_check_vmdk(file_stat_t *file_stat)
{
  static const unsigned char vmdk_header3_1[8]= { 'C','O','W','D', 0x01, 0x00, 0x00, 0x00};
  static const unsigned char vmdk_header4_1[8]= { 'K','D','M','V', 0x01, 0x00, 0x00, 0x00};
  static const unsigned char vmdk_header4_2[8]= { 'K','D','M','V', 0x02, 0x00, 0x00, 0x00};
  register_header_check(0, vmdk_header3_1,sizeof(vmdk_header3_1), &header_check_vmdk3, file_stat);
  register_header_check(0, vmdk_header4_1,sizeof(vmdk_header4_1), &header_check_vmdk4, file_stat);
  register_header_check(0, vmdk_header4_2,sizeof(vmdk_header4_2), &header_check_vmdk4, file_stat);
}
