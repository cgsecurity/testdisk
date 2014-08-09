/*

    File: file_wim.c

    Copyright (C) 2012 Christophe GRENIER <grenier@cgsecurity.org>
  
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

static void register_header_check_wim(file_stat_t *file_stat);
/* http://go.microsoft.com/fwlink/?LinkId=92227 */

const file_hint_t file_hint_wim= {
  .extension="wim",
  .description="Windows imaging (WIM) image",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_wim
};

struct reshdr_disk_short
{
  union {
    uint64_t flags;	/* one byte is a combination of RESHDR_FLAG_XXX */
    uint64_t size;	/* the 7 low-bytes are used to store the size */
  };
  uint64_t offset;
  uint64_t original_size;
} __attribute__ ((__packed__));

#define RESHDR_GET_SIZE(R) (le64(R.size) & 0x00FFFFFFFFFFFFFF)

struct _WIMHEADER_V1_PACKED
{
  char			ImageTag[8];
  uint32_t		cbSize;
  uint32_t		dwVersion;
  uint32_t		dwFlags;
  uint32_t		dwCompressionSize;
  unsigned char		gWIMGuid[16];
  uint16_t		usPartNumber;
  uint16_t		usTotalParts;
  uint32_t		dwImageCount;
  struct reshdr_disk_short	rhOffsetTable;
  struct reshdr_disk_short	rhXmlData;
  struct reshdr_disk_short	rhBootMetadata;
  uint32_t		dwBootIndex;
  struct reshdr_disk_short	rhIntegrity;
  unsigned char		bUnused[60];
} __attribute__ ((__packed__));

static int header_check_wim(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct _WIMHEADER_V1_PACKED *hdr=(const struct _WIMHEADER_V1_PACKED *)buffer;
  uint64_t size=le32(hdr->cbSize);
  if(le32(hdr->cbSize) < sizeof(struct _WIMHEADER_V1_PACKED))
    return 0;
#ifdef DEBUG_WIM
  log_info("cbSize %llu\n", (unsigned long long)le32(hdr->cbSize));
  log_info("dwCompressionSize %llu\n", (unsigned long long)le32(hdr->dwCompressionSize));
  log_info("rhOffsetTable %llu %llu\n", (unsigned long long)RESHDR_GET_SIZE(hdr->rhOffsetTable), (unsigned long long)le64(hdr->rhOffsetTable.offset));
  log_info("rhXmlData %llu %llu\n", (unsigned long long)RESHDR_GET_SIZE(hdr->rhXmlData), (unsigned long long)le64(hdr->rhXmlData.offset));
  log_info("rhBootMetadata %llu %llu\n", (unsigned long long)RESHDR_GET_SIZE(hdr->rhBootMetadata), (unsigned long long)le64(hdr->rhBootMetadata.offset));
  log_info("rhIntegrity %llu %llu\n", (unsigned long long)RESHDR_GET_SIZE(hdr->rhIntegrity), (unsigned long long)le64(hdr->rhIntegrity.offset));
#endif
  if(RESHDR_GET_SIZE(hdr->rhOffsetTable) > 0 && RESHDR_GET_SIZE(hdr->rhOffsetTable) + le64(hdr->rhOffsetTable.offset) > size)
    size=RESHDR_GET_SIZE(hdr->rhOffsetTable) + le64(hdr->rhOffsetTable.offset);
  if(RESHDR_GET_SIZE(hdr->rhXmlData) > 0 && RESHDR_GET_SIZE(hdr->rhXmlData) + le64(hdr->rhXmlData.offset) > size)
    size=RESHDR_GET_SIZE(hdr->rhXmlData) + le64(hdr->rhXmlData.offset);
  if(RESHDR_GET_SIZE(hdr->rhBootMetadata) > 0 && RESHDR_GET_SIZE(hdr->rhBootMetadata) + le64(hdr->rhBootMetadata.offset) > size)
    size=RESHDR_GET_SIZE(hdr->rhBootMetadata) + le64(hdr->rhBootMetadata.offset);
  if(RESHDR_GET_SIZE(hdr->rhIntegrity) > 0 && RESHDR_GET_SIZE(hdr->rhIntegrity) + le64(hdr->rhIntegrity.offset) > size)
    size=RESHDR_GET_SIZE(hdr->rhIntegrity) + le64(hdr->rhIntegrity.offset);
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_wim.extension;
  file_recovery_new->calculated_file_size=size;
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static void register_header_check_wim(file_stat_t *file_stat)
{
  register_header_check(0, "MSWIM\0\0\0", 8, &header_check_wim, file_stat);
}
