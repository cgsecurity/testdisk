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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_wim)
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

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_wim(file_stat_t *file_stat);
/* http://go.microsoft.com/fwlink/?LinkId=92227 */

const file_hint_t file_hint_wim = {
  .extension = "wim",
  .description = "Windows imaging (WIM) image",
  .max_filesize = PHOTOREC_MAX_FILE_SIZE,
  .recover = 1,
  .enable_by_default = 1,
  .register_header_check = &register_header_check_wim
};

struct reshdr_disk_short
{
  union
  {
    uint64_t flags; /* one byte is a combination of RESHDR_FLAG_XXX */
    uint64_t size;  /* the 7 low-bytes are used to store the size */
  };
  uint64_t offset;
  uint64_t original_size;
} __attribute__((gcc_struct, __packed__));

#define RESHDR_GET_SIZE(R) (le64(R.size) & 0x00FFFFFFFFFFFFFF)

struct _WIMHEADER_V1_PACKED
{
  char ImageTag[8];
  uint32_t cbSize;
  uint32_t dwVersion;
  uint32_t dwFlags;
  uint32_t dwCompressionSize;
  unsigned char gWIMGuid[16];
  uint16_t usPartNumber;
  uint16_t usTotalParts;
  uint32_t dwImageCount;
  struct reshdr_disk_short rhOffsetTable;
  struct reshdr_disk_short rhXmlData;
  struct reshdr_disk_short rhBootMetadata;
  uint32_t dwBootIndex;
  struct reshdr_disk_short rhIntegrity;
  unsigned char bUnused[60];
} __attribute__((gcc_struct, __packed__));

/*@
  @ requires size <= 0x00FFFFFFFFFFFFFF;
  @ assigns  \nothing;
  @*/
static uint64_t wim_max(const uint64_t offset, const uint64_t size, const uint64_t max_size)
{
  uint64_t tmp;
  if(size == 0)
    return max_size;
  if(offset > PHOTOREC_MAX_FILE_SIZE)
    return 0;
  tmp = offset + size;
  if(tmp > max_size)
    return tmp;
  return max_size;
}

/*@
  @ requires buffer_size > sizeof(struct _WIMHEADER_V1_PACKED);
  @ requires separation: \separated(&file_hint_wim, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_wim(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct _WIMHEADER_V1_PACKED *hdr = (const struct _WIMHEADER_V1_PACKED *)buffer;
  uint64_t size = le32(hdr->cbSize);
  const uint64_t rhOffsetTable_s = RESHDR_GET_SIZE(hdr->rhOffsetTable);
  /*@ assert rhOffsetTable_s <= 0x00FFFFFFFFFFFFFF; */
  const uint64_t rhOffsetTable_o = le64(hdr->rhOffsetTable.offset);
  const uint64_t rhXmlData_s = RESHDR_GET_SIZE(hdr->rhXmlData);
  /*@ assert rhXmlData_s <= 0x00FFFFFFFFFFFFFF; */
  const uint64_t rhXmlData_o = le64(hdr->rhXmlData.offset);
  const uint64_t rhBootMetadata_s = RESHDR_GET_SIZE(hdr->rhBootMetadata);
  /*@ assert rhBootMetadata_s <= 0x00FFFFFFFFFFFFFF; */
  const uint64_t rhBootMetadata_o = le64(hdr->rhBootMetadata.offset);
  const uint64_t rhIntegrity_s = RESHDR_GET_SIZE(hdr->rhIntegrity);
  /*@ assert rhIntegrity_s <= 0x00FFFFFFFFFFFFFF; */
  const uint64_t rhIntegrity_o = le64(hdr->rhIntegrity.offset);

  if(size < sizeof(struct _WIMHEADER_V1_PACKED))
    return 0;
#ifdef DEBUG_WIM
  log_info("cbSize %llu\n", (unsigned long long)size);
  log_info("dwCompressionSize %llu\n", (unsigned long long)le32(hdr->dwCompressionSize));
  log_info("rhOffsetTable %llu %llu\n", (unsigned long long)rhOffsetTable_s, (unsigned long long)rhOffsetTable_o);
  log_info("rhXmlData %llu %llu\n", (unsigned long long)rhXmlData_s, (unsigned long long)rhXmlData_o);
  log_info("rhBootMetadata %llu %llu\n", (unsigned long long)rhBootMetadata_s, (unsigned long long)rhBootMetadata_o);
  log_info("rhIntegrity %llu %llu\n", (unsigned long long)rhIntegrity_s, (unsigned long long)rhIntegrity_o);
#endif
  size = wim_max(rhOffsetTable_o, rhOffsetTable_s, size);
  if(size == 0)
    return 0;
  size = wim_max(rhXmlData_o, rhXmlData_s, size);
  if(size == 0)
    return 0;
  size = wim_max(rhBootMetadata_o, rhBootMetadata_s, size);
  if(size == 0)
    return 0;
  size = wim_max(rhIntegrity_o, rhIntegrity_s, size);
  if(size == 0)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension = file_hint_wim.extension;
  file_recovery_new->calculated_file_size = size;
  file_recovery_new->data_check = &data_check_size;
  file_recovery_new->file_check = &file_check_size;
  /*@ assert valid_file_recovery(file_recovery_new); */
  return 1;
}

static void register_header_check_wim(file_stat_t *file_stat)
{
  register_header_check(0, "MSWIM\0\0\0", 8, &header_check_wim, file_stat);
}
#endif
