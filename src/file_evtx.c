/*

    File: file_evtx.c

    Copyright (C) 2019 Christophe GRENIER <grenier@cgsecurity.org>

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

struct evtx_header
{
  char     magic[8];
  uint64_t OldestChunk;
  uint64_t CurrentChunkNum;
  uint64_t NextRecordNum;
  uint32_t HeaderPart1Len;	/* 0x80 */
  uint16_t MinorVersion;	/* 1 */
  uint16_t MajorVersion;	/* 3 */
  uint16_t HeaderSize;		/* 0x1000 */
  uint16_t ChunkCount;
  char	   unk[76];		/* 0 */
  uint32_t Flags;
  uint32_t Checksum;
} __attribute__ ((gcc_struct, __packed__));

static void register_header_check_evtx(file_stat_t *file_stat);

const file_hint_t file_hint_evtx= {
  .extension="evtx",
  .description="Microsoft Event Log",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_evtx
};

static int header_check_evtx(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct evtx_header *hdr=(const struct evtx_header *)buffer;
  if(le32(hdr->HeaderPart1Len) != 0x80 ||
      le16(hdr->MinorVersion) != 1 ||
      le16(hdr->MajorVersion) != 3 ||
      le16(hdr->HeaderSize) != 0x1000)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_evtx.extension;
  file_recovery_new->calculated_file_size=(uint64_t)le16(hdr->HeaderSize) + (uint64_t)le16(hdr->ChunkCount) * 64 * 1024;
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static void register_header_check_evtx(file_stat_t *file_stat)
{
  register_header_check(0, "ElfFile", 8, &header_check_evtx, file_stat);
}
