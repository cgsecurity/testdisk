/*

    File: file_sqlitewal.c

    Copyright (C) 2024 Christophe GRENIER <grenier@cgsecurity.org>

    SQLite Write-Ahead Log (WAL) file format:
    https://www.sqlite.org/walformat.html

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_sqlitewal)
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

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_sqlitewal(file_stat_t *file_stat);

const file_hint_t file_hint_sqlitewal= {
  .extension="wal",
  .description="SQLite Write-Ahead Log",
  .max_filesize=100*1024*1024,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_sqlitewal
};

/* WAL file header layout (big-endian):
 *   Offset  0: magic number (4 bytes) — 0x377f0682 (big-endian) or 0x377f0683
 *   Offset  4: file format version (4 bytes)
 *   Offset  8: database page size in bytes
 *   Offset 12: checkpoint sequence number
 *   Offset 16: salt-1
 *   Offset 20: salt-2
 *   Offset 24: checksum-1
 *   Offset 28: checksum-2
 */
struct sqlitewal_header
{
  uint32_t magic;
  uint32_t version;
  uint32_t pagesize;
  uint32_t checkpoint_seq;
  uint32_t salt1;
  uint32_t salt2;
  uint32_t checksum1;
  uint32_t checksum2;
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires buffer_size >= sizeof(struct sqlitewal_header);
  @ requires separation: \separated(&file_hint_sqlitewal, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_sqlitewal(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct sqlitewal_header *hdr=(const struct sqlitewal_header *)buffer;
  const uint32_t pagesize=be32(hdr->pagesize);
  /* Page size must be a power of two between 512 and 65536 */
  if(pagesize < 512 || pagesize > 65536 || ((pagesize - 1) & pagesize) != 0)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_sqlitewal.extension;
  return 1;
}

static void register_header_check_sqlitewal(file_stat_t *file_stat)
{
  /* WAL magic: 0x377f0682 (big-endian checksum) */
  static const unsigned char wal_magic[4]= { 0x37, 0x7F, 0x06, 0x82 };
  register_header_check(0, wal_magic, sizeof(wal_magic), &header_check_sqlitewal, file_stat);
}
#endif
