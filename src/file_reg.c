/*

    File: file_reg.c

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

static void register_header_check_reg(file_stat_t *file_stat);

const file_hint_t file_hint_reg= {
  .extension="reg",
  .description="Windows Registry",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
	.register_header_check=&register_header_check_reg
};

struct creg_file_header
{
  uint32_t CREG_ID;		/* CREG */
  uint32_t uk1;
  uint32_t rgdb_offset;
  uint32_t chksum;
  uint16_t num_rgdb;
  uint16_t flags;
  uint32_t uk2;
  uint32_t uk3;
  uint32_t uk4;
} __attribute__ ((__packed__));

struct rgdb_block
{
  uint32_t RGDB_ID;		/* RGDB */
  uint32_t size;
  uint32_t unused_size;
  uint16_t flags;
  uint16_t section;
  uint32_t free_offset;	/* -1 if there is no free space */
  uint16_t max_id;
  uint16_t first_free_id;
  uint32_t uk1;
  uint32_t chksum;
} __attribute__ ((__packed__));

static int header_check_reg_9x(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct creg_file_header*header=(const struct creg_file_header*)buffer;
  if(le32(header->rgdb_offset)+4 > buffer_size)
    return 0;
  {
    const struct rgdb_block*block=(const struct rgdb_block*)(buffer+le32(header->rgdb_offset));
    if(memcmp(block,"RGDB",4)!=0)
      return 0;
    reset_file_recovery(file_recovery_new);
    file_recovery_new->min_filesize=0x1000;
    file_recovery_new->extension=file_hint_reg.extension;
    return 1;
  }
}

struct regf_file_header
{
  uint32_t signature;
  uint32_t primary_sequence_number;
  uint32_t secondary_sequence_number;
  uint64_t modification_time;
  uint32_t major_version;
  uint32_t minor_version;
  uint32_t file_type;
  uint32_t unknown3;
  uint32_t root_key_offset;
  uint32_t hive_bins_size;
  uint32_t unknown4;
  uint8_t unknown5[ 64 ];
  uint8_t unknown6[ 396 ];
  uint32_t xor_checksum;
} __attribute__ ((__packed__));

static int header_check_reg_nt(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct regf_file_header *header=(const struct regf_file_header*)buffer;
  if(le32(header->file_type) > 1)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->min_filesize=0x1000;
  file_recovery_new->extension=file_hint_reg.extension;
  file_recovery_new->time=td_ntfs2utc(le64(header->modification_time));
  return 1;
}

/* TODO: use information from http://home.eunet.no/pnordahl/ntpasswd/WinReg.txt to get the file size
   Registry: regf hbin hbin...
*/
static void register_header_check_reg(file_stat_t *file_stat)
{
  static const unsigned char reg_header_nt[4]  = { 'r','e','g','f'};
  static const unsigned char reg_header_9x[4]  = { 'C','R','E','G'};
  register_header_check(0, reg_header_nt,sizeof(reg_header_nt), &header_check_reg_nt, file_stat);
  register_header_check(0, reg_header_9x,sizeof(reg_header_9x), &header_check_reg_9x, file_stat);
}
