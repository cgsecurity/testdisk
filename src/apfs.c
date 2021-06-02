/*

    File: apfs.c

    Copyright (C) 2021 Christophe GRENIER <grenier@cgsecurity.org>

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

#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <time.h>
#include "types.h"
#include "common.h"
#include "apfs.h"
#include "fnctdsk.h"
#include "log.h"
#include "guid_cpy.h"

static void set_APFS_info(const nx_superblock_t *sb, partition_t *partition)
{
  partition->upart_type=UP_APFS;
}

int check_APFS(disk_t *disk_car, partition_t *partition)
{
  unsigned char *buffer=(unsigned char*)MALLOC(APFS_SUPERBLOCK_SIZE);
  const nx_superblock_t* sb=(const nx_superblock_t *)buffer;
  if(disk_car->pread(disk_car, buffer, APFS_SUPERBLOCK_SIZE, partition->part_offset) != APFS_SUPERBLOCK_SIZE)
  {
    free(buffer);
    return 1;
  }
  if(test_APFS(sb, partition)!=0)
  {
    free(buffer);
    return 1;
  }
  set_APFS_info(sb, partition);
  free(buffer);
  return 0;
}

int recover_APFS(const disk_t *disk, const nx_superblock_t *sb, partition_t *partition, const int verbose, const int dump_ind)
{
  if(test_APFS(sb, partition)!=0)
    return 1;
  if(dump_ind!=0)
  {
    if(partition!=NULL && disk!=NULL)
      log_info("\nAPFS magic value at %u/%u/%u\n",
	  offset2cylinder(disk,partition->part_offset),
	  offset2head(disk,partition->part_offset),
	  offset2sector(disk,partition->part_offset));
    /* There is a little offset ... */
    dump_log(sb,DEFAULT_SECTOR_SIZE);
  }
  if(partition==NULL)
    return 0;
  set_APFS_info(sb, partition);
  partition->part_type_i386=P_LINUX;
  partition->part_type_mac=PMAC_LINUX;
  partition->part_type_sun=PSUN_LINUX;
  partition->part_type_gpt=GPT_ENT_TYPE_MAC_APFS;
  partition->part_size=le32(sb->nx_block_size) * le64(sb->nx_block_count);
  guid_cpy(&partition->part_uuid, (const efi_guid_t *)&sb->nx_uuid);
  if(verbose>0)
  {
    log_info("\n");
  }
  partition->sborg_offset=0;
  partition->sb_size=le32(sb->nx_block_size);
  partition->sb_offset=0;
  if(verbose>0)
  {
    log_info("recover_APFS: s_blocksize=%u\n", partition->blocksize);
    log_info("recover_APFS: s_blocks_count %lu\n", (long unsigned int)le64(sb->nx_block_count));
    if(disk==NULL)
      log_info("recover_APFS: part_size %lu\n", (long unsigned)(partition->part_size / DEFAULT_SECTOR_SIZE));
    else
      log_info("recover_APFS: part_size %lu\n", (long unsigned)(partition->part_size / disk->sector_size));
  }
  return 0;
}
