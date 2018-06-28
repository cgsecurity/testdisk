/*

    File: f2fs.c

    Copyright (C) 2018 Christophe GRENIER <grenier@cgsecurity.org>

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

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "common.h"
#include "f2fs_fs.h"
#include "f2fs.h"
#include "log.h"

extern const arch_fnct_t arch_none;

static void set_f2fs_info(partition_t *partition, const struct f2fs_super_block*hdr)
{
  partition->upart_type=UP_F2FS;
  partition->blocksize=1<<le32(hdr->log_blocksize);
  partition->fsname[0]='\0';
  if(partition->sb_offset==0)
    snprintf(partition->info, sizeof(partition->info), "F2FS, blocksize=%u", partition->blocksize);
  else
    snprintf(partition->info, sizeof(partition->info), "F2FS found using backup sector, blocksize=%u", partition->blocksize);
}

int check_f2fs(disk_t *disk, partition_t *partition)
{
  unsigned char *buffer=(unsigned char*)MALLOC(F2FS_BLKSIZE);
  if(disk->pread(disk, buffer, F2FS_BLKSIZE, partition->part_offset + F2FS_SUPER_OFFSET) != F2FS_BLKSIZE)
  {
    free(buffer);
    return 1;
  }
  if(test_f2fs((struct f2fs_super_block*)buffer)!=0)
  {
    free(buffer);
    return 1;
  }
  set_f2fs_info(partition, (struct f2fs_super_block*)buffer);
  free(buffer);
  return 0;
}

int test_f2fs(const struct f2fs_super_block *hdr)
{
  if(le32(hdr->magic) != F2FS_SUPER_MAGIC)
    return 1;
  /* Currently, support 512/1024/2048/4096 bytes sector size */
  if(le32(hdr->log_sectorsize) < 9 || le32(hdr->log_sectorsize) > 12)
    return 1;
  /* Currently, support only 4KB block size */
  if(le32(hdr->log_blocksize) != F2FS_BLKSIZE_BITS)
    return 1;
  if(le32(hdr->log_sectorsize) + le32(hdr->log_sectors_per_block) != le32(hdr->log_blocksize))
    return 1;
  /* check log blocks per segment */
  if(le32(hdr->log_blocks_per_seg) != 9)
    return 1;
  if(le64(hdr->block_count) == 0)
    return 1;
  return 0;
}

int recover_f2fs(const disk_t *disk, const struct f2fs_super_block *hdr, partition_t *partition)
{
  if(test_f2fs(hdr)!=0)
    return 1;
  partition->sborg_offset=0;
  partition->sb_size=F2FS_BLKSIZE;
  partition->part_type_i386=P_LINUX;
  partition->part_type_gpt=GPT_ENT_TYPE_MS_BASIC_DATA;
  partition->part_size=(uint64_t)le64(hdr->block_count) << le32(hdr->log_blocksize);
  set_f2fs_info(partition, hdr);
  return 0;
}
