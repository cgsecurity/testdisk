/*

    File: xfs.c

    Copyright (C) 2004-2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include "types.h"
#include "common.h"
#include "xfs.h"
#include "fnctdsk.h"
#include "log.h"
#include "guid_cpy.h"

static void set_xfs_info(const struct xfs_sb *sb, partition_t *partition);
static int test_xfs(const disk_t *disk_car, const struct xfs_sb *sb, const partition_t *partition, const int verbose);

int check_xfs(disk_t *disk_car,partition_t *partition,const int verbose)
{
  unsigned char *buffer=(unsigned char*)MALLOC(XFS_SUPERBLOCK_SIZE);
  if(disk_car->pread(disk_car, buffer, XFS_SUPERBLOCK_SIZE, partition->part_offset) != XFS_SUPERBLOCK_SIZE)
  {
    free(buffer);
    return 1;
  }
  if(test_xfs(disk_car, (struct xfs_sb*)buffer, partition, verbose)!=0)
  {
    free(buffer);
    return 1;
  }
  set_xfs_info((struct xfs_sb*)buffer, partition);
  free(buffer);
  return 0;
}

static int test_xfs(const disk_t *disk_car, const struct xfs_sb *sb, const partition_t *partition, const int verbose)
{
  if(sb->sb_magicnum!=be32(XFS_SB_MAGIC) ||
      (uint16_t)be16(sb->sb_sectsize)  != (1U << sb->sb_sectlog) ||
      (uint32_t)be32(sb->sb_blocksize) != (1U << sb->sb_blocklog) ||
      (uint16_t)be16(sb->sb_inodesize) != (1U << sb->sb_inodelog))
    return 1;
  switch(be16(sb->sb_versionnum) & XFS_SB_VERSION_NUMBITS)
  {
    case XFS_SB_VERSION_1:
    case XFS_SB_VERSION_2:
    case XFS_SB_VERSION_3:
    case XFS_SB_VERSION_4:
    case XFS_SB_VERSION_5:
      break;
    default:
      log_error("Unknown XFS version 0x%x\n",be16(sb->sb_versionnum)& XFS_SB_VERSION_NUMBITS);
      break;
  }
  if(verbose>0)
    log_info("\nXFS Marker at %u/%u/%u\n", offset2cylinder(disk_car,partition->part_offset),offset2head(disk_car,partition->part_offset),offset2sector(disk_car,partition->part_offset));
  return 0;
}

int recover_xfs(disk_t *disk_car, const struct xfs_sb *sb,partition_t *partition,const int verbose, const int dump_ind)
{
  if(test_xfs(disk_car, sb, partition, verbose)!=0)
    return 1;
  if(verbose>0 || dump_ind!=0)
  {
    log_info("\nrecover_xfs\n");
    if(dump_ind!=0)
    {
      dump_log(sb,DEFAULT_SECTOR_SIZE);
    }
  }
  set_xfs_info(sb, partition);
  partition->part_size = (uint64_t)be64(sb->sb_dblocks) * be32(sb->sb_blocksize);
  partition->part_type_i386=P_LINUX;
  partition->part_type_mac=PMAC_LINUX;
  partition->part_type_sun=PSUN_LINUX;
  partition->part_type_gpt=GPT_ENT_TYPE_LINUX_DATA;
  guid_cpy(&partition->part_uuid, (const efi_guid_t *)&sb->sb_uuid);
  return 0;
}

static void set_xfs_info(const struct xfs_sb *sb, partition_t *partition)
{
  partition->blocksize=be32(sb->sb_blocksize);
  partition->fsname[0]='\0';
  partition->info[0]='\0';
  switch(be16(sb->sb_versionnum) & XFS_SB_VERSION_NUMBITS)
  {
    case XFS_SB_VERSION_1:
      partition->upart_type = UP_XFS;
      snprintf(partition->info, sizeof(partition->info),
	  "XFS <=6.1, blocksize=%u", partition->blocksize);
      break;
    case XFS_SB_VERSION_2:
      partition->upart_type = UP_XFS2;
      snprintf(partition->info, sizeof(partition->info),
	  "XFS 6.2 - attributes, blocksize=%u", partition->blocksize);
      break;
    case XFS_SB_VERSION_3:
      partition->upart_type = UP_XFS3;
      snprintf(partition->info, sizeof(partition->info),
	  "XFS 6.2 - new inode version, blocksize=%u", partition->blocksize);
      break;
    case XFS_SB_VERSION_4:
      partition->upart_type = UP_XFS4;
      snprintf(partition->info, sizeof(partition->info),
	  "XFS 6.2+ - bitmap version, blocksize=%u", partition->blocksize);
      break;
    case XFS_SB_VERSION_5:
      partition->upart_type = UP_XFS5;
      snprintf(partition->info, sizeof(partition->info),
	  "XFS CRC enabled, blocksize=%u", partition->blocksize);
      break;
    default:
      snprintf(partition->info, sizeof(partition->info),
	  "XFS unknown version %u\n", be16(sb->sb_versionnum)& XFS_SB_VERSION_NUMBITS);
      break;
  }
  set_part_name(partition,sb->sb_fname,12);
}
