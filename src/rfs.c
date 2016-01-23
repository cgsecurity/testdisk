/*

    File: rfs.c

    Copyright (C) 1998-2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include "rfs.h"
#include "fnctdsk.h"
#include "log.h"
#include "guid_cpy.h"

static void set_rfs_info(const struct reiserfs_super_block *sb, partition_t *partition);
static int test_rfs(const disk_t *disk_car, const struct reiserfs_super_block *sb, const partition_t *partition, const int verbose);

static int test_rfs4(const disk_t *disk_car, const struct reiser4_master_sb*sb, const partition_t *partition, const int verbose);

static void set_rfs4_info(const struct reiser4_master_sb *sb4, partition_t *partition)
{
  partition->upart_type = UP_RFS4;
  partition->fsname[0]='\0';
  partition->blocksize=le16(sb4->blocksize);
  snprintf(partition->info, sizeof(partition->info),
      "ReiserFS 4 blocksize=%u", partition->blocksize);
}

int check_rfs(disk_t *disk_car,partition_t *partition,const int verbose)
{
  unsigned char *buffer=(unsigned char*)MALLOC(REISERFS_SUPER_BLOCK_SIZE);
  if(disk_car->pread(disk_car, buffer, REISERFS_SUPER_BLOCK_SIZE, partition->part_offset + 128 * 512) != REISERFS_SUPER_BLOCK_SIZE) /* 64k offset */
  {
    free(buffer);
    return 1;
  }
  if(test_rfs(disk_car, (struct reiserfs_super_block*)buffer, partition, verbose)==0)
  {
    set_rfs_info((struct reiserfs_super_block*)buffer, partition);
    free(buffer);
    return 0;
  }
  if(test_rfs4(disk_car, (struct reiser4_master_sb*)buffer, partition, verbose)==0)
  {
    set_rfs4_info((const struct reiser4_master_sb*)buffer, partition);
    free(buffer);
    return 0;
  }
  free(buffer);
  return 1;
}

static int test_rfs(const disk_t *disk_car, const struct reiserfs_super_block *sb, const partition_t *partition, const int verbose)
{
  if (memcmp(sb->s_magic,REISERFS_SUPER_MAGIC,sizeof(REISERFS_SUPER_MAGIC)) != 0 &&
      memcmp(sb->s_magic,REISERFS2_SUPER_MAGIC,sizeof(REISERFS2_SUPER_MAGIC)) != 0 &&
      memcmp(sb->s_magic,REISERFS3_SUPER_MAGIC,sizeof(REISERFS3_SUPER_MAGIC)) != 0)
    return 1;
  /*
   * sanity checks.
   */

  if (le32(sb->s_block_count) < le32(sb->s_free_blocks))
    return (1);

  if (le32(sb->s_block_count) < REISERFS_MIN_BLOCK_AMOUNT)
    return (1);

  if ((le16(sb->s_state) != REISERFS_VALID_FS) &&
      (le16(sb->s_state) != REISERFS_ERROR_FS))
    return (1);

  if (le16(sb->s_oid_maxsize) % 2!=0) /* must be even */
    return (1);

  if (le16(sb->s_oid_maxsize) < le16(sb->s_oid_cursize))
    return (1);

  if ((le16(sb->s_blocksize) != 4096) && (le16(sb->s_blocksize) != 8192))
    return (1);

  if(partition==NULL)
    return 0;
  if(verbose>0)
    log_info("\nReiserFS Marker at %u/%u/%u\n",
	offset2cylinder(disk_car,partition->part_offset),
	offset2head(disk_car,partition->part_offset),
	offset2sector(disk_car,partition->part_offset));
  return 0;
}

static int test_rfs4(const disk_t *disk_car, const struct reiser4_master_sb *sb, const partition_t *partition, const int verbose)
{
  if (memcmp(sb->magic,REISERFS4_SUPER_MAGIC,sizeof(REISERFS4_SUPER_MAGIC)) != 0)
    return 1;
  if(verbose>0)
    log_info("\nReiserFS Marker at %u/%u/%u\n", offset2cylinder(disk_car,partition->part_offset),offset2head(disk_car,partition->part_offset),offset2sector(disk_car,partition->part_offset));
  /*
   * sanity checks.
   */
  if (le16(sb->blocksize) != 4096)
    return (1);
  /* if a value > 4096 become legal, the code will break while reading the filesystem size (read out of bound) */
  return 0;
}

int recover_rfs(disk_t *disk_car, const struct reiserfs_super_block *sb,partition_t *partition,const int verbose, const int dump_ind)
{
  const struct reiser4_master_sb *sb4=(const struct reiser4_master_sb *)sb;
  if(test_rfs(disk_car, sb, partition, verbose)==0)
  {
    if(verbose>0 || dump_ind!=0)
    {
      log_info("\nrecover_rfs\n");
      log_info("block_count=%u\n",(unsigned int)le32(sb->s_block_count));
      log_info("block_size=%u\n",le16(sb->s_blocksize));
      if(dump_ind!=0)
      {
	dump_log(sb,DEFAULT_SECTOR_SIZE);
      }
    }
    partition->part_size = (uint64_t)le32(sb->s_block_count) * le16(sb->s_blocksize);
    partition->part_type_i386 = P_LINUX;
    partition->part_type_mac= PMAC_LINUX;
    partition->part_type_sun= PSUN_LINUX;
    partition->part_type_gpt=GPT_ENT_TYPE_LINUX_DATA;
    guid_cpy(&partition->part_uuid, (const efi_guid_t *)&sb->s_uuid);
    set_rfs_info(sb, partition);
    return 0;
  }
  if(test_rfs4(disk_car, sb4, partition, verbose)==0)
  {
    const struct format40_super *fmt40_super=(const struct format40_super *)((const char*)sb4+le16(sb4->blocksize));
    if(verbose>0 || dump_ind!=0)
    {
      log_info("\nrecover_rfs\n");
      log_info("block_count=%lu\n",(unsigned long int)le64(fmt40_super->sb_block_count));
      log_info("block_size=%u\n",le16(sb4->blocksize));
      if(dump_ind!=0)
      {
	dump_log(sb,DEFAULT_SECTOR_SIZE);
      }
    }
    partition->part_size = (uint64_t)le64(fmt40_super->sb_block_count) * le16(sb4->blocksize);
    partition->part_type_i386 = P_LINUX;
    partition->part_type_mac= PMAC_LINUX;
    partition->part_type_sun= PSUN_LINUX;
    partition->part_type_gpt=GPT_ENT_TYPE_LINUX_DATA;
    guid_cpy(&partition->part_uuid, (const efi_guid_t *)&sb4->uuid);
    set_rfs4_info(sb4, partition);
    return 0;
  }
  return 1;
}

static void set_rfs_info(const struct reiserfs_super_block *sb, partition_t *partition)
{
  partition->fsname[0]='\0';
  partition->blocksize=le16(sb->s_blocksize);
  if (memcmp(sb->s_magic,REISERFS_SUPER_MAGIC,sizeof(REISERFS_SUPER_MAGIC)) == 0)
  {
    partition->upart_type = UP_RFS;
    snprintf(partition->info, sizeof(partition->info),
	"ReiserFS 3.5 with standard journal blocksize=%u", partition->blocksize);
  }
  else if(memcmp(sb->s_magic,REISERFS2_SUPER_MAGIC,sizeof(REISERFS2_SUPER_MAGIC)) == 0)
  {
    partition->upart_type = UP_RFS2;
    snprintf(partition->info, sizeof(partition->info),
	"ReiserFS 3.6 with standard journal blocksize=%u", partition->blocksize);
    set_part_name(partition,(const char*)sb->s_label,16);
  }
  else if(memcmp(sb->s_magic,REISERFS3_SUPER_MAGIC,sizeof(REISERFS3_SUPER_MAGIC)) == 0)
  {
    partition->upart_type = UP_RFS3;
    if(le16(sb->sb_version)==1)
      snprintf(partition->info, sizeof(partition->info),
	  "ReiserFS 3.5 with non standard journal blocksize=%u", partition->blocksize);
    else if(le16(sb->sb_version)==2)
      snprintf(partition->info, sizeof(partition->info),
	  "ReiserFS 3.6 with non standard journal blocksize=%u", partition->blocksize);
    else
      snprintf(partition->info, sizeof(partition->info),
	  "ReiserFS 3.? with non standard journal blocksize=%u", partition->blocksize);
    set_part_name(partition,(const char*)sb->s_label,16);
  }
  if(le16(sb->s_state) == REISERFS_ERROR_FS)
  {
    strcat(partition->info,", need recovery");
  }
}

