/*

    File: jfs.c

    Copyright (C) 2004-2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include "jfs_superblock.h"
#include "jfs.h"
#include "fnctdsk.h"
#include "log.h"
#include "guid_cpy.h"

static int test_JFS(disk_t *disk_car, const struct jfs_superblock *sb,partition_t *partition,const int verbose, const int dump_ind);
static int set_JFS_info(disk_t *disk_car, const struct jfs_superblock *sb,partition_t *partition,const int verbose, const int dump_ind);

int check_JFS(disk_t *disk_car,partition_t *partition,const int verbose)
{
  unsigned char *buffer=(unsigned char*)MALLOC(JFS_SUPERBLOCK_SIZE);
  if(disk_car->read(disk_car,JFS_SUPERBLOCK_SIZE, buffer, partition->part_offset+64*512)!=0)
  {
    free(buffer);
    return 1;
  }
  if(test_JFS(disk_car,(struct jfs_superblock*)buffer,partition,verbose,0)!=0)
  {
    free(buffer);
    return 1;
  }
  set_JFS_info(disk_car,(struct jfs_superblock*)buffer,partition,verbose,0);
  free(buffer);
  return 0;
}

static int set_JFS_info(disk_t *disk_car, const struct jfs_superblock *sb,partition_t *partition,const int verbose, const int dump_ind)
{
  snprintf(partition->info,sizeof(partition->info),"JFS %u",(unsigned int)le32(sb->s_version));
  partition->fsname[0]='\0';
  if(le32(sb->s_version)==1)
  {
    set_part_name(partition,sb->s_fpack,11);
  }
  return 0;
}

/*
Primary superblock is at 0x8000
*/
int recover_JFS(disk_t *disk_car, const struct jfs_superblock *sb,partition_t *partition,const int verbose, const int dump_ind)
{
  if(test_JFS(disk_car,sb,partition,verbose,dump_ind)!=0)
    return 1;
  set_JFS_info(disk_car,sb,partition,verbose,dump_ind);
  partition->part_type_i386=P_LINUX;
  partition->part_type_sun=PSUN_LINUX;
  partition->part_type_mac=PMAC_LINUX;
  partition->part_type_gpt=GPT_ENT_TYPE_LINUX_DATA;
  partition->part_size=(uint64_t)le32(sb->s_pbsize) * le64(sb->s_size) +
    le32(sb->s_bsize) * (le24(sb->s_fsckpxd.len)+le24(sb->s_logpxd.len));
  partition->sborg_offset=64*512;
  partition->sb_size=JFS_SUPERBLOCK_SIZE;
  partition->sb_offset=0;
  partition->blocksize=le32(sb->s_bsize);
  guid_cpy(&partition->part_uuid, (const efi_guid_t *)&sb->s_uuid);
  if(verbose>0)
  {
    log_info("\n");
    log_info("recover_JFS: s_blocksize=%u\n",partition->blocksize);
    log_info("recover_JFS: s_size %lu\n",(long unsigned int)le64(sb->s_size));
    log_info("recover_JFS: s_fsckpxd.len:%d\n", (int)le24(sb->s_fsckpxd.len));
    log_info("recover_JFS: s_logpxd.len:%d\n", (int)le24(sb->s_logpxd.len));
    log_info("recover_JFS: part_size %lu\n",(long unsigned)(partition->part_size/disk_car->sector_size));
  }
  return 0;
}

static int test_JFS(disk_t *disk_car, const struct jfs_superblock *sb,partition_t *partition,const int verbose, const int dump_ind)
{
  if(memcmp(sb->s_magic,"JFS1",4)!=0)
    return 1;
  if(dump_ind!=0)
  {
    log_info("\nJFS magic value at %u/%u/%u\n", offset2cylinder(disk_car,partition->part_offset),offset2head(disk_car,partition->part_offset),offset2sector(disk_car,partition->part_offset));
    /* There is a little offset ... */
    dump_log(sb,DEFAULT_SECTOR_SIZE);
  }
  /*
  if( le32(sb->s_agsize) >= (1 << L2BPERDMAP) ) {
    return 2;
  }
  if(partition->part_size!=0 && (partition->part_size<le64(sb->s_size)))
    return 8;
    */
  partition->upart_type=UP_JFS;
  return 0;
}
