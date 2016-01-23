/*

    File: cramfs.c

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
#include "cramfs.h"
#include "fnctdsk.h"
#include "log.h"

static void set_cramfs_info(const struct cramfs_super *sb, partition_t *partition);
static int test_cramfs(const disk_t *disk_car, const struct cramfs_super *sb, const partition_t *partition, const int verbose);

int check_cramfs(disk_t *disk_car,partition_t *partition,const int verbose)
{
  unsigned char *buffer=(unsigned char*)MALLOC(CRAMFS_SUPERBLOCK_SIZE);
  if(disk_car->pread(disk_car, buffer, CRAMFS_SUPERBLOCK_SIZE, partition->part_offset + 0x200) == CRAMFS_SUPERBLOCK_SIZE)
  {
    if(test_cramfs(disk_car, (struct cramfs_super*)buffer, partition, verbose)==0)
    {
      set_cramfs_info((struct cramfs_super*)buffer, partition);
      free(buffer);
      return 0;
    }
  }
  if(disk_car->pread(disk_car, buffer, CRAMFS_SUPERBLOCK_SIZE, partition->part_offset) == CRAMFS_SUPERBLOCK_SIZE)
  {
    if(test_cramfs(disk_car, (struct cramfs_super*)buffer, partition, verbose)==0)
    {
      set_cramfs_info((struct cramfs_super*)buffer, partition);
      free(buffer);
      return 0;
    }
  }
  free(buffer);
  return 1;
}

static int test_cramfs(const disk_t *disk_car, const struct cramfs_super *sb, const partition_t *partition, const int verbose)
{
  if (sb->magic!=le32(CRAMFS_MAGIC))
    return 1;
  if(partition==NULL)
    return 0;
  if(verbose>0)
    log_info("\ncramfs Marker at %u/%u/%u\n", offset2cylinder(disk_car,partition->part_offset),offset2head(disk_car,partition->part_offset),offset2sector(disk_car,partition->part_offset));
  return 0;
}

int recover_cramfs(disk_t *disk_car, const struct cramfs_super *sb,partition_t *partition,const int verbose, const int dump_ind)
{
  if(test_cramfs(disk_car, sb, partition, verbose)!=0)
    return 1;
  if(verbose>0 || dump_ind!=0)
  {
    log_trace("\nrecover_cramfs\n");
    if(dump_ind!=0)
    {
      dump_log(sb,DEFAULT_SECTOR_SIZE);
    }
  }
  partition->part_size = sb->size;
  partition->part_type_i386 = P_LINUX;
  partition->part_type_mac= PMAC_LINUX;
  partition->part_type_sun= PSUN_LINUX;
  partition->part_type_gpt= GPT_ENT_TYPE_LINUX_DATA;
  set_cramfs_info(sb, partition);
  return 0;
}

static void set_cramfs_info(const struct cramfs_super *sb, partition_t *partition)
{
  partition->upart_type = UP_CRAMFS;
  set_part_name(partition, (const char*)sb->name, 16);
  strncpy(partition->info,"cramfs",sizeof(partition->info));
}
