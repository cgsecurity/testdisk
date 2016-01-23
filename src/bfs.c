/*

    File: bfs.c

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
 
#include "types.h"
#include "common.h"
#include "bfs.h"
#include "fnctdsk.h"
#include "log.h"

static void set_BeFS_info(const struct disk_super_block *beos_block, partition_t *partition);
static int test_BeFS(disk_t *disk_car, const struct disk_super_block*beos_block, const partition_t *partition, const int dump_ind);

int check_BeFS(disk_t *disk_car,partition_t *partition)
{
  unsigned char *buffer;
  buffer=(unsigned char*)MALLOC(BFS_SUPERBLOCK_SIZE);
  if(disk_car->pread(disk_car, buffer, BFS_SUPERBLOCK_SIZE, partition->part_offset + 0x200) != BFS_SUPERBLOCK_SIZE)
  {
    free(buffer);
    return 1;
  }
  if(test_BeFS(disk_car,(struct disk_super_block*)buffer,partition,0)!=0)
  {
    free(buffer);
    return 1;
  }
  set_BeFS_info((struct disk_super_block*)buffer, partition);
  free(buffer);
  return 0;
}

int recover_BeFS(disk_t *disk_car, const struct disk_super_block *beos_block, partition_t *partition, const int dump_ind)
{
  if(test_BeFS(disk_car,beos_block,partition,dump_ind)!=0)
    return 1;
  set_BeFS_info(beos_block, partition);
  partition->part_size=le64(beos_block->num_blocks) << le32(beos_block->block_shift);
  partition->part_type_i386=(unsigned char)P_BEOS;
  return 0;
}

static int test_BeFS(disk_t *disk_car, const struct disk_super_block*beos_block, const partition_t *partition, const int dump_ind)
{
  if(beos_block->magic1!=le32(SUPER_BLOCK_MAGIC1) &&
      beos_block->magic2!=le32(SUPER_BLOCK_MAGIC2) &&
      beos_block->magic3!=le32(SUPER_BLOCK_MAGIC3))
    return 1;
  if(partition==NULL)
    return 0;
  if(dump_ind!=0)
  {
    log_info("\nBeFS magic value at %u/%u/%u\n", offset2cylinder(disk_car,partition->part_offset),offset2head(disk_car,partition->part_offset),offset2sector(disk_car,partition->part_offset));
    dump_log(beos_block,DEFAULT_SECTOR_SIZE);
  }
  return 0;
}

static void set_BeFS_info(const struct disk_super_block *beos_block, partition_t *partition)
{
  partition->upart_type=UP_BEOS;
  partition->blocksize= 1 << le32(beos_block->block_shift);
  partition->info[0]='\0';
  snprintf(partition->info, sizeof(partition->info), "BeFS blocksize=%u", partition->blocksize);
  set_part_name(partition,beos_block->name,B_OS_NAME_LENGTH);
}
