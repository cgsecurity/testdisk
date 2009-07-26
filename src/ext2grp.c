/*

    File: ext2grp.c

    Copyright (C) 2008-2009 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include "list.h"
#include "filegen.h"
#include "dir.h"
#include "ext2grp.h"
#include "ext2.h"
#include "log.h"
#include "photorec.h"

unsigned int ext2_fix_group(alloc_data_t *list_search_space, disk_t *disk, partition_t *partition)
{
  struct td_list_head *search_walker = NULL;
  unsigned char *buffer;
  unsigned int blocksize;
  if(partition->upart_type!=UP_EXT2 &&
      partition->upart_type!=UP_EXT3 &&
      partition->upart_type!=UP_EXT4)
  {
    log_error("Not a valid ext2/ext3/ext4 filesystem");
    free_search_space(list_search_space);
    return 0;
  }

  buffer=(unsigned char*)MALLOC(EXT2_SUPERBLOCK_SIZE);
  if(disk->pread(disk, buffer, EXT2_SUPERBLOCK_SIZE, partition->part_offset + 0x400) != EXT2_SUPERBLOCK_SIZE)
  {
    free(buffer);
    return 0;
  }
  {
    const struct ext2_super_block *sb=(const struct ext2_super_block *)buffer;
    const unsigned int mult=(unsigned int)le32(sb->s_blocks_per_group) * (EXT2_MIN_BLOCK_SIZE<<le32(sb->s_log_block_size));
    td_list_for_each(search_walker, &list_search_space->list)
    {
      alloc_data_t *current_search_space;
      current_search_space=td_list_entry(search_walker, alloc_data_t, list);
      log_info("ext2_group: %llu\n", (long long unsigned)current_search_space->start);
      current_search_space->start=current_search_space->start*mult + (le32(sb->s_log_block_size)==0?1024:0);
      current_search_space->end=current_search_space->end*mult+mult-1 + (le32(sb->s_log_block_size)==0?1024:0);
    }
    blocksize=EXT2_MIN_BLOCK_SIZE<<le32(sb->s_log_block_size);
  }
  free(buffer);
  return blocksize;
}

unsigned int ext2_fix_inode(alloc_data_t *list_search_space, disk_t *disk, partition_t *partition)
{
  struct td_list_head *search_walker = NULL;
  unsigned char *buffer;
  unsigned int blocksize;
  if(partition->upart_type!=UP_EXT2 &&
      partition->upart_type!=UP_EXT3 &&
      partition->upart_type!=UP_EXT4)
  {
    log_error("Not a valid ext2/ext3/ext4 filesystem");
    free_search_space(list_search_space);
    return 0;
  }

  buffer=(unsigned char*)MALLOC(EXT2_SUPERBLOCK_SIZE);
  if(disk->pread(disk, buffer, EXT2_SUPERBLOCK_SIZE, partition->part_offset + 0x400) != EXT2_SUPERBLOCK_SIZE)
  {
    free(buffer);
    return 0;
  }
  {
    const struct ext2_super_block *sb=(const struct ext2_super_block *)buffer;
    const unsigned int divd=(unsigned int)le32(sb->s_inodes_per_group);
    const unsigned int mult=(unsigned int)le32(sb->s_blocks_per_group) * (EXT2_MIN_BLOCK_SIZE<<le32(sb->s_log_block_size));
    td_list_for_each(search_walker, &list_search_space->list)
    {
      alloc_data_t *current_search_space;
      current_search_space=td_list_entry(search_walker, alloc_data_t, list);
      log_info("ext2_inode: %llu\n", (long long unsigned)current_search_space->start);
      current_search_space->start=current_search_space->start/divd*mult + (sb->s_log_block_size==0?1024:0);
      current_search_space->end=current_search_space->end/divd*mult+mult-1 + (sb->s_log_block_size==0?1024:0);
    }
    blocksize=EXT2_MIN_BLOCK_SIZE<<le32(sb->s_log_block_size);
  }
  free(buffer);
  return blocksize;
}
