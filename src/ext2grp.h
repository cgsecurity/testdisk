/*

    File: ext2grp.h

    Copyright (C) 2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifndef _EXT2GRP_H
#define _EXT2GRP_H
#ifdef __cplusplus
extern "C" {
#endif

/*@
  @ requires valid_list_search_space(list_search_space);
  @ requires valid_disk(disk);
  @ requires valid_partition(partition);
  @ requires \valid(disk);
  @ requires \valid_read(partition);
  @ requires \separated(list_search_space, disk, partition);
  @ decreases 0;
  @ ensures  valid_disk(disk);
  @*/
// ensures  valid_list_search_space(list_search_space);
// ensures  valid_partition(partition);
unsigned int ext2_fix_group(alloc_data_t *list_search_space, disk_t *disk, const partition_t *partition);

/*@
  @ requires valid_list_search_space(list_search_space);
  @ requires valid_disk(disk);
  @ requires valid_partition(partition);
  @ requires \valid(disk);
  @ requires \valid_read(partition);
  @ requires \separated(list_search_space, disk, partition);
  @ decreases 0;
  @ ensures  valid_disk(disk);
  @*/
// ensures  valid_list_search_space(list_search_space);
// ensures  valid_partition(partition);
unsigned int ext2_fix_inode(alloc_data_t *list_search_space, disk_t *disk, const partition_t *partition);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
