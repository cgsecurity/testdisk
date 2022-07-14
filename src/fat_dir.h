/*

    File: fat_dir.h

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
#ifndef _FAT_DIR_H
#define _FAT_DIR_H
#ifdef __cplusplus
extern "C" {
#endif
#include "dir_common.h"

/*@
  @ requires \valid_read(buffer + (0 .. size-1));
  @ requires \initialized(buffer + (0 .. size-1));
  @ requires \valid(dir_list);
  @ requires \separated(dir_list, buffer+(..));
  @*/
int dir_fat_aux(const unsigned char*buffer, const unsigned int size, const unsigned int param, file_info_t *dir_list);

/*@
  @ requires \valid(disk_car);
  @ requires valid_disk(disk_car);
  @ requires \valid_read(partition);
  @ requires valid_partition(partition);
  @ requires \valid(dir_data);
  @ requires \separated(disk_car, partition, dir_data);
  @ decreases 0;
  @*/
dir_partition_t dir_partition_fat_init(disk_t *disk_car, const partition_t *partition, dir_data_t *dir_data, const int verbose);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
