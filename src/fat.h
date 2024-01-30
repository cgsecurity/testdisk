/*

    File: fat.h

    Copyright (C) 1998-2004,2007-2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#ifndef _FAT_H
#define _FAT_H
#ifdef __cplusplus
extern "C" {
#endif

#include "fat_common.h"
/*@
  @ requires \valid(disk);
  @ requires valid_disk(disk);
  @ requires \valid_read(partition);
  @ requires valid_partition(partition);
  @ requires separation: \separated(disk, partition);
  @ decreases 0;
  @*/
int comp_FAT(disk_t *disk, const partition_t *partition, const unsigned long int fat_size, const unsigned long int sect_res);

/*@
  @ requires \valid_read(fh1);
  @ requires \valid_read(fh2);
  @*/
int log_fat2_info(const struct fat_boot_sector*fh1, const struct fat_boot_sector*fh2, const upart_type_t upart_type, const unsigned int sector_size);

/*@
  @ requires \valid(disk);
  @ requires valid_disk(disk);
  @ requires \valid_read(partition);
  @ requires valid_partition(partition);
  @ requires separation: \separated(disk, partition);
  @*/
unsigned int get_next_cluster(disk_t *disk, const partition_t *partition, const upart_type_t upart_type, const int offset, const unsigned int cluster);

/*@
  @ requires \valid(disk);
  @ requires valid_disk(disk);
  @ requires \valid_read(partition);
  @ requires valid_partition(partition);
  @ requires separation: \separated(disk, partition);
  @ decreases 0;
  @*/
int set_next_cluster(disk_t *disk, const partition_t *partition, const upart_type_t upart_type, const int offset, const unsigned int cluster, const unsigned int next_cluster);

/*@
  @ requires \valid_read(partition);
  @ terminates \true;
  @ assigns  \nothing;
  @*/
int is_fat(const partition_t *partition);

/*@
  @ requires \valid_read(partition);
  @ terminates \true;
  @ assigns  \nothing;
  @*/
int is_part_fat(const partition_t *partition);

/*@
  @ requires \valid_read(partition);
  @ terminates \true;
  @ assigns  \nothing;
  @*/
int is_part_fat12(const partition_t *partition);

/*@
  @ requires \valid_read(partition);
  @ terminates \true;
  @ assigns  \nothing;
  @*/
int is_part_fat16(const partition_t *partition);

/*@
  @ requires \valid_read(partition);
  @ terminates \true;
  @ assigns  \nothing;
  @*/
int is_part_fat32(const partition_t *partition);

/*@
  @ requires \valid(disk);
  @ requires valid_disk(disk);
  @ requires \valid_read(partition);
  @ requires valid_partition(partition);
  @ requires separation: \separated(disk, partition);
  @ decreases 0;
  @*/
unsigned int fat32_get_prev_cluster(disk_t *disk, const partition_t *partition, const unsigned int fat_offset, const unsigned int cluster, const unsigned int no_of_cluster);

/*@
  @ requires \valid(disk);
  @ requires valid_disk(disk);
  @ requires \valid_read(partition);
  @ requires valid_partition(partition);
  @ requires separation: \separated(disk, partition);
  @ requires \valid(next_free);
  @ requires \valid(free_count);
  @ decreases 0;
  @*/
int fat32_free_info(disk_t *disk, const partition_t *partition, const unsigned int fat_offset, const unsigned int no_of_cluster, unsigned int *next_free, unsigned int *free_count);

/*@
  @ requires \valid_read(boot_fat32 + (0 .. sector_size + 512 -1));
  @ terminates \true;
  @ assigns  \nothing;
  @*/
unsigned long int fat32_get_free_count(const unsigned char *boot_fat32, const unsigned int sector_size);

/*@
  @ requires \valid_read(boot_fat32 + (0 .. sector_size + 512 -1));
  @ terminates \true;
  @ assigns  \nothing;
  @*/
unsigned long int fat32_get_next_free(const unsigned char *boot_fat32, const unsigned int sector_size);

/*@
  @ requires \valid(disk);
  @ requires valid_disk(disk);
  @ requires \valid_read(fat_header);
  @ requires \valid(partition);
  @ requires valid_partition(partition);
  @ requires separation: \separated(disk, partition, fat_header);
  @*/
int recover_FAT(disk_t *disk, const struct fat_boot_sector*fat_header, partition_t *partition, const int verbose, const int dump_ind, const int backup);

/*@
  @ requires \valid(disk);
  @ requires valid_disk(disk);
  @ requires \valid(partition);
  @ requires valid_partition(partition);
  @ requires separation: \separated(disk, partition);
  @ decreases 0;
  @*/
int check_FAT(disk_t *disk, partition_t *partition, const int verbose);

/*@
  @ requires \valid(disk);
  @ requires valid_disk(disk);
  @ requires \valid_read(fat_header);
  @ requires \valid(partition);
  @ requires valid_partition(partition);
  @ requires separation: \separated(disk, partition, fat_header);
  @*/
int test_FAT(disk_t *disk, const struct fat_boot_sector *fat_header, const partition_t *partition, const int verbose, const int dump_ind);

/*@
  @ requires \valid(disk);
  @ requires valid_disk(disk);
  @ requires \valid_read(fat_header);
  @ requires \valid(partition);
  @ requires valid_partition(partition);
  @ requires separation: \separated(disk, partition, fat_header);
  @*/
int recover_OS2MB(const disk_t *disk, const struct fat_boot_sector*fat_header, partition_t *partition, const int verbose, const int dump_ind);

/*@
  @ requires \valid(disk);
  @ requires valid_disk(disk);
  @ requires \valid(partition);
  @ requires valid_partition(partition);
  @ requires separation: \separated(disk, partition);
  @ decreases 0;
  @*/
int check_OS2MB(disk_t *disk, partition_t *partition, const int verbose);

/*@
  @ requires \valid_read(name);
  @ terminates \true;
  @ assigns \nothing;
  @*/
int check_VFAT_volume_name(const char *name, const unsigned int max_size);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
