/*

    file: analyse.h

    Copyright (C) 1998-2004 Christophe GRENIER <grenier@cgsecurity.org>
  
    this software is free software; you can redistribute it and/or modify
    it under the terms of the gnu general public license as published by
    the free software foundation; either version 2 of the license, or
    (at your option) any later version.
  
    this program is distributed in the hope that it will be useful,
    but without any warranty; without even the implied warranty of
    merchantability or fitness for a particular purpose.  see the
    gnu general public license for more details.
  
    You should have received a copy of the GNU General Public License along
    with this program; if not, write the Free Software Foundation, Inc., 51
    Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

 */
#ifndef _ANALYSE_H
#define _ANALYSE_H
#ifdef __cplusplus
extern "C" {
#endif

/*@
  @ requires \valid(disk_car);
  @ requires valid_disk(disk_car);
  @ requires \valid(partition);
  @ requires valid_partition(partition);
  @ requires \separated(buffer, disk_car, partition);
  @ decreases 0;
  @*/
int search_type_0(const unsigned char *buffer, disk_t *disk_car,partition_t *partition,const int verbose, const int dump_ind);

/*@
  @ requires \valid_read(disk_car);
  @ requires valid_disk(disk_car);
  @ requires \valid(partition);
  @ requires valid_partition(partition);
  @ requires \separated(buffer, disk_car, partition);
  @ decreases 0;
  @*/
int search_type_1(const unsigned char *buffer, const disk_t *disk_car, partition_t *partition, const int verbose, const int dump_ind);

/*@
  @ requires \valid(disk_car);
  @ requires valid_disk(disk_car);
  @ requires \valid(partition);
  @ requires valid_partition(partition);
  @ requires \separated(buffer, disk_car, partition);
  @ decreases 0;
  @*/
int search_type_2(const unsigned char *buffer, disk_t *disk_car,partition_t *partition,const int verbose, const int dump_ind);

/*@
  @ requires \valid(disk_car);
  @ requires valid_disk(disk_car);
  @ requires \valid(partition);
  @ requires valid_partition(partition);
  @ requires \separated(buffer, disk_car, partition);
  @ decreases 0;
  @*/
int search_type_8(unsigned char *buffer, disk_t *disk_car,partition_t *partition,const int verbose, const int dump_ind);

/*@
  @ requires \valid(disk_car);
  @ requires valid_disk(disk_car);
  @ requires \valid(partition);
  @ requires valid_partition(partition);
  @ requires \separated(buffer, disk_car, partition);
  @ decreases 0;
  @*/
int search_type_16(unsigned char *buffer, disk_t *disk_car,partition_t *partition,const int verbose, const int dump_ind);

/*@
  @ requires \valid(disk_car);
  @ requires valid_disk(disk_car);
  @ requires \valid(partition);
  @ requires valid_partition(partition);
  @ requires \separated(buffer, disk_car, partition);
  @ decreases 0;
  @*/
int search_type_64(unsigned char *buffer, disk_t *disk_car,partition_t *partition,const int verbose, const int dump_ind);

/*@
  @ requires \valid(disk_car);
  @ requires valid_disk(disk_car);
  @ requires \valid(partition);
  @ requires valid_partition(partition);
  @ requires \separated(buffer, disk_car, partition);
  @ decreases 0;
  @*/
int search_type_128(unsigned char *buffer, disk_t *disk_car,partition_t *partition,const int verbose, const int dump_ind);

/*@
  @ requires \valid(disk_car);
  @ requires valid_disk(disk_car);
  @ requires \valid(partition);
  @ requires valid_partition(partition);
  @ requires \separated(buffer, disk_car, partition);
  @ decreases 0;
  @*/
int search_type_2048(unsigned char *buffer, disk_t *disk_car,partition_t *partition,const int verbose, const int dump_ind);

/*@
  @ requires \valid(disk);
  @ requires valid_disk(disk);
  @ requires \valid(partition);
  @ requires valid_partition(partition);
  @ requires \separated(buffer, disk, partition);
  @ decreases 0;
  @*/
int search_exFAT_backup(unsigned char *buffer, disk_t *disk, partition_t *partition);

/*@
  @ requires \valid(disk_car);
  @ requires valid_disk(disk_car);
  @ requires \valid(partition);
  @ requires valid_partition(partition);
  @ requires \separated(buffer, disk_car, partition);
  @ decreases 0;
  @*/
int search_FAT_backup(unsigned char *buffer, disk_t *disk_car,partition_t *partition, const int verbose, const int dump_ind);

/*@
  @ requires \valid(disk_car);
  @ requires valid_disk(disk_car);
  @ requires \valid(partition);
  @ requires valid_partition(partition);
  @ requires \separated(buffer, disk_car, partition);
  @ decreases 0;
  @*/
int search_HFS_backup(unsigned char *buffer, disk_t *disk_car,partition_t *partition, const int verbose, const int dump_ind);

/*@
  @ requires \valid(disk_car);
  @ requires valid_disk(disk_car);
  @ requires \valid(partition);
  @ requires valid_partition(partition);
  @ requires \separated(buffer, disk_car, partition);
  @ decreases 0;
  @*/
int search_NTFS_backup(unsigned char *buffer, disk_t *disk_car,partition_t *partition, const int verbose, const int dump_ind);

/*@
  @ requires \valid(disk);
  @ requires valid_disk(disk);
  @ requires \valid(partition);
  @ requires valid_partition(partition);
  @ requires \separated(disk, partition);
  @*/
int check_linux(disk_t *disk, partition_t *partition, const int verbose);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
