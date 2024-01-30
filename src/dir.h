/*

    File: dir.h

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
#ifndef _DIR_H
#define _DIR_H
#ifdef __cplusplus
extern "C" {
#endif
#include "dir_common.h"

/*@
  @ requires \valid(datestr + (0 .. 17));
  @*/
int set_datestr(char *datestr, size_t n, const time_t timev);

/*@
  @ requires dir_data==\null || \valid_read(dir_data);
  @ requires \valid_read(dir_list);
  @ requires \separated(dir_data, dir_list);
  @*/
int dir_aff_log(const dir_data_t *dir_data, const file_info_t*dir_list);

/*@
  @ requires \valid_read(disk_car);
  @ requires valid_disk(disk_car);
  @ requires \valid_read(partition);
  @ requires valid_partition(partition);
  @ requires \valid_read(dir_data);
  @ requires \valid_read(list);
  @*/
void log_list_file(const disk_t *disk_car, const partition_t *partition, const dir_data_t *dir_data, const file_info_t*list);

/*@
  @ requires \valid(list);
  @*/
unsigned int delete_list_file(file_info_t *list);

/*@
  @ requires \valid_read(disk_car);
  @ requires valid_disk(disk_car);
  @ requires \valid_read(partition);
  @ requires valid_partition(partition);
  @ requires \valid_read(dir_data);
  @ requires \separated(disk_car, partition, dir_data);
  @*/
int dir_whole_partition_log(disk_t *disk_car, const partition_t *partition, dir_data_t *dir_data, const unsigned long int inode);

/*@
  @ requires \valid_read(disk_car);
  @ requires valid_disk(disk_car);
  @ requires \valid_read(partition);
  @ requires valid_partition(partition);
  @ requires \valid_read(dir_data);
  @ requires \separated(disk_car, partition, dir_data);
  @*/
void dir_whole_partition_copy(disk_t *disk_car, const partition_t *partition, dir_data_t *dir_data, const unsigned long int inode);

/*@
  @ requires \valid(str + (0 .. 9));
  @ assigns str[0 .. 9];
  @*/
void mode_string (const unsigned int mode, char *str);

/*@
  @ requires valid_read_string(pathname);
  @*/
int set_mode(const char *pathname, unsigned int mode);

/*@
  @ requires valid_read_string(filename);
  @ requires \separated(localfilename, localroot, filename);
  @*/
FILE *fopen_local(char **localfilename, const char *localroot, const char *filename);

/*@
  @ requires valid_read_string(filename);
  @*/
char *gen_local_filename(const char *filename);

/*@
  @ requires valid_read_string(localroot);
  @ requires valid_read_string(pathname);
  @*/
char *mkdir_local(const char *localroot, const char *pathname);

/*@
  @ requires valid_read_string(filename);
  @*/
void mkdir_local_for_file(const char *filename);

/*@
  @ requires \valid_read(a);
  @ requires \valid_read(b);
  @*/
int filesort(const struct td_list_head *a, const struct td_list_head *b);
#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
