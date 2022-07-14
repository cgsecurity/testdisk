/*

    File: savehdr.h

    Copyright (C) 2004,2006 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifndef _SAVEHDR_H
#define _SAVEHDR_H
#ifdef __cplusplus
extern "C" {
#endif

#include "list.h"
typedef struct
{
  struct td_list_head list;
  time_t my_time;
  char description[128];
  list_part_t *list_part;
} backup_disk_t;

/*@
  @ requires valid_disk(disk_car);
  @ requires valid_partition(partition);
  @ decreases 0;
  @*/
int save_header(disk_t *disk_car, const partition_t *partition, const int verbose);

/*@
  @ requires valid_disk(disk_car);
  @ requires valid_list_part(list_part);
  @ decreases 0;
  @*/
int partition_save(disk_t *disk_car, const list_part_t *list_part, const int verbose);

/*@
  @ requires valid_disk(disk_car);
  @ decreases 0;
  @*/
backup_disk_t *partition_load(const disk_t *disk_car, const int verbose);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
