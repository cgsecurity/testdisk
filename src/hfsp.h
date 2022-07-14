/*
    File: hfsp.h, TestDisk

    Copyright (C) 2005-2021 Christophe GRENIER <grenier@cgsecurity.org>

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
#ifndef _HFSP_H
#define _HFSP_H
#ifdef __cplusplus
extern "C" {
#endif
#include "hfsp_struct.h"

/*@
  @ requires \valid(disk_car);
  @ requires valid_disk(disk_car);
  @ requires \valid(partition);
  @ requires \separated(disk_car, partition);
  @ decreases 0;
  @*/
int check_HFSP(disk_t *disk_car, partition_t *partition, const int verbose);

/*@
  @ requires \valid_read(disk_car);
  @ requires valid_disk(disk_car);
  @ requires \valid_read(vh);
  @ requires \valid_read(partition);
  @ requires \separated(disk_car, vh, partition);
  @*/
int test_HFSP(const disk_t *disk_car, const struct hfsp_vh *vh, const partition_t *partition, const int verbose, const int dump_ind);

/*@
  @ requires \valid(disk_car);
  @ requires valid_disk(disk_car);
  @ requires \valid_read(vh);
  @ requires \valid(partition);
  @ requires \separated(disk_car, vh, partition);
  @ decreases 0;
  @*/
int recover_HFSP(disk_t *disk_car, const struct hfsp_vh *vh, partition_t *partition, const int verbose, const int dump_ind, const int backup);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
