/*

    File: luks.h

    Copyright (C) 2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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

    LUKS on-disk-format: http://luks.endorphin.org/spec
 */
#ifndef _LUKS_H
#define _LUKS_H
#include "luks_struct.h"
#ifdef __cplusplus
extern "C" {
#endif

/*@
  @ requires \valid(disk_car);
  @ requires valid_disk(disk_car);
  @ requires \valid(partition);
  @ requires \separated(disk_car, partition);
  @ decreases 0;
  @*/
int check_LUKS(disk_t *disk_car, partition_t *partition);

/*@
  @ requires \valid_read(disk_car);
  @ requires valid_disk(disk_car);
  @ requires \valid_read(sb);
  @ requires \valid(partition);
  @ requires \separated(disk_car, sb, partition);
  @*/
int recover_LUKS(const disk_t *disk_car, const struct luks_phdr *sb, partition_t *partition, const int verbose, const int dump_ind);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
