/*

    File: chgtype.h

    Copyright (C) 1998-2009 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifndef _CHGTYPE_H
#define _CHGTYPE_H
#ifdef __cplusplus
extern "C" {
#endif

/*@
  @ requires \valid_read(disk_car);
  @ requires valid_disk(disk_car);
  @ requires \valid(partition);
  @ requires valid_partition(partition);
  @ requires \valid(current_cmd);
  @ requires \separated(disk_car, partition, current_cmd);
  @ decreases 0;
  @*/
void change_part_type_cli(const disk_t *disk_car,partition_t *partition, char **current_cmd);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
