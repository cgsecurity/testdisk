/*

    File: ext2_sb.h

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
#ifndef _EXT2_SB_H
#define _EXT2_SB_H
#ifdef __cplusplus
extern "C" {
#endif

/*@
  @ requires \valid(disk_car);
  @ requires valid_disk(disk_car);
  @ requires valid_list_part(list_part);
  @ requires \valid(current_cmd);
  @ requires valid_read_string(*current_cmd);
  @ requires separation: \separated(disk_car, list_part, current_cmd);
  @ ensures  valid_read_string(*current_cmd);
  @*/
int interface_superblock(disk_t *disk_car, const list_part_t *list_part, char**current_cmd);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
