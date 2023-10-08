/*

    File: addpart.h

    Copyright (C) 2009 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#ifndef _ADDPART_H
#define _ADDPART_H
/*@
  @ requires \valid(disk);
  @ requires valid_disk(disk);
  @ requires valid_list_part(list_part);
  @ requires \valid(current_cmd);
  @ requires valid_read_string(*current_cmd);
  @ requires separation: \separated(disk, list_part, current_cmd);
  @*/
list_part_t *add_partition_cli(disk_t *disk, list_part_t *list_part, char **current_cmd);
#endif
