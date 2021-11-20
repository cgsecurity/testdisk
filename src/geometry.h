/*

    File: geometry.h

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
#ifndef _GEOMETRY_H
#define _GEOMETRY_H
#ifdef __cplusplus
extern "C" {
#endif

/*@
  @ requires \valid(disk);
  @ requires valid_disk(disk);
  @ requires 0 < disk->geom.sectors_per_head;
  @ requires 0 < disk->geom.heads_per_cylinder;
  @ assigns disk->geom.cylinders;
  @*/
void set_cylinders_from_size_up(disk_t *disk);

/*@
  @ requires \valid(disk);
  @ requires valid_disk(disk);
  @ assigns disk->sector_size, disk->geom.cylinders;
  @*/
int change_sector_size(disk_t *disk, const int cyl_modified, const unsigned int sector_size);

/*@
  @ requires \valid(disk);
  @ requires valid_disk(disk);
  @ requires \valid_function(disk->description);
  @ requires \valid(current_cmd);
  @ requires valid_read_string(*current_cmd);
  @ requires separation: \separated(disk, current_cmd, *current_cmd);
  @*/
// ensures  valid_read_string(*current_cmd);
int change_geometry_cli(disk_t *disk, char **current_cmd);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
