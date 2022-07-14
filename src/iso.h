/*

    File: iso.h

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

#ifndef _ISO_H
#define _ISO_H
#ifdef __cplusplus
extern "C" {
#endif
/*@
  @ requires \valid(disk_car);
  @ requires valid_disk(disk_car);
  @ requires \valid(partition);
  @ requires valid_partition(partition);
  @ requires separation: \separated(disk_car, partition);
  @ decreases 0;
  @*/
int check_ISO(disk_t *disk_car, partition_t *partition);

/*@
  @ requires \valid_read(iso);
  @ requires \valid(partition);
  @ requires valid_partition(partition);
  @ requires separation: \separated(iso, partition);
  @*/
int recover_ISO(const struct iso_primary_descriptor *iso, partition_t *partition);
#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
