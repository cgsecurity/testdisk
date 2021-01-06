/*

    File: addpartn.h

    Copyright (C) 2013 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#ifndef _ADDPARTN_H
#define _ADDPARTN_H
#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_NCURSES
/*@
  @ requires valid_disk(disk);
  @ requires valid_list_part(list_part);
  @ requires separation: \separated(disk, list_part);
  @*/
list_part_t *add_partition_ncurses(disk_t *disk, list_part_t *list_part);
#endif

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
