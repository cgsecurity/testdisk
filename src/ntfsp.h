/*

    File: ntfsp.h

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

 */
#ifndef _NTFSP_H
#define _NTFSP_H
#ifdef __cplusplus
extern "C" {
#endif

#if defined(HAVE_LIBNTFS) || defined(HAVE_LIBNTFS3G)
/*@
  @ requires \valid(disk_car);
  @ requires valid_disk(disk_car);
  @ requires valid_list_search_space(list_search_space);
  @ requires \separated(disk_car, partition, list_search_space);
  @ ensures  valid_list_search_space(list_search_space);
  @*/
unsigned int ntfs_remove_used_space(disk_t *disk_car, const partition_t *partition, alloc_data_t *list_search_space);
#endif

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
