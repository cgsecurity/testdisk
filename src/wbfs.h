/*

    File: wbfs.h

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

#ifndef _WBFS_H
#define _WBFS_H
#ifdef __cplusplus
extern "C" {
#endif
#define WBFS_MAGIC (('W'<<24)|('B'<<16)|('F'<<8)|('S'))

struct wbfs_head
{
  uint32_t magic;
  // parameters copied in the partition for easy dumping, and bug reports
  uint32_t n_hd_sec;		// total number of hd_sec in this partition
  uint8_t  hd_sec_sz_s;       	// sector size in this partition
  uint8_t  wbfs_sec_sz_s;     	// size of a wbfs sec
  uint8_t  padding3[2];
  uint8_t  disc_table[0];    	// size depends on hd sector size
} __attribute__ ((__packed__));

int check_WBFS(disk_t *disk,partition_t *partition);
int recover_WBFS(disk_t *disk, const struct wbfs_head *sb, partition_t *partition, const int verbose, const int dump_ind);
#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
