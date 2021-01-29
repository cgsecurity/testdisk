/*

    file: ext2_sbn.h

    Copyright (C) 2009 Christophe GRENIER <grenier@cgsecurity.org>
  
    this software is free software; you can redistribute it and/or modify
    it under the terms of the gnu general public license as published by
    the free software foundation; either version 2 of the license, or
    (at your option) any later version.
  
    this program is distributed in the hope that it will be useful,
    but without any warranty; without even the implied warranty of
    merchantability or fitness for a particular purpose.  see the
    gnu general public license for more details.
  
    You should have received a copy of the GNU General Public License along
    with this program; if not, write the Free Software Foundation, Inc., 51
    Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

 */
#ifndef _EXT2_SBN_H
#define _EXT2_SBN_H
#ifdef __cplusplus
extern "C" {
#endif

/*@
  @ requires \valid(disk_car);
  @ requires valid_disk(disk_car);
  @ requires \valid(partition);
  @ requires valid_partition(partition);
  @ ensures  valid_list_part(\result);
  @*/
list_part_t *search_superblock(disk_t *disk_car, partition_t *partition, const int verbose, const int dump_ind);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
