/*

    File: fat_cluster.h

    Copyright (C) 2008-2009 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifndef _FAT_CLUSTER_H
#define _FAT_CLUSTER_H
#ifdef __cplusplus
extern "C" {
#endif

typedef struct sector_cluster_struct sector_cluster_t;
typedef struct cluster_offset_struct cluster_offset_t;

struct sector_cluster_struct
{
  unsigned int sector;
  unsigned int cluster;
};

struct cluster_offset_struct
{
  unsigned int  sectors_per_cluster;
  unsigned long int offset;
  unsigned int  nbr;
  unsigned int  first_sol;
};

/*@
  @ requires \valid(disk_car);
  @ requires valid_disk(disk_car);
  @ requires \valid_read(partition);
  @ requires valid_partition(partition);
  @ requires \valid(sectors_per_cluster);
  @ requires \valid(offset);
  @ requires \separated(disk_car, partition, sectors_per_cluster, offset);
  @ decreases 0;
  @*/
int find_sectors_per_cluster(disk_t *disk_car, const partition_t *partition, const int verbose, const int dump_ind, unsigned int *sectors_per_cluster, uint64_t *offset, const upart_type_t upart_type);

/*@
  @ assigns \nothing;
  @*/
upart_type_t no_of_cluster2part_type(const unsigned long int no_of_cluster);

/*@
  @ requires \valid_read(sector_cluster + (0 .. nbr_sector_cluster-1));
  @ requires \valid(sectors_per_cluster);
  @ requires \valid(offset);
  @ requires \separated(sector_cluster + (..), sectors_per_cluster, offset);
  @*/
int find_sectors_per_cluster_aux(const sector_cluster_t *sector_cluster, const unsigned int nbr_sector_cluster, unsigned int *sectors_per_cluster, uint64_t *offset, const int verbose, const unsigned long int part_size_in_sectors, const upart_type_t upart_type);

#ifdef __cplusplus
} /* closing brace for extern "c" */
#endif
#endif
