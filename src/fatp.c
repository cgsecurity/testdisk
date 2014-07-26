/*

    File: fatp.c

    Copyright (C) 2006-2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include "types.h"
#include "common.h"
#include "list.h"
#include "filegen.h"
#include "fatp.h"
#include "fat.h"
#include "fat_common.h"
#include "log.h"

static void fat16_remove_used_space(disk_t *disk_car,const partition_t *partition, alloc_data_t *list_search_space, const unsigned int fat_offset, const unsigned int no_of_cluster, const unsigned int start_data, const unsigned int cluster_size, const unsigned int sector_size);
static void fat32_remove_used_space(disk_t *disk_car,const partition_t *partition, alloc_data_t *list_search_space, const unsigned int fat_offset, const unsigned int no_of_cluster, const unsigned int start_data, const unsigned int cluster_size, const unsigned int sector_size);

static void fat12_remove_used_space(disk_t *disk,const partition_t *partition, alloc_data_t *list_search_space, const unsigned int fat_offset, const unsigned int no_of_cluster, const unsigned int start_data, const unsigned int cluster_size, const unsigned int sector_size)
{
  unsigned char *buffer;
  unsigned int cluster;
  const uint64_t hd_offset=partition->part_offset+(uint64_t)fat_offset*sector_size;
  uint64_t start_free=0;
  uint64_t end_free=0;
  unsigned long int offset_s_prev=0;
  log_trace("fat12_remove_used_space\n");
  buffer=(unsigned char *)MALLOC(2*sector_size);
  del_search_space(list_search_space, partition->part_offset,
      partition->part_offset + (uint64_t)start_data * sector_size - 1);
  for(cluster=2; cluster<=no_of_cluster+1; cluster++)
  {
    unsigned long int offset_s,offset_o;
    unsigned int next_cluster;
    offset_s=(cluster+cluster/2)/disk->sector_size;
    offset_o=(cluster+cluster/2)%disk->sector_size;
    if(offset_s!=offset_s_prev || cluster==2)
    {
      offset_s_prev=offset_s;
      if((unsigned)disk->pread(disk, buffer, 2*sector_size, hd_offset + offset_s * disk->sector_size) != 2*sector_size)
      {
	/* Consider these FAT sectors points to free clusters */
      }
    }
    if((cluster&1)!=0)
      next_cluster=le16((*((uint16_t*)&buffer[offset_o])))>>4;
    else
      next_cluster=le16(*((uint16_t*)&buffer[offset_o]))&0x0FFF;
    if(next_cluster!=0)
    {
      /* Not free */
      if(end_free+1==partition->part_offset+(start_data+(uint64_t)(cluster-2)*cluster_size)*sector_size)
	end_free+=cluster_size*sector_size;
      else
      {
	if(start_free != end_free)
	  del_search_space(list_search_space, start_free, end_free);
	start_free=partition->part_offset+(start_data+(uint64_t)(cluster-2)*cluster_size)*sector_size;
	end_free=start_free+(uint64_t)cluster_size*sector_size-1;
      }
    }
  }
  free(buffer);
  if(start_free != end_free)
    del_search_space(list_search_space, start_free, end_free);
}

static void fat16_remove_used_space(disk_t *disk_car,const partition_t *partition, alloc_data_t *list_search_space, const unsigned int fat_offset, const unsigned int no_of_cluster, const unsigned int start_data, const unsigned int cluster_size, const unsigned int sector_size)
{
  unsigned char *buffer;
  const uint16_t *p16;
  unsigned int prev_cluster;
  uint64_t hd_offset=partition->part_offset+(uint64_t)fat_offset*sector_size;
  uint64_t start_free=0;
  uint64_t end_free=0;
  log_trace("fat16_remove_used_space\n");
  buffer=(unsigned char *)MALLOC(sector_size);
  p16=(const uint16_t*)buffer;
  del_search_space(list_search_space, partition->part_offset,
      partition->part_offset + (uint64_t)start_data * sector_size - 1);
  for(prev_cluster=2;prev_cluster<=no_of_cluster+1;prev_cluster++)
  {
    unsigned int offset_o;
    offset_o=prev_cluster%(sector_size/2);
    if((offset_o==0)||(prev_cluster==2))
    {
      if((unsigned)disk_car->pread(disk_car, buffer, sector_size, hd_offset) != sector_size)
      {
	/* Consider these FAT sectors points to free clusters */
      }
      hd_offset+=sector_size;
    }
    if(le16(p16[offset_o])!=0)
    {
      /* Not free */
      if(end_free+1==partition->part_offset+(start_data+(uint64_t)(prev_cluster-2)*cluster_size)*sector_size)
	end_free+=cluster_size*sector_size;
      else
      {
	if(start_free != end_free)
	  del_search_space(list_search_space, start_free, end_free);
	start_free=partition->part_offset+(start_data+(uint64_t)(prev_cluster-2)*cluster_size)*sector_size;
	end_free=start_free+(uint64_t)cluster_size*sector_size-1;
      }
    }
  }
  free(buffer);
  if(start_free != end_free)
    del_search_space(list_search_space, start_free, end_free);
}

static void fat32_remove_used_space(disk_t *disk_car,const partition_t *partition, alloc_data_t *list_search_space, const unsigned int fat_offset, const unsigned int no_of_cluster, const unsigned int start_data, const unsigned int cluster_size, const unsigned int sector_size)
{
  unsigned char *buffer;
  uint32_t *p32;
  unsigned int prev_cluster;
  uint64_t hd_offset=partition->part_offset+(uint64_t)fat_offset*sector_size;
  uint64_t start_free=0;
  uint64_t end_free=0;
  log_trace("fat32_remove_used_space\n");
  buffer=(unsigned char *)MALLOC(sector_size);
  p32=(uint32_t*)buffer;
  del_search_space(list_search_space, partition->part_offset,
      partition->part_offset + (uint64_t)start_data * sector_size - 1);
  for(prev_cluster=2;prev_cluster<=no_of_cluster+1;prev_cluster++)
  {
    unsigned long int cluster;
    unsigned int offset_o;
    offset_o=prev_cluster%(sector_size/4);
    if((offset_o==0)||(prev_cluster==2))
    {
      if((unsigned)disk_car->pread(disk_car, buffer, sector_size, hd_offset) != sector_size)
      {
	/* Consider these FAT sectors points to free clusters */
      }
      hd_offset+=sector_size;
    }
    cluster=le32(p32[offset_o]) & 0xFFFFFFF;
    if(cluster!=0)
    {
      /* Not free */
      if(end_free+1==partition->part_offset+(uint64_t)(start_data+(prev_cluster-2)*cluster_size)*sector_size)
	end_free+=cluster_size*sector_size;
      else
      {
	if(start_free != end_free)
	  del_search_space(list_search_space, start_free, end_free);
	start_free=partition->part_offset+(start_data+(uint64_t)(prev_cluster-2)*cluster_size)*sector_size;
	end_free=start_free+(uint64_t)cluster_size*sector_size-1;
      }
    }
  }
  free(buffer);
  if(start_free != end_free)
    del_search_space(list_search_space, start_free, end_free);
}

unsigned int fat_remove_used_space(disk_t *disk_car, const partition_t *partition, alloc_data_t *list_search_space)
{
    unsigned long int fat_length;
    unsigned long int start_fat1;
    unsigned long int part_size;
    unsigned int no_of_cluster;
    unsigned int start_data;
    unsigned char *buffer;
    unsigned int res;
    unsigned int sector_size;
    const struct fat_boot_sector *fat_header;
    buffer=(unsigned char *)MALLOC(3*disk_car->sector_size);
    fat_header=(const struct fat_boot_sector *)buffer;
    if((unsigned)disk_car->pread(disk_car, buffer, 3 * disk_car->sector_size, partition->part_offset) != 3 * disk_car->sector_size)
    {
      free(buffer);
      return 0;
    }
    sector_size=fat_sector_size(fat_header);
    if(sector_size==0)
    {
      free(buffer);
      return 0;
    }
    fat_length=le16(fat_header->fat_length)>0?le16(fat_header->fat_length):le32(fat_header->fat32_length);
    part_size=(fat_sectors(fat_header)>0?fat_sectors(fat_header):le32(fat_header->total_sect));
    start_fat1=le16(fat_header->reserved);
    start_data=start_fat1+fat_header->fats*fat_length+(get_dir_entries(fat_header)*32+sector_size-1)/sector_size;
    no_of_cluster=(part_size-start_data)/fat_header->sectors_per_cluster;
    if(partition->upart_type==UP_FAT12)
      fat12_remove_used_space(disk_car,partition, list_search_space, start_fat1, no_of_cluster, start_data, fat_header->sectors_per_cluster,sector_size);
    else if(partition->upart_type==UP_FAT16)
      fat16_remove_used_space(disk_car,partition, list_search_space, start_fat1, no_of_cluster, start_data, fat_header->sectors_per_cluster,sector_size);
    else if(partition->upart_type==UP_FAT32)
      fat32_remove_used_space(disk_car,partition, list_search_space, start_fat1, no_of_cluster, start_data, fat_header->sectors_per_cluster,sector_size);
    res=fat_header->sectors_per_cluster * sector_size;
    free(buffer);
    return res;
}
