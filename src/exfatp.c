/*

    File: fatp.c

    Copyright (C) 2010 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include "exfatp.h"
#include "exfat.h"
#include "log.h"
#include "fat.h"

static struct exfat_alloc_bitmap_entry *exfat_get_bitmap(unsigned char*buffer, const unsigned int size)
{
  unsigned int i;
  for(i=0; i<size; i+=0x20)
    if(buffer[i]==0x81)
      return (struct exfat_alloc_bitmap_entry *)&buffer[i];
  return NULL;
}

unsigned int exfat_remove_used_space(disk_t *disk, const partition_t *partition, alloc_data_t *list_search_space)
{
  struct exfat_super_block *exfat_header;
  unsigned int cluster_shift;
  /* Load boot sector */
  exfat_header=(struct exfat_super_block *)MALLOC(0x200);
  if(disk->pread(disk, exfat_header, 0x200, partition->part_offset) != 0x200)
  {
    log_error("Can't read exFAT boot sector.\n");
    free(exfat_header);
    return 0;
  }
  cluster_shift=exfat_header->block_per_clus_bits + exfat_header->blocksize_bits;
  /* Load bitmap information */
  {
    const struct exfat_alloc_bitmap_entry *bitmap;
    const uint64_t start=partition->part_offset +
      exfat_cluster_to_offset(exfat_header, le32(exfat_header->rootdir_clusnr));
    unsigned char *buffer_rootdir=(unsigned char *)MALLOC(1<<cluster_shift);
    unsigned char *buffer;
    unsigned int i;
    unsigned int cluster_bitmap;
    const uint64_t start_exfat1=(uint64_t)le32(exfat_header->fat_blocknr) << exfat_header->blocksize_bits;
    uint64_t start_free=0;
    uint64_t end_free=0;
    if(disk->pread(disk, buffer_rootdir, 1 << cluster_shift, start) != (1<<cluster_shift))
    {
      log_error("exFAT: Can't root directory cluster.\n");
      free(buffer_rootdir);
      free(exfat_header);
      return 0; 
    }
    bitmap=exfat_get_bitmap(buffer_rootdir, 1<<cluster_shift);
    if(bitmap==NULL)
    {
      log_error("exFAT: Can't find bitmap.\n");
      free(buffer_rootdir);
      free(exfat_header);
      return 0; 
    }
    cluster_bitmap=le32(bitmap->first_cluster);
    log_trace("exfat_remove_used_space\n");
    buffer=(unsigned char *)MALLOC(1<<cluster_shift);
    for(i=2; i<le32(exfat_header->total_clusters)+2; i++)
    {
      const unsigned int offset_o=(i-2)%(8<<cluster_shift);
      if(offset_o==0)
      {
	exfat_read_cluster(disk, partition, exfat_header, buffer, cluster_bitmap);
	cluster_bitmap=get_next_cluster(disk, partition, UP_FAT32, start_exfat1, cluster_bitmap);
      }
      if(((buffer[offset_o/8]>>(offset_o%8))&1) != 0)
      {
	/* Not free */
	if(end_free+1==partition->part_offset + exfat_cluster_to_offset(exfat_header, i))
	  end_free+=(1<<cluster_shift);
	else
	{
	  if(start_free != end_free)
	    del_search_space(list_search_space, start_free, end_free);
	  start_free=partition->part_offset + exfat_cluster_to_offset(exfat_header, i);
	  end_free=start_free + (1<<cluster_shift) - 1;
	}
      }
    }
    free(buffer);
    if(start_free != end_free)
      del_search_space(list_search_space, start_free, end_free);
    free(buffer_rootdir);
    free(exfat_header);
  }
  return (1<<cluster_shift);
}
