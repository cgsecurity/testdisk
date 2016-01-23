/*

    File: sun.c

    Copyright (C) 2004-2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include "types.h"
#include "common.h"
#include "sun.h"
#include "fnctdsk.h"
#include "log.h"
#include "log_part.h"

#define SUN_LABEL_MAGIC          0xDABE
extern const arch_fnct_t arch_sun;

static void set_sun_info_i386(partition_t *partition);
static int test_sun_i386(const disk_t *disk_car, const sun_partition_i386 *sunlabel, const partition_t *partition, const int verbose);

int check_sun_i386(disk_t *disk_car,partition_t *partition,const int verbose)
{
  unsigned char *buffer=(unsigned char*)MALLOC(SUN_PARTITION_I386_SIZE);
  const sun_partition_i386 *sunlabel=(const sun_partition_i386*)buffer;
  if(disk_car->pread(disk_car, buffer, SUN_PARTITION_I386_SIZE, partition->part_offset + 0x200) != SUN_PARTITION_I386_SIZE)
  {
    free(buffer);
    return 1;
  }
  if(test_sun_i386(disk_car, sunlabel, partition, verbose)!=0)
  {
    free(buffer);
    return 1;
  }
  set_sun_info_i386(partition);
  free(buffer);
  return 0;
}

static int test_sun_i386(const disk_t *disk_car, const sun_partition_i386 *sunlabel, const partition_t *partition, const int verbose)
{
  if ((le16(sunlabel->magic) != SUN_LABEL_MAGIC) ||
      (le32(sunlabel->magic_start) != SUN_LABEL_MAGIC_START))
    return 1;
  if(verbose>0)
    log_info("\nSUN Marker at %u/%u/%u\n",
	offset2cylinder(disk_car,partition->part_offset),
	offset2head(disk_car,partition->part_offset),
	offset2sector(disk_car,partition->part_offset));
  {
    int i;
    partition_t *new_partition=partition_new(NULL);
    for(i=0;i<16;i++)
    {
      if (sunlabel->partitions[i].num_sectors > 0
	  && sunlabel->partitions[i].id > 0)
	//	    && sunlabel->partitions[i].id != WHOLE_DISK)
      {
	partition_reset(new_partition, &arch_sun);
	new_partition->order=i;
	new_partition->part_type_sun=sunlabel->partitions[i].id;
	new_partition->part_offset=partition->part_offset+(uint64_t)le32(sunlabel->partitions[i].start_sector) * le16(sunlabel->sector_size);
	new_partition->part_size=(uint64_t)le32(sunlabel->partitions[i].num_sectors) * le16(sunlabel->sector_size);
	new_partition->status=STATUS_PRIM;
	log_partition(disk_car,new_partition);
      }
    }
    free(new_partition);
  }
  return 0;
}

int recover_sun_i386(disk_t *disk_car, const sun_partition_i386 *sunlabel, partition_t *partition,const int verbose, const int dump_ind)
{
  if(test_sun_i386(disk_car, sunlabel, partition, verbose)!=0)
    return 1;
  if(verbose>0 || dump_ind!=0)
  {
    log_info("\nrecover_sun\n");
    if(dump_ind!=0)
    {
      dump_log(sunlabel,sizeof(*sunlabel));
    }
  }
  partition->part_size=(uint64_t)le32(sunlabel->partitions[2].num_sectors) * le16(sunlabel->sector_size);
  set_sun_info_i386(partition);
  partition->part_type_i386 = P_SUN;
  partition->part_type_gpt=GPT_ENT_TYPE_SOLARIS_ROOT;
  return 0;
}

static void set_sun_info_i386(partition_t *partition)
{
  partition->upart_type = UP_SUN;
  partition->info[0]='\0';
  partition->fsname[0]='\0';
}
