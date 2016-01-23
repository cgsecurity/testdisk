/*

    File: fatx.c

    Copyright (C) 2005-2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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
 
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include "types.h"
#include "common.h"
#include "fatx.h"
static void set_FATX_info(partition_t *partition);

static int test_fatx(const struct disk_fatx *fatx_block)
{
  if(memcmp(fatx_block->magic,"FATX",4)!=0)
    return 1;
  return 0;
}

int check_FATX(disk_t *disk_car,partition_t *partition)
{
  unsigned char buffer[8*DEFAULT_SECTOR_SIZE];
  if(disk_car->pread(disk_car, &buffer, sizeof(buffer), partition->part_offset) != sizeof(buffer))
  { return 1; }
  if(test_fatx((const struct disk_fatx *)&buffer)!=0)
    return 1;
  set_FATX_info(partition);
  return 0;
}

int recover_FATX(const struct disk_fatx *fatx_block, partition_t *partition)
{
  if(test_fatx(fatx_block)!=0)
    return 1;
  set_FATX_info(partition);
  partition->part_type_xbox=PXBOX_FATX;
  /* FIXME: Locate the partition but cannot get the part_size unfortunatly */
  partition->part_size=(uint64_t)le32(fatx_block->cluster_size_in_sector)*512;
  return 0;
}

static void set_FATX_info(partition_t *partition)
{
  partition->upart_type=UP_FATX;
  partition->fsname[0]='\0';
  strncpy(partition->info,"FATX",sizeof(partition->info));
}
