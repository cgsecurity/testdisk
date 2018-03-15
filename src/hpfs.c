/*

    File: hpfs.c

    Copyright (C) 1998-2009 Christophe GRENIER <grenier@cgsecurity.org>

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
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>     /* free */
#endif
#include "types.h"
#include "common.h"
#include "fat.h"
#include "fat_common.h"
#include "hpfs.h"
#include "fnctdsk.h"
#include "intrf.h"
#include "log.h"
#include "log_part.h"

static void set_HPFS_info(partition_t *partition)
{
  partition->upart_type=UP_HPFS;
}

static int test_HPFS(disk_t *disk_car, const struct fat_boot_sector *hpfs_header, const partition_t *partition, const int verbose, const int dump_ind)
{
  const char*buffer=(const char*)hpfs_header;
  if(le16(hpfs_header->marker)==0xAA55)
  {
    if(memcmp(buffer+OS2_NAME,"IBM",3)==0)
    {   /* D'apres une analyse de OS2 sur systeme FAT...
           FAT_NAME1=FAT
         */
      if(verbose||dump_ind)
      {
        log_info("\nHPFS maybe at %u/%u/%u\n",
            offset2cylinder(disk_car,partition->part_offset),
            offset2head(disk_car,partition->part_offset),
            offset2sector(disk_car,partition->part_offset));
      }
      if(dump_ind!=0)
        dump_log(buffer, DEFAULT_SECTOR_SIZE);
      return 0;
    }
  }     /* fin marqueur de fin :)) */
  return 1;
}

int recover_HPFS(disk_t *disk_car, const struct fat_boot_sector *hpfs_header, partition_t *partition, const int verbose)
{
  if(test_HPFS(disk_car, hpfs_header, partition, verbose,0)!=0)
    return 1;
  set_HPFS_info(partition);
  partition->part_type_i386=P_HPFS;
  partition->part_type_gpt=GPT_ENT_TYPE_MAC_HFS;
  partition->fsname[0]='\0';
  partition->info[0]='\0';
  partition->part_size=(uint64_t)(fat_sectors(hpfs_header)>0?fat_sectors(hpfs_header):le32(hpfs_header->total_sect)) *
    fat_sector_size(hpfs_header);
  return 0;
}

int check_HPFS(disk_t *disk_car,partition_t *partition,const int verbose)
{
  unsigned char *buffer=(unsigned char *)MALLOC(disk_car->sector_size);
  if((unsigned)disk_car->pread(disk_car, buffer, disk_car->sector_size, partition->part_offset) != disk_car->sector_size)
  {
    screen_buffer_add("check_HPFS: Read error\n");
    log_error("check_HPFS: Read error\n");
    free(buffer);
    return 1;
  }
  if(test_HPFS(disk_car,(const struct fat_boot_sector *)buffer,partition,verbose,0)!=0)
  {
    if(verbose>0)
    {
      log_info("\n\ntest_HPFS()\n");
      log_partition(disk_car,partition);
    }
    free(buffer);
    return 1;
  }
  set_HPFS_info(partition);
  free(buffer);
  return 0;
}
