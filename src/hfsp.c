/*

    File: hfsp.c

    Copyright (C) 1998-2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include "hfsp.h"
#include "fnctdsk.h"
#include "log.h"

static void set_HFSP_info(partition_t *partition, const struct hfsp_vh *vh)
{
  partition->blocksize=be32(vh->blocksize);
  partition->fsname[0]='\0';
  if (be16(vh->version)==4)
  {
    partition->upart_type=UP_HFSP;
    snprintf(partition->info, sizeof(partition->info), "HFS+ blocksize=%u", partition->blocksize);
  }
  else if (be16(vh->version)==5)
  {
    partition->upart_type=UP_HFSX;
    snprintf(partition->info, sizeof(partition->info), "HFSX blocksize=%u", partition->blocksize);
  }
}


int check_HFSP(disk_t *disk_car,partition_t *partition,const int verbose)
{
  unsigned char *buffer=(unsigned char*)MALLOC(HFSP_BOOT_SECTOR_SIZE);
  if(disk_car->pread(disk_car, buffer, HFSP_BOOT_SECTOR_SIZE, partition->part_offset + 0x400) != HFSP_BOOT_SECTOR_SIZE)
  {
    free(buffer);
    return 1;
  }
  if(test_HFSP(disk_car,(struct hfsp_vh *)buffer,partition,verbose,0)!=0)
  {
    free(buffer);
    return 1;
  }
  set_HFSP_info(partition, (const struct hfsp_vh *)buffer);
  if(disk_car->pread(disk_car, buffer, HFSP_BOOT_SECTOR_SIZE, 
	partition->part_offset + partition->part_size - 0x400) == HFSP_BOOT_SECTOR_SIZE &&
      test_HFSP(disk_car,(struct hfsp_vh *)buffer,partition,verbose,0)==0)
  {
    strcat(partition->info, " + Backup");
  }
  free(buffer);
  return 0;
}

int recover_HFSP(disk_t *disk_car, const struct hfsp_vh *vh,partition_t *partition,const int verbose, const int dump_ind, const int backup)
{
  uint64_t part_size;
  if(test_HFSP(disk_car,vh,partition,verbose,dump_ind)!=0)
    return 1;
  part_size=(uint64_t)be32(vh->total_blocks)*be32(vh->blocksize);
  partition->sborg_offset=0x400;
  partition->sb_size=HFSP_BOOT_SECTOR_SIZE;
  if(backup>0)
  {
    if(partition->part_offset+2*disk_car->sector_size<part_size)
      return 1;
    /* backup is at total_blocks-2 */
    partition->sb_offset=part_size-0x400;
    partition->part_offset-=partition->sb_offset;
  }
  partition->part_size=part_size;
  set_HFSP_info(partition, vh);
  if(backup==0)
  {
    unsigned char *buffer=(unsigned char*)MALLOC(HFSP_BOOT_SECTOR_SIZE);
    if(disk_car->pread(disk_car, buffer, HFSP_BOOT_SECTOR_SIZE, 
	  partition->part_offset + partition->part_size - 0x400) == HFSP_BOOT_SECTOR_SIZE &&
	test_HFSP(disk_car,(struct hfsp_vh *)buffer,partition,verbose,0)==0)
    {
      strcat(partition->info, " + Backup");
    }
    free(buffer);
  }
  partition->part_type_i386=P_HFSP;
  partition->part_type_mac=PMAC_HFS;
  partition->part_type_gpt=GPT_ENT_TYPE_MAC_HFS;
  if(verbose>0)
  {
    log_info("part_size %lu\n",(long unsigned)(partition->part_size/disk_car->sector_size));
  }
  return 0;
}

int test_HFSP(disk_t *disk_car, const struct hfsp_vh *vh, const partition_t *partition, const int verbose, const int dump_ind)
{
  if (be32(vh->free_blocks) > be32(vh->total_blocks))
    return 1;
  /* Blocksize must be a multiple of 512 */
  if (be32(vh->blocksize)<512 ||
      ((be32(vh->blocksize)-1) & be32(vh->blocksize))!=0)
    return 1;
  /* http://developer.apple.com/technotes/tn/tn1150.html */
  if (be16(vh->version)==4 && vh->signature==be16(HFSP_VOLHEAD_SIG))
  {
    if(partition==NULL)
      return 0;
    if(verbose>0 || dump_ind!=0)
    {
      log_info("\nHFS+ magic value at %u/%u/%u\n", offset2cylinder(disk_car,partition->part_offset),offset2head(disk_car,partition->part_offset),offset2sector(disk_car,partition->part_offset));
    }
  }
  else if (be16(vh->version)==5 && vh->signature==be16(HFSX_VOLHEAD_SIG))
  {
    if(partition==NULL)
      return 0;
    if(verbose>0 || dump_ind!=0)
    {
      log_info("\nHFSX magic value at %u/%u/%u\n", offset2cylinder(disk_car,partition->part_offset),offset2head(disk_car,partition->part_offset),offset2sector(disk_car,partition->part_offset));
    }
  }
  else
  {
    return 1;
  }
  if(dump_ind!=0)
  {
    /* There is a little offset ... */
    dump_log(vh,DEFAULT_SECTOR_SIZE);
  }
  if(verbose>1)
  {
    log_info("blocksize %u\n",(unsigned) be32(vh->blocksize));
    log_info("total_blocks %u\n",(unsigned) be32(vh->total_blocks));
    log_info("free_blocks  %u\n",(unsigned) be32(vh->free_blocks));
  }
  return 0;
}
