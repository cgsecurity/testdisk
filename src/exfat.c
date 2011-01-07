/*

    File: exfat.c

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
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
 
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "common.h"
#include "exfat.h"

static int set_EXFAT_info(partition_t *partition)
{
  partition->fsname[0]='\0';
  if(partition->sb_offset==0)
    strncpy(partition->info,"exFAT",sizeof(partition->info));
  else
    strncpy(partition->info,"exFAT found using backup sector!",sizeof(partition->info));
  return 0;
}

int check_EXFAT(disk_t *disk_car, partition_t *partition)
{
  unsigned char *buffer=(unsigned char*)MALLOC(EXFAT_BS_SIZE);
  if(disk_car->pread(disk_car, buffer, EXFAT_BS_SIZE, partition->part_offset) != EXFAT_BS_SIZE)
  {
    free(buffer);
    return 1;
  }
  if(test_EXFAT((struct exfat_super_block*)buffer, partition)!=0)
  {
    free(buffer);
    return 1;
  }
  set_EXFAT_info(partition);
  free(buffer);
  return 0;
}

int test_EXFAT(const struct exfat_super_block *exfat_header, partition_t *partition)
{
  if(le16(exfat_header->signature)!=0xAA55)
    return 1;
  if(memcmp(exfat_header->oem_id, "EXFAT   ", sizeof(exfat_header->oem_id))!=0)
    return 1;
  partition->upart_type=UP_EXFAT;
  return 0;
}

int recover_EXFAT(const disk_t *disk, const struct exfat_super_block *exfat_header, partition_t *partition)
{
  if(test_EXFAT(exfat_header, partition)!=0)
    return 1;
  partition->sborg_offset=0;
  partition->sb_size=12 << exfat_header->blocksize_bits;
  partition->part_type_i386=P_EXFAT;
  partition->part_type_gpt=GPT_ENT_TYPE_MS_BASIC_DATA;
  partition->part_size=(uint64_t)le64(exfat_header->nr_sectors) * disk->sector_size;
  if(le64(exfat_header->start_sector) +
      (12 << exfat_header->blocksize_bits) == partition->part_offset)
  {
    partition->sb_offset=12 << exfat_header->blocksize_bits;
    partition->part_offset-=partition->sb_offset;
  }
  set_EXFAT_info(partition);
  return 0;
}
