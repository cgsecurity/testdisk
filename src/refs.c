/*

    File: refs.c

    Copyright (C) 2015 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include "refs.h"

static void set_ReFS_info(partition_t *partition, const struct ReFS_boot_sector *refs_header)
{
  partition->fsname[0]='\0';
  partition->info[0]='\0';
  snprintf(partition->info, sizeof(partition->info), "ReFS");
}

static int test_ReFS(const struct ReFS_boot_sector *refs_header, partition_t *partition)
{
  if(refs_header->fsname!=be32(0x52654653))
    return 1;
  if(refs_header->identifier!=be32(0x46535253))
    return 1;
  partition->upart_type=UP_ReFS;
  return 0;
}

int check_ReFS(disk_t *disk, partition_t *partition)
{
  unsigned char *buffer=(unsigned char*)MALLOC(ReFS_BS_SIZE);
  if(disk->pread(disk, buffer, ReFS_BS_SIZE, partition->part_offset) != ReFS_BS_SIZE)
  {
    free(buffer);
    return 1;
  }
  if(test_ReFS((struct ReFS_boot_sector*)buffer, partition)!=0)
  {
    free(buffer);
    return 1;
  }
  set_ReFS_info(partition, (struct ReFS_boot_sector*)buffer);
  free(buffer);
  return 0;
}

int recover_ReFS(const disk_t *disk, const struct ReFS_boot_sector *refs_header, partition_t *partition)
{
  if(test_ReFS(refs_header, partition)!=0)
    return 1;
  partition->sborg_offset=0;
  partition->sb_size=0x200;
  partition->part_type_i386=P_NTFS;
  partition->part_type_gpt=GPT_ENT_TYPE_MS_BASIC_DATA;
  partition->part_size=disk->sector_size;
  set_ReFS_info(partition, refs_header);
  return 0;
}
