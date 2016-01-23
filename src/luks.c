/*

    File: luks.c

    Copyright (C) 2007 Christophe GRENIER <grenier@cgsecurity.org>

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
#include "luks.h"
#include "fnctdsk.h"
#include "log.h"
#include "guid_cpy.h"

static int test_LUKS(disk_t *disk_car, const struct luks_phdr *sb, const partition_t *partition, const int dump_ind);
static void set_LUKS_info(const struct luks_phdr *sb, partition_t *partition);

int check_LUKS(disk_t *disk_car,partition_t *partition)
{
  unsigned char *buffer=(unsigned char*)MALLOC(DEFAULT_SECTOR_SIZE);
  if(disk_car->pread(disk_car, buffer, DEFAULT_SECTOR_SIZE, partition->part_offset) != DEFAULT_SECTOR_SIZE)
  {
    free(buffer);
    return 1;
  }
  if(test_LUKS(disk_car, (struct luks_phdr*)buffer, partition, 0)!=0)
  {
    free(buffer);
    return 1;
  }
  set_LUKS_info((struct luks_phdr*)buffer, partition);
  free(buffer);
  return 0;
}

static void set_LUKS_info(const struct luks_phdr *sb, partition_t *partition)
{
  partition->upart_type=UP_LUKS;
  if(partition->part_size > 0)
    sprintf(partition->info,"LUKS %u", be16(sb->version));
  else
    sprintf(partition->info,"LUKS %u (Data size unknown)", be16(sb->version));
}

int recover_LUKS(disk_t *disk_car, const struct luks_phdr *sb,partition_t *partition,const int verbose, const int dump_ind)
{
  if(test_LUKS(disk_car, sb, partition, dump_ind)!=0)
    return 1;
  if(partition==NULL)
    return 0;
  set_LUKS_info(sb, partition);
  partition->part_type_i386=P_LINUX;
  partition->part_type_mac=PMAC_LINUX;
  partition->part_type_sun=PSUN_LINUX;
  partition->part_type_gpt=GPT_ENT_TYPE_LINUX_DATA;
  partition->part_size=(uint64_t)be32(sb->payloadOffset)*disk_car->sector_size;
  partition->blocksize=0;
  partition->sborg_offset=0;
  partition->sb_offset=0;
  /* sb->uuid is bigger than part_uuid */
  guid_cpy(&partition->part_uuid, (const efi_guid_t *)&sb->uuid);
  if(verbose>0)
  {
    log_info("\n");
  }
  return 0;
}

static int test_LUKS(disk_t *disk_car, const struct luks_phdr *sb, const partition_t *partition, const int dump_ind)
{
  static const uint8_t LUKS_MAGIC[LUKS_MAGIC_L] = {'L','U','K','S', 0xba, 0xbe};
  if(memcmp(sb->magic, LUKS_MAGIC, LUKS_MAGIC_L)!=0)
    return 1;
  if(dump_ind!=0)
  {
    if(partition!=NULL && disk_car!=NULL)
      log_info("\nLUKS magic value at %u/%u/%u\n",
          offset2cylinder(disk_car,partition->part_offset),
          offset2head(disk_car,partition->part_offset),
          offset2sector(disk_car,partition->part_offset));
    dump_log(sb,DEFAULT_SECTOR_SIZE);
  }
  return 0;
}
