/*

    File: iso.c

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
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include "types.h"
#include "common.h"
#include "iso9660.h"
#include "iso.h"
#include "fnctdsk.h"
#include "log.h"
#include "guid_cpy.h"

/*@
  @ requires \valid_read(iso);
  @ requires \valid(partition);
  @ requires valid_partition(partition);
  @ requires \separated(iso, partition);
  @*/
static void set_ISO_info(const struct iso_primary_descriptor *iso, partition_t *partition);

/*@
  @ requires \valid_read(iso);
  @ assigns  \nothing;
  @*/
static int test_ISO(const struct iso_primary_descriptor *iso)
{
  static const unsigned char iso_header[6]= { 0x01, 'C', 'D', '0', '0', '1'};
  if(memcmp(iso, iso_header, sizeof(iso_header))!=0)
    return 1;
  return 0;
}

int check_ISO(disk_t *disk_car, partition_t *partition)
{
  unsigned char *buffer=(unsigned char*)MALLOC(ISO_PD_SIZE);
  /*@ assert \valid(buffer + (0 .. ISO_PD_SIZE-1)); */
  if(disk_car->pread(disk_car, buffer, ISO_PD_SIZE, partition->part_offset + 64 * 512) != ISO_PD_SIZE)
  {
    free(buffer);
    return 1;
  }
  if(test_ISO((struct iso_primary_descriptor*)buffer)!=0)
  {
    free(buffer);
    return 1;
  }
  set_ISO_info((struct iso_primary_descriptor*)buffer, partition);
  free(buffer);
  return 0;
}

static void set_ISO_info(const struct iso_primary_descriptor *iso, partition_t *partition)
{
  const unsigned int volume_space_size_le=le32(iso->volume_space_size_le);
  const unsigned int volume_space_size_be=be32(iso->volume_space_size_be);
  const unsigned int logical_block_size_le=le16(iso->logical_block_size_le);
  const unsigned int logical_block_size_be=be16(iso->logical_block_size_be);
  partition->upart_type=UP_ISO;
  set_part_name_chomp(partition, (const char*)iso->volume_id, 32);
  if(volume_space_size_le==volume_space_size_be && logical_block_size_le==logical_block_size_be)
  {
    partition->blocksize=logical_block_size_le;
    snprintf(partition->info, sizeof(partition->info),
	"ISO9660 blocksize=%u", partition->blocksize);
  }
  else
    snprintf(partition->info, sizeof(partition->info), "ISO");
}

int recover_ISO(const struct iso_primary_descriptor *iso, partition_t *partition)
{
  if(test_ISO(iso)!=0)
    return 1;
  set_ISO_info(iso, partition);
  /*@ assert \valid_read(iso); */
  /*@ assert \valid(partition); */
  {
    const unsigned int volume_space_size_le=le32(iso->volume_space_size_le);
    const unsigned int volume_space_size_be=be32(iso->volume_space_size_be);
    const unsigned int logical_block_size_le=le16(iso->logical_block_size_le);
    const unsigned int logical_block_size_be=be16(iso->logical_block_size_be);
    if(volume_space_size_le==volume_space_size_be && logical_block_size_le==logical_block_size_be)
    {	/* ISO 9660 */
      partition->part_size=(uint64_t)volume_space_size_le * logical_block_size_le;
    }
  }
  return 0;
}
