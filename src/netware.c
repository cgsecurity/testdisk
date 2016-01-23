/*

    File: netware.c

    Copyright (C) 1998-2005 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include "types.h"
#include "common.h"
#include "netware.h"

static int test_netware(const struct disk_netware *netware_block)
{
  if(memcmp(netware_block->magic,"Nw_PaRtItIoN",12)==0)
  {
    return 0;
  }
  return 1;
}

int check_netware(disk_t *disk_car, partition_t *partition)
{
  unsigned char *buffer=(unsigned char *)MALLOC(DEFAULT_SECTOR_SIZE);
  if(disk_car->pread(disk_car, buffer, DEFAULT_SECTOR_SIZE, partition->part_offset) != DEFAULT_SECTOR_SIZE)
  {
    free(buffer);
    return 1;
  }
  if(test_netware((const struct disk_netware *)buffer)!=0)
  {
    free(buffer);
    return 1;
  }
  partition->upart_type=UP_NETWARE;
  free(buffer);
  return 0;
}

int recover_netware(disk_t *disk_car, const struct disk_netware *netware_block,partition_t *partition)
{
  if(test_netware(netware_block)!=0)
    return 1;
  partition->upart_type=UP_NETWARE;
  partition->part_type_i386=P_NETWARE;
  partition->part_size=(uint64_t)le32(netware_block->nbr_sectors) * disk_car->sector_size;
  partition->fsname[0]='\0';
  partition->info[0]='\0';
  return 0;
}
