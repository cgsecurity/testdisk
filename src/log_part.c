/*

    File: log_part.c

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
#include "types.h"
#include "common.h"
#include "fnctdsk.h"
#include "log.h"
#include "log_part.h"
#include "intrf.h"	/* aff_part_aux */

void log_partition(const disk_t *disk, const partition_t *partition)
{
  const char *msg;
  char buffer_part_size[100];
  msg=aff_part_aux(AFF_PART_ORDER|AFF_PART_STATUS, disk, partition);
  log_info("%s",msg);
  size_to_unit(partition->part_size, buffer_part_size);
  if(partition->info[0]!='\0')
    log_info("\n     %s, %s", partition->info, buffer_part_size);
  log_info("\n");
}

void log_all_partitions(const disk_t *disk, const list_part_t *list_part)
{
  const list_part_t *element;
  for(element=list_part; element!=NULL; element=element->next)
    log_partition(disk, element->part);
}
