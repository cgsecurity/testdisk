/*

    File: pdisksel.c

    Copyright (C) 2014 Christophe GRENIER <grenier@cgsecurity.org>

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
#include "types.h"
#include "common.h"
#include "list.h"
#include "filegen.h"
#include "partauto.h"
#include "pdisksel.h"
extern const arch_fnct_t arch_none;

disk_t *photorec_disk_selection_cli(const char *cmd_device, const list_disk_t *list_disk, alloc_data_t *list_search_space)
{
  const list_disk_t *element_disk;
  disk_t *disk=NULL;
  for(element_disk=list_disk;element_disk!=NULL;element_disk=element_disk->next)
  {
    if(strcmp(element_disk->disk->device, cmd_device)==0)
      disk=element_disk->disk;
  }
  if(disk==NULL)
    return NULL;
  {
    /* disk sector size is now known, fix the sector ranges */
    struct td_list_head *search_walker = NULL;
    td_list_for_each(search_walker, &list_search_space->list)
    {
      alloc_data_t *current_search_space;
      current_search_space=td_list_entry(search_walker, alloc_data_t, list);
      current_search_space->start=current_search_space->start*disk->sector_size;
      current_search_space->end=current_search_space->end*disk->sector_size+disk->sector_size-1;
    }
  }
  autodetect_arch(disk, &arch_none);
  return disk;
}

