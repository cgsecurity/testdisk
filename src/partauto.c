/*

    File: partauto.c

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
#include "types.h"
#include "common.h"
#include "list.h"
#include "fnctdsk.h"
#include "partauto.h"
#include "log.h"

extern const arch_fnct_t arch_gpt;
extern const arch_fnct_t arch_i386;
extern const arch_fnct_t arch_mac;
extern const arch_fnct_t arch_none;
extern const arch_fnct_t arch_sun;
extern const arch_fnct_t arch_xbox;

void autodetect_arch(disk_t *disk)
{
  list_part_t *list_part=NULL;
  const arch_fnct_t *arch=disk->arch;
#ifdef DEBUG_PARTAUTO
  const int verbose=2;
#else
  const int verbose=0;
  unsigned int old_levels;
  old_levels=log_set_levels(0);
#endif
  if(list_part==NULL)
  {
    disk->arch=&arch_none;
    list_part=disk->arch->read_part(disk,verbose,0);
    if(list_part!=NULL && list_part->part!=NULL && list_part->part->upart_type==UP_UNK)
    {
      part_free_list(list_part);
      list_part=NULL;
    }
  }
  if(list_part==NULL)
  {
    disk->arch=&arch_xbox;
    list_part=disk->arch->read_part(disk,verbose,0);
  }
  if(list_part==NULL)
  {
    disk->arch=&arch_gpt;
    list_part=disk->arch->read_part(disk,verbose,0);
  }
  if(list_part==NULL)
  {
    disk->arch=&arch_i386;
    list_part=disk->arch->read_part(disk,verbose,0);
  }
  if(list_part==NULL)
  {
    disk->arch=&arch_sun;
    list_part=disk->arch->read_part(disk,verbose,0);
  }
  if(list_part==NULL)
  {
    disk->arch=&arch_mac;
    list_part=disk->arch->read_part(disk,verbose,0);
  }
  if(list_part==NULL)
    disk->arch=arch;
  log_info("Partition table type (auto): %s\n", disk->arch->part_name);
  part_free_list(list_part);
#ifndef DEBUG_PARTAUTO
  log_set_levels(old_levels);
#endif
}
