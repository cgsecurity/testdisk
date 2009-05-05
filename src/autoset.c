/*

    File: autoset.c

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
#include "types.h"
#include "common.h"
#include "autoset.h"

extern const arch_fnct_t arch_gpt;
extern const arch_fnct_t arch_mac;

void autoset_unit(disk_t *disk)
{
  if(disk==NULL)
    return ;
  if(
    disk->arch==&arch_mac || 
      disk->arch==&arch_gpt || 
      (disk->geom.heads_per_cylinder==1 && disk->geom.sectors_per_head==1))
    disk->unit=UNIT_SECTOR;
  else
    disk->unit=UNIT_CHS;
}
