/*

    File: addpartn.c

    Copyright (C) 1998-2013 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#ifdef HAVE_NCURSES
#include <stdio.h>
#include "types.h"
#include "common.h"
#include "parti386.h"
#include "partgpt.h"
#include "partmac.h"
#include "partsun.h"
#include "partxbox.h"
#include "parti386n.h"
#include "partgptn.h"
#include "partmacn.h"
#include "partsunn.h"
#include "partxboxn.h"
#include "addpartn.h"

extern const arch_fnct_t arch_gpt;
extern const arch_fnct_t arch_i386;
extern const arch_fnct_t arch_mac;
extern const arch_fnct_t arch_sun;
extern const arch_fnct_t arch_xbox;

list_part_t *add_partition_ncurses(disk_t *disk, list_part_t *list_part)
{
  if(disk->arch==&arch_gpt)
    return add_partition_gpt_ncurses(disk, list_part);
  else if(disk->arch==&arch_i386)
    return add_partition_i386_ncurses(disk, list_part);
  else if(disk->arch==&arch_mac)
    return add_partition_mac_ncurses(disk, list_part);
  else if(disk->arch==&arch_sun)
    return add_partition_sun_ncurses(disk, list_part);
  else if(disk->arch==&arch_xbox)
    return add_partition_xbox_ncurses(disk, list_part);
  return list_part;
}
#endif
