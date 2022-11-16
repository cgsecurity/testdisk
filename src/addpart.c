/*

    File: addpart.c

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
#include <assert.h>
#include "types.h"
#include "common.h"
#include "parti386.h"
#include "partgpt.h"
#include "parthumax.h"
#include "partmac.h"
#include "partsun.h"
#include "partxbox.h"
#include "addpart.h"

#if !defined(SINGLE_PARTITION_TYPE) || defined(SINGLE_PARTITION_GPT)
extern const arch_fnct_t arch_gpt;
#endif
#if !defined(SINGLE_PARTITION_TYPE) || defined(SINGLE_PARTITION_HUMAX)
extern const arch_fnct_t arch_humax;
#endif
#if !defined(SINGLE_PARTITION_TYPE) || defined(SINGLE_PARTITION_I386)
extern const arch_fnct_t arch_i386;
#endif
#if !defined(SINGLE_PARTITION_TYPE) || defined(SINGLE_PARTITION_MAC)
extern const arch_fnct_t arch_mac;
#endif
#if !defined(SINGLE_PARTITION_TYPE) || defined(SINGLE_PARTITION_SUN)
extern const arch_fnct_t arch_sun;
#endif
#if !defined(SINGLE_PARTITION_TYPE) || defined(SINGLE_PARTITION_XBOX)
extern const arch_fnct_t arch_xbox;
#endif

list_part_t *add_partition_cli(disk_t *disk, list_part_t *list_part, char **current_cmd)
{
  assert(current_cmd!=NULL);
  /*@ assert valid_read_string(*current_cmd); */
#if !defined(SINGLE_PARTITION_TYPE) || defined(SINGLE_PARTITION_GPT)
  if(disk->arch==&arch_gpt)
    return add_partition_gpt_cli(disk, list_part, current_cmd);
#endif
#if !defined(SINGLE_PARTITION_TYPE) || defined(SINGLE_PARTITION_I386)
  if(disk->arch==&arch_i386)
    return add_partition_i386_cli(disk, list_part, current_cmd);
#endif
#if !defined(SINGLE_PARTITION_TYPE) || defined(SINGLE_PARTITION_HUMAX)
  if(disk->arch==&arch_humax)
    return add_partition_humax_cli(disk, list_part, current_cmd);
#endif
#if !defined(SINGLE_PARTITION_TYPE) || defined(SINGLE_PARTITION_MAC)
  if(disk->arch==&arch_mac)
    return add_partition_mac_cli(disk, list_part, current_cmd);
#endif
#if !defined(SINGLE_PARTITION_TYPE) || defined(SINGLE_PARTITION_SUN)
  if(disk->arch==&arch_sun)
    return add_partition_sun_cli(disk, list_part, current_cmd);
#endif
#if !defined(SINGLE_PARTITION_TYPE) || defined(SINGLE_PARTITION_XBOX)
  if(disk->arch==&arch_xbox)
    return add_partition_xbox_cli(disk, list_part, current_cmd);
#endif
  return list_part;
}
