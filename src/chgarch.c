/*

    File: chgarch.c

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

#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include "types.h"
#include "common.h"
#include "log.h"
#include "log_part.h"
#include "autoset.h"
#include "hdaccess.h"
#include "chgarch.h"

extern const arch_fnct_t arch_i386;
extern const arch_fnct_t arch_gpt;
extern const arch_fnct_t arch_humax;
extern const arch_fnct_t arch_mac;
extern const arch_fnct_t arch_none;
extern const arch_fnct_t arch_sun;
extern const arch_fnct_t arch_xbox;


/* return 1 if user need to give the partition table type */
int change_arch_type_cli(disk_t *disk, const int verbose, char**current_cmd)
{
  const arch_fnct_t *arch_list[]={&arch_i386, &arch_gpt, &arch_humax, &arch_mac, &arch_none, &arch_sun, &arch_xbox, NULL};
  int keep_asking;
  if(*current_cmd==NULL)
    return 1;
  do
  {
    int i;
    keep_asking=0;
    skip_comma_in_command(current_cmd);
    for(i=0;arch_list[i]!=NULL;i++)
      if(check_command(current_cmd, arch_list[i]->part_name_option, strlen(arch_list[i]->part_name_option))==0)
      {
	disk->arch=arch_list[i];
	keep_asking=1;
      }
    if(check_command(current_cmd, "ask_type", 8)==0)
    {
      return 1;
    }
  } while(keep_asking>0);
  autoset_unit(disk);
  hd_update_geometry(disk, verbose);
  log_info("%s\n",disk->description_short(disk));
  log_info("Partition table type: %s\n", disk->arch->part_name);
  return 0;
}
