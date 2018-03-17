/*

    File: chgtype.c

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
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <assert.h>
#include "types.h"
#include "common.h"
#include "chgtype.h"
#include "log.h"
#include "log_part.h"

extern const arch_fnct_t arch_gpt;
extern const arch_fnct_t arch_none;

static int get_hex_from_command(char **current_cmd)
{
  const int tmp=strtol(*current_cmd, NULL, 16);
  while(*current_cmd[0]!=',' && *current_cmd[0]!='\0')
    (*current_cmd)++;
  return tmp;
}

void change_part_type_cli(const disk_t *disk_car,partition_t *partition, char **current_cmd)
{
  assert(current_cmd!=NULL);
  assert(partition!=NULL);
  if(*current_cmd==NULL || partition->arch==NULL)
    return ;
  if(partition->arch==NULL)
    return;
  if(partition->arch==&arch_gpt)
  {
    partition->arch=&arch_none;
    skip_comma_in_command(current_cmd);
    {
      const int tmp_val=get_hex_from_command(current_cmd);
      partition->arch->set_part_type(partition,tmp_val);
    }
    log_info("Change partition type:\n");
    log_partition(disk_car,partition);
    partition->arch=&arch_gpt;
    return;
  }
  if(partition->arch->set_part_type==NULL)
    return ;
  skip_comma_in_command(current_cmd);
  {
    const int tmp_val=get_hex_from_command(current_cmd);
    partition->arch->set_part_type(partition,tmp_val);
  }
  log_info("Change partition type:\n");
  log_partition(disk_car,partition);
  return ;
}
