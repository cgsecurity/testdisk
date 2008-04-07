/*

    File: chgtype.c

    Copyright (C) 1998-2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include "lang.h"
#include "intrf.h"
#include "intrfn.h"
#include "fnctdsk.h"
#include "chgtype.h"
#include "log.h"
#include "guid_cmp.h"

extern const arch_fnct_t arch_gpt;
extern const arch_fnct_t arch_none;

struct part_name_struct
{
  unsigned int index;
  const char *name;
};

static void change_part_type_cli(const disk_t *disk_car,partition_t *partition, char **current_cmd)
{
  while(*current_cmd[0]==',')
    (*current_cmd)++;
  {
    int tmp_val= strtol(*current_cmd, NULL, 16);
    while(*current_cmd[0]!=',' && *current_cmd[0]!='\0')
      (*current_cmd)++;
    partition->arch->set_part_type(partition,tmp_val);
  }
}

#ifdef HAVE_NCURSES
static void change_part_type_ncurses(const disk_t *disk_car,partition_t *partition)
{
  partition_t *new_partition;
  char response[100];
  int size=0;
  int i;
  unsigned int last[3], done = 0, next = 0;
  struct part_name_struct part_name[0x100];
  struct MenuItem menuType[]=
  {
    { 'P', "Previous",""},
    { 'N', "Next","" },
    { 'Q', "Proceed","Go set the partition type"},
    { 0, NULL, NULL }
  };
  /* Create an index of all partition type except Intel extended */
  new_partition=partition_new(NULL);
  dup_partition_t(new_partition,partition);
  for(i=0;i<=0xFF;i++)
  {
    if(partition->arch->set_part_type(new_partition,i)==0)
    {
      part_name[size].name=new_partition->arch->get_partition_typename(new_partition);
      if(part_name[size].name!=NULL)
	part_name[size++].index=i;
    }
  }
  free(new_partition);

  /* Display the list of partition type in 3 columns */
  screen_buffer_reset();
  screen_buffer_add("List of partition type\n");
  for (i = 2; i >= 0; i--)
    last[2 - i] = done += (size + i - done) / (i + 1);
  i = done = 0;
  while (done < last[0])
  {
    screen_buffer_add( "%02x %-20s%c",  part_name[next].index, part_name[next].name,(i==2 ? '\n' : ' '));
    next = last[i++] + done;
    if (i > 2 || next >= last[i]) {
      i = 0;
      next = ++done;
    }
  }

  /* Ask for the new partition type*/
  aff_copy(stdscr);
  wmove(stdscr,4,0);
  aff_part(stdscr,AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition);
  screen_buffer_display(stdscr,"",menuType);
  wmove(stdscr,23,0);
  wprintw(stdscr,"New partition type [current %02x] ? ",partition->arch->get_part_type(partition));
  if (get_string(response, sizeof(response), NULL) > 0) {
    int tmp_val = strtol(response, NULL, 16);
    partition->arch->set_part_type(partition,tmp_val);
  }
}
#endif

void change_part_type(const disk_t *disk_car,partition_t *partition, char **current_cmd)
{
  const arch_fnct_t *arch=partition->arch;
  if(partition->arch==NULL)
  {
    log_error("change_part_type arch==NULL\n");
    return;
  }
  if(partition->arch==&arch_gpt)
    partition->arch=&arch_none;
  if(partition->arch->set_part_type==NULL)
  {
    log_error("change_part_type set_part_type==NULL\n");
    partition->arch=arch;
    return;
  }
  if(*current_cmd!=NULL)
    change_part_type_cli(disk_car, partition, current_cmd);
  else
  {
#ifdef HAVE_NCURSES
    change_part_type_ncurses(disk_car, partition);
#endif
  }
  if(arch==&arch_gpt)
  {
    partition->arch=arch;
    /* TODO: use upart_type to set part_type_gpt */
    if(guid_cmp(partition->part_type_gpt, GPT_ENT_TYPE_UNUSED)==0)
      partition->part_type_gpt=GPT_ENT_TYPE_MS_BASIC_DATA;
  }
  log_info("Change partition type:\n");
  log_partition(disk_car,partition);
}
