/*

    File: chgtypen.c

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

#ifdef HAVE_NCURSES
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include "types.h"
#include "common.h"
#include "intrf.h"
#include "intrfn.h"
#include "fnctdsk.h"
#include "chgtype.h"
#include "chgtypen.h"
#include "log.h"
#include "log_part.h"
#include "guid_cmp.h"
#include "guid_cpy.h"
#include "partgpt.h"

extern const arch_fnct_t arch_gpt;
extern const arch_fnct_t arch_i386;
extern const arch_fnct_t arch_none;
extern const arch_fnct_t arch_sun;
extern const struct systypes_gtp gpt_sys_types[];

struct part_name_struct
{
  unsigned int index;
  const char *name;
};

static void change_part_type_int_ncurses(const disk_t *disk_car, partition_t *partition)
{
  partition_t *new_partition;
  char response[100];
  int size=0;
  int i;
  unsigned int last[3], done = 0, next = 0;
  struct part_name_struct part_name[0x100];
  const struct MenuItem menuType[]=
  {
    { 'P', "Previous",""},
    { 'N', "Next","" },
    { 'Q', "Proceed","Go set the partition type"},
    { 0, NULL, NULL }
  };
  if(partition->arch->set_part_type==NULL)
    return ;
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
  wmove(stdscr,LINES-2,0);
  wclrtoeol(stdscr);
  wprintw(stdscr,"New partition type [current %02x] ? ",partition->arch->get_part_type(partition));
  if (get_string(stdscr, response, sizeof(response), NULL) > 0) {
    const int tmp_val = strtol(response, NULL, 16);
    partition->arch->set_part_type(partition,tmp_val);
  }
}
#define	INTER_CHGTYPE 15
#define	INTER_CHGTYPE_X 0
#define	INTER_CHGTYPE_Y 23

static void change_part_type_list_ncurses(const disk_t *disk_car, partition_t *partition)
{
  partition_t *new_partition;
  unsigned int intr_nbr_line=0;
  unsigned int offset=0;
  unsigned int i;
  unsigned int current_element_num=0;
  struct part_name_struct part_name[0x100];
  if(partition->arch->set_part_type==NULL)
    return ;
  aff_copy(stdscr);
  wmove(stdscr,4,0);
  aff_part(stdscr, AFF_PART_ORDER|AFF_PART_STATUS, disk_car, partition);
  wmove(stdscr,INTER_CHGTYPE_Y, INTER_CHGTYPE_X);
  wattrset(stdscr, A_REVERSE);
  wprintw(stdscr, "[ Proceed ]");
  wattroff(stdscr, A_REVERSE);
  /* Create an index of all partition type except Intel extended */
  new_partition=partition_new(NULL);
  dup_partition_t(new_partition,partition);
  for(i=0;i<=0xFF;i++)
  {
    if(partition->arch->set_part_type(new_partition,i)==0)
    {
      part_name[intr_nbr_line].name=new_partition->arch->get_partition_typename(new_partition);
      if(part_name[intr_nbr_line].name!=NULL)
      {
	if(partition->arch->get_part_type(partition)==i)
	  current_element_num=intr_nbr_line;
	part_name[intr_nbr_line++].index=i;
      }
    }
  }
  free(new_partition);
  while(1)
  {
    wmove(stdscr,5,0);
    wprintw(stdscr, "Please choose the partition type, press Enter when done.");
    wmove(stdscr,5+1,1);
    wclrtoeol(stdscr);
    if(offset>0)
      wprintw(stdscr, "Previous");
    for(i=offset;i<intr_nbr_line && (i-offset)<3*INTER_CHGTYPE;i++)
    {
      if(i-offset<INTER_CHGTYPE)
	wmove(stdscr,5+2+i-offset,0);
      else if(i-offset<2*INTER_CHGTYPE)
	wmove(stdscr,5+2+i-offset-INTER_CHGTYPE,26);
      else
	wmove(stdscr,5+2+i-offset-2*INTER_CHGTYPE,52);
      wclrtoeol(stdscr);	/* before addstr for BSD compatibility */
      if(i==current_element_num)
      {
	wattrset(stdscr, A_REVERSE);
	wprintw(stdscr,">%s", part_name[i].name);
	wattroff(stdscr, A_REVERSE);
      } else
      {
	wprintw(stdscr," %s", part_name[i].name);
      }
    }
    if(i-offset<INTER_CHGTYPE)
      wmove(stdscr,5+2+i-offset,1);
    else if(i-offset<2*INTER_CHGTYPE)
      wmove(stdscr,5+2+i-offset-INTER_CHGTYPE,27);
    else
      wmove(stdscr,5+2+i-offset-2*INTER_CHGTYPE,53);
    wclrtoeol(stdscr);
    if(i<intr_nbr_line)
      wprintw(stdscr, "Next");
    switch(wgetch(stdscr))
    {
      case 'p':
      case 'P':
      case KEY_UP:
	if(current_element_num>0)
	  current_element_num--;
	break;
      case 'n':
      case 'N':
      case KEY_DOWN:
	if(current_element_num < intr_nbr_line-1)
	  current_element_num++;
	break;
      case KEY_LEFT:
	if(current_element_num > INTER_CHGTYPE)
	  current_element_num-=INTER_CHGTYPE;
	else
	  current_element_num=0;
	break;
      case KEY_PPAGE:
	if(current_element_num > 3*INTER_CHGTYPE-1)
	  current_element_num-=3*INTER_CHGTYPE-1;
	else
	  current_element_num=0;
	break;
      case KEY_RIGHT:
	if(current_element_num+INTER_CHGTYPE < intr_nbr_line-1)
	  current_element_num+=INTER_CHGTYPE;
	else
	  current_element_num=intr_nbr_line-1;
	break;
      case KEY_NPAGE:
	if(current_element_num+3*INTER_CHGTYPE-1 < intr_nbr_line-1)
	  current_element_num+=3*INTER_CHGTYPE-1;
	else
	  current_element_num=intr_nbr_line-1;
	break;
      case 'Q':
      case 'q':
      case key_CR:
#ifdef PADENTER
      case PADENTER:
#endif
	partition->arch->set_part_type(partition, part_name[current_element_num].index);
	return;
    }
    if(current_element_num < offset)
      offset=current_element_num;
    if(current_element_num >= offset+3*INTER_CHGTYPE)
      offset=current_element_num-3*INTER_CHGTYPE+1;
  }
}

static void gpt_change_part_type(const disk_t *disk_car, partition_t *partition)
{
  unsigned int offset=0;
  unsigned int i,j;
  unsigned int current_element_num=0;
  log_info("gpt_change_part_type\n");
  aff_copy(stdscr);
  wmove(stdscr,4,0);
  aff_part(stdscr, AFF_PART_ORDER|AFF_PART_STATUS, disk_car, partition);
  wmove(stdscr,INTER_CHGTYPE_Y, INTER_CHGTYPE_X);
  wattrset(stdscr, A_REVERSE);
  wprintw(stdscr, "[ Proceed ]");
  wattroff(stdscr, A_REVERSE);
  /* By default, select the current type */
  for(i=0;gpt_sys_types[i].name!=NULL;i++)
  {
    if(guid_cmp(partition->part_type_gpt, gpt_sys_types[i].part_type)==0)
    {
      current_element_num=i;
      while(current_element_num >= offset+3*INTER_CHGTYPE)
	offset++;
    }
  }
  while(1)
  {
    wmove(stdscr,5,0);
    wprintw(stdscr, "Please choose the partition type, press Enter when done.");
    wmove(stdscr,5+1,1);
    wclrtoeol(stdscr);
    if(offset>0)
      wprintw(stdscr, "Previous");
    for(i=offset;gpt_sys_types[i].name!=NULL && (i-offset)<3*INTER_CHGTYPE;i++)
    {
      if(i-offset<INTER_CHGTYPE)
	wmove(stdscr,5+2+i-offset,0);
      else if(i-offset<2*INTER_CHGTYPE)
	wmove(stdscr,5+2+i-offset-INTER_CHGTYPE,26);
      else
	wmove(stdscr,5+2+i-offset-2*INTER_CHGTYPE,52);
      wclrtoeol(stdscr);	/* before addstr for BSD compatibility */
      if(i==current_element_num)
      {
	wattrset(stdscr, A_REVERSE);
	wprintw(stdscr,">%s", gpt_sys_types[i].name);
	wattroff(stdscr, A_REVERSE);
      } else
      {
	wprintw(stdscr," %s", gpt_sys_types[i].name);
      }
    }
    if(i-offset<INTER_CHGTYPE)
      wmove(stdscr,5+2+i-offset,1);
    else if(i-offset<2*INTER_CHGTYPE)
      wmove(stdscr,5+2+i-offset-INTER_CHGTYPE,27);
    else
      wmove(stdscr,5+2+i-offset-2*INTER_CHGTYPE,53);
    wclrtoeol(stdscr);
    if(gpt_sys_types[i].name!=NULL)
      wprintw(stdscr, "Next");
    switch(wgetch(stdscr))
    {
      case 'p':
      case 'P':
      case KEY_UP:
	if(current_element_num>0)
	  current_element_num--;
	break;
      case 'n':
      case 'N':
      case KEY_DOWN:
	if(gpt_sys_types[current_element_num].name!=NULL && gpt_sys_types[current_element_num+1].name!=NULL)
	  current_element_num++;
	break;
      case KEY_LEFT:
	if(current_element_num > INTER_CHGTYPE)
	  current_element_num-=INTER_CHGTYPE;
	else
	  current_element_num=0;
	break;
      case KEY_PPAGE:
	if(current_element_num > 3*INTER_CHGTYPE-1)
	  current_element_num-=3*INTER_CHGTYPE-1;
	else
	  current_element_num=0;
	break;
      case KEY_RIGHT:
	for(j=0;j<INTER_CHGTYPE;j++)
	{
	  if(gpt_sys_types[current_element_num].name!=NULL && gpt_sys_types[current_element_num+1].name!=NULL)
	    current_element_num++;
	}
	break;
      case KEY_NPAGE:
	for(j=0;j<3*INTER_CHGTYPE;j++)
	{
	  if(gpt_sys_types[current_element_num].name!=NULL && gpt_sys_types[current_element_num+1].name!=NULL)
	    current_element_num++;
	}
	break;
      case 'Q':
      case 'q':
      case key_CR:
#ifdef PADENTER
      case PADENTER:
#endif
	guid_cpy(&partition->part_type_gpt, &gpt_sys_types[current_element_num].part_type);
	return;
    }
    if(current_element_num<offset)
      offset=current_element_num;
    if(current_element_num >= offset+3*INTER_CHGTYPE)
      offset=current_element_num-3*INTER_CHGTYPE+1;
  }
}

void change_part_type_ncurses(const disk_t *disk_car, partition_t *partition)
{
  if(partition->arch==NULL)
  {
    log_error("change_part_type arch==NULL\n");
    return;
  }
  if(partition->arch==&arch_gpt)
  {
    gpt_change_part_type(disk_car, partition);
    log_info("Change partition type:\n");
    log_partition(disk_car,partition);
    partition->arch=&arch_none;
    change_part_type_list_ncurses(disk_car, partition);
    log_info("Change partition type:\n");
    log_partition(disk_car,partition);
    partition->arch=&arch_gpt;
    return ;
  }
  if(partition->arch->set_part_type==NULL)
  {
    log_error("change_part_type set_part_type==NULL\n");
    return;
  }
  if(partition->arch==&arch_i386 || partition->arch==&arch_sun)
    change_part_type_int_ncurses(disk_car, partition);
  else
    change_part_type_list_ncurses(disk_car, partition);
  log_info("Change partition type:\n");
  log_partition(disk_car,partition);
}
#endif
