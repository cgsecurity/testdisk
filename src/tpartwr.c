/*

    File: tpartwr.c

    Copyright (C) 2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include "lang.h"
#include "intrf.h"
#ifdef HAVE_NCURSES
#include "intrfn.h"
#endif
#include "log.h"
#include "tpartwr.h"

int interface_write(disk_t *disk_car,list_part_t *list_part,const int can_search_deeper, const int can_ask_minmax_ext, int *no_confirm, char **current_cmd, unsigned int *menu)
{
  list_part_t *parts;
#ifdef HAVE_NCURSES
  const struct MenuItem menuWrite[]=
  {
    { 'P', "Previous",""},
    { 'N', "Next","" },
    { 'Q', "Quit","Return to main menu"},
    { 'R', "Return", "Return to partition selection"},
    { 'S', "Deeper Search","Try to find more partitions"},
    { 'W', "Write","Write partition structure to disk"},
    { 'E', "Extd Part","Maximize/Minimize extended partition"},
    { 0, NULL, NULL }
  };
#endif
  int command;
  log_info("\ninterface_write()\n");
  screen_buffer_reset();
#ifdef HAVE_NCURSES
  aff_copy(stdscr);
  wmove(stdscr,4,0);
  wprintw(stdscr,"%s",disk_car->description(disk_car));
  wmove(stdscr,5,0);
  mvwaddstr(stdscr,6,0,msg_PART_HEADER_LONG);
#endif
  for(parts=list_part;parts!=NULL;parts=parts->next)
    if(parts->part->status!=STATUS_LOG)
      aff_part_buffer(AFF_PART_ORDER|AFF_PART_STATUS,disk_car,parts->part);
  for(parts=list_part;parts!=NULL;parts=parts->next)
    if(parts->part->status==STATUS_LOG)
      aff_part_buffer(AFF_PART_ORDER|AFF_PART_STATUS,disk_car,parts->part);
  command='Q';
  if(list_part==NULL)
  {
    screen_buffer_add(" \nNo partition found or selected for recovery");
    screen_buffer_to_log();
    if(*current_cmd!=NULL)
    {
      skip_comma_in_command(current_cmd);
      if(check_command(current_cmd,"search",6)==0)
      {
	command='S';
      }
    }
    else
    {
      char options[10];
      options[0]='R';
      options[1]=0;
      if(can_search_deeper)
	strcat(options,"S");
      log_flush();
#ifdef HAVE_NCURSES
      command=screen_buffer_display_ext(stdscr, options, menuWrite,menu);
#endif
    }
  }
  else
  {
    if(*current_cmd!=NULL)
    {
      do
      {
	command='Q';
	skip_comma_in_command(current_cmd);
	if(check_command(current_cmd,"search",6)==0)
	{
	  if(can_search_deeper)
	    command='S';
	}
	else if(check_command(current_cmd,"noconfirm",9)==0)
	{
	  command=0;	/* do nothing */
	  (*no_confirm)=1;
	}
	else if(check_command(current_cmd,"write",5)==0)
	{
	  if(disk_car->arch->write_part!=NULL)
	    command='W';
	}
      } while(command==0);
      screen_buffer_to_log();
    }
    else
    {
      char options[10];
      options[0]='R';
      options[1]=0;
      if(can_search_deeper)
	strcat(options,"S");
      if(disk_car->arch->write_part!=NULL)
	strcat(options,"W");
      else
	screen_buffer_add(" \nWrite isn't available because the partition table type \"%s\" has been selected.",
	    disk_car->arch->part_name);
      if(can_ask_minmax_ext)
	strcat(options,"E");
      screen_buffer_to_log();
      log_flush();
#ifdef HAVE_NCURSES
      command=screen_buffer_display_ext(stdscr,options,menuWrite,menu);
#else
      command='Q';
#endif
    }
  }
  return command;
}
