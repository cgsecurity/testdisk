/*

    File: tdelete.c

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
#include "types.h"
#include "common.h"
#include "lang.h"
#include "intrf.h"
#ifdef HAVE_NCURSES
#include "intrfn.h"
#endif
#include "log.h"
#include "tdelete.h"

#ifdef HAVE_NCURSES
#define INTER_DISK_X	0
#define INTER_DISK_Y	7

int write_clean_table(disk_t *disk_car)
{
  aff_copy(stdscr);
  wmove(stdscr,5,0);
  wprintw(stdscr,"%s\n",disk_car->description(disk_car));
  wmove(stdscr,INTER_DISK_Y,INTER_DISK_X);
  if(disk_car->arch->erase_list_part==NULL)
  {
    display_message("Partition table clearing is not implemented for this partition type.\n");
    return 1;
  }
  wprintw(stdscr,msg_WRITE_CLEAN_TABLE);
  if(ask_YN(stdscr)!=0 && ask_confirmation("Clear partition table, confirm ? (Y/N)")!=0)
  {
    if(disk_car->arch->erase_list_part(disk_car))
    {
      display_message("Write error: Can't clear partition table.\n");
      return 2;
    }
    else
      display_message("Partition table has been cleared.\nYou have to reboot for the change to take effect.\n");
  }
  return 0;
}
#else
int write_clean_table(disk_t *disk_car)
{
  if(disk_car->arch->erase_list_part==NULL)
  {
    log_error("Partition table clearing is not implemented for this partition type.\n");
    return 1;
  }
  if(disk_car->arch->erase_list_part(disk_car))
  {
    log_error("Write error: Can't clear partition table.\n");
    return 2;
  }
  else
    log_info("Partition table has been cleared.\nYou have to reboot for the change to take effect.\n");
  return 0;
}
#endif
