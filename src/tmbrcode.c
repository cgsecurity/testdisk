/*

    File: mbrcode.c

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
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include "types.h"
#include "common.h"
#include "lang.h"
#include "intrf.h"
#ifdef HAVE_NCURSES
#include "intrfn.h"
#endif
#include "log.h"
#include "tmbrcode.h"

#ifdef HAVE_NCURSES
#define INTER_DISK_X	0
#define INTER_DISK_Y	7
int write_MBR_code(disk_t *disk_car)
{
  aff_copy(stdscr);
  wmove(stdscr,5,0);
  wprintw(stdscr,"%s\n",disk_car->description(disk_car));
  wmove(stdscr,INTER_DISK_Y,INTER_DISK_X);
  if(disk_car->arch->write_MBR_code==NULL)
  {
    display_message("Function to write a new MBR code not implemented for this partition type.\n");
    return 1;
  }
  wprintw(stdscr,msg_WRITE_MBR_CODE);
  if(ask_YN(stdscr)!=0 && ask_confirmation("Write a new copy of MBR code, confirm ? (Y/N)")!=0)
  {
    if(disk_car->arch->write_MBR_code(disk_car))
    {
      display_message("Write error: Can't write new MBR code.\n");
      return 2;
    }
    else
      display_message("A new copy of MBR code has been written.\nYou have to reboot for the change to take effect.\n");
  }
  return 0;
}
#else
int write_MBR_code(disk_t *disk_car)
{
  if(disk_car->arch->write_MBR_code==NULL)
  {
    log_error("Function to write a new MBR code not implemented for this partition type.\n");
    return 1;
  }
  if(disk_car->arch->write_MBR_code(disk_car))
  {
    log_error("Write error: Can't write new MBR code.\n");
    return 2;
  }
  else
    log_info("A new copy of MBR code has been written.\nYou have to reboot for the change to take effect.\n");
  return 0;
}
#endif
