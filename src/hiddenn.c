/*

    File: hiddenn.c

    Copyright (C) 2008-2009 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include "intrf.h"
#include "intrfn.h"
#include "hiddenn.h"

#define INTER_DISK_X		0
#define INTER_DISK_Y		18

int interface_check_hidden_ncurses(disk_t *disk, const int hpa_dco)
{
  static const struct MenuItem menuHidden[]=
  {
    { 'C', "Continue", "Continue even if there is hidden data"},
    { 0,NULL,NULL}
  };
  unsigned int menu=0;
  int car;
  int line=8;
  aff_copy(stdscr);
  wmove(stdscr,4,0);
  wprintw(stdscr,"%s\n",disk->description_short(disk));
  wmove(stdscr,6,0);
  wprintw(stdscr,"Hidden sectors are present.");
  if(disk->sector_size!=0)
  {
    wmove(stdscr,line++,0);
    wprintw(stdscr, "size       %llu sectors\n", (long long unsigned)(disk->disk_real_size/disk->sector_size));
  }
  if(disk->user_max!=0)
  {
    wmove(stdscr,line++,0);
    wprintw(stdscr, "user_max   %llu sectors\n", (long long unsigned)disk->user_max);
  }
  if(disk->native_max!=0)
  {
    wmove(stdscr,line++,0);
    wprintw(stdscr, "native_max %llu sectors\n", (long long unsigned)(disk->native_max+1));
  }
  if(disk->dco!=0)
  {
    wmove(stdscr,line++,0);
    wprintw(stdscr, "dco        %llu sectors\n", (long long unsigned)(disk->dco+1));
  }
  if(hpa_dco&1)
  {
      wmove(stdscr,line++,0);
      wprintw(stdscr, "Host Protected Area (HPA) present.\n");
  }
  if(hpa_dco&2)
  {
    wmove(stdscr,line,0);
    wprintw(stdscr, "Device Configuration Overlay (DCO) present.\n");
  }
  car= wmenuSelect_ext(stdscr, 23, INTER_DISK_Y, INTER_DISK_X, menuHidden, 10,
      "CQ", MENU_VERT | MENU_VERT_WARN | MENU_BUTTON, &menu,NULL);
  if(car=='c' || car=='C')
    return 0;
  return 1;
}
#endif
