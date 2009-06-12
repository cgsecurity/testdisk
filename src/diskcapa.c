/*

    File: diskcapa.c

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
#include "intrf.h"
#ifdef HAVE_NCURSES
#include "intrfn.h"
#endif
#include "log.h"
#include "diskcapa.h"

#ifdef HAVE_NCURSES
static int interface_check_disk_capacity_ncurses(disk_t *disk_car)
{
  static const struct MenuItem menuMain[]=
  {
    { 'C', "Continue","The HD is really 137 GB only."},
    { 'Q',"Quit","The HD is bigger, it's safer to enable LBA48 support first."},
    { 0,NULL,NULL}
  };
  unsigned int menu=1;
  int car;
  aff_copy(stdscr);
  wmove(stdscr,4,0);
  wprintw(stdscr,"%s\n",disk_car->description(disk_car));
  wmove(stdscr,6,0);
  wprintw(stdscr,"The Harddisk size seems to be 137GB.");
  wmove(stdscr,7,0);
  wprintw(stdscr,"Support for 48-bit Logical Block Addressing (LBA) is needed to access");
  wmove(stdscr,8,0);
  wprintw(stdscr,"hard disks larger than 137 GB.");
  wmove(stdscr,9,0);
#if defined(__CYGWIN__) || defined(__MINGW32__)
  wprintw(stdscr,"Update Windows to support LBA48 (minimum: W2K SP4 or XP SP1)");
#endif
  car= wmenuSelect_ext(stdscr, 23, INTER_MAIN_Y, INTER_MAIN_X, menuMain, 10,
      "CQ", MENU_VERT | MENU_VERT_WARN | MENU_BUTTON, &menu,NULL);
  if(car=='c' || car=='C')
    return 0;
  return 1;
}
#endif

int interface_check_disk_capacity(disk_t *disk_car)
{
  /* Test for LBA28 limitation */
  if(disk_car->geom.sectors_per_head>0 &&
      disk_car->geom.cylinders == (((1<<28)-1) / disk_car->geom.heads_per_cylinder / disk_car->geom.sectors_per_head))
  {
    log_warning("LBA28 limitation\n");
    log_flush();
#ifdef HAVE_NCURSES
    return interface_check_disk_capacity_ncurses(disk_car);
#endif
  }
  return 0;
}
