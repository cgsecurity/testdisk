/*

    File: diskacc.c

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
#include "intrf.h"
#ifdef HAVE_NCURSES
#include "intrfn.h"
#endif
#include "log.h"
#include "diskacc.h"

#define INTER_DISK_X		0
#define INTER_DISK_Y		18

#ifdef HAVE_NCURSES
static int interface_check_disk_access_ncurses(disk_t *disk_car)
{
  static const struct MenuItem menuDiskAccess[]=
  {
    { 'C', "Continue", "Continue even if write access isn't available"},
    { 'Q', "Quit", "Return to disk selection"},
    { 0,NULL,NULL}
  };
  unsigned int menu=0;
  int car;
  int line=9;
  aff_copy(stdscr);
  wmove(stdscr,4,0);
  wprintw(stdscr,"%s\n",disk_car->description_short(disk_car));
  wmove(stdscr,6,0);
  wprintw(stdscr,"Write access for this media is not available.");
  wmove(stdscr,7,0);
  wprintw(stdscr,"TestDisk won't be able to modify it.");
#ifdef DJGPP
#elif defined(__CYGWIN__) || defined(__MINGW32__)
  wmove(stdscr,line++,0);
  wprintw(stdscr,"- You may need to be administrator to have write access.\n");
  wmove(stdscr,line++,0);
  wprintw(stdscr,"Under Vista, select TestDisk, right-click and choose \"Run as administrator\".\n");
#elif defined HAVE_GETEUID
  if(geteuid()!=0)
  {
    wmove(stdscr,line++,0);
    wprintw(stdscr,"- You may need to be root to have write access.\n");
#if defined(__APPLE__)
    wmove(stdscr,line++,0);
    wprintw(stdscr,"Use the sudo command to launch TestDisk.\n");
#endif
    wmove(stdscr,line++,0);
    wprintw(stdscr,"- Check the OS permissions for this file or device.\n");
  }
#endif
#if defined(__APPLE__)
  wmove(stdscr,line++,0);
  wprintw(stdscr,"- No partition from this disk must be mounted:\n");
  wmove(stdscr,line++,0);
  wprintw(stdscr,"Open the Disk Utility (In Finder -> Application -> Utility folder)\n");
  wmove(stdscr,line++,0);
  wprintw(stdscr,"and press Unmount button for each volume from this disk\n");
#endif
  wmove(stdscr,line,0);
  wprintw(stdscr,"- This media may be physically write-protected, check the jumpers.\n");
  car= wmenuSelect_ext(stdscr, 23, INTER_DISK_Y, INTER_DISK_X, menuDiskAccess, 10,
      "CQ", MENU_VERT | MENU_VERT_WARN | MENU_BUTTON, &menu,NULL);
  if(car=='c' || car=='C')
    return 0;
  return 1;
}
#endif

int interface_check_disk_access(disk_t *disk_car, char **current_cmd)
{
  if((disk_car->access_mode&TESTDISK_O_RDWR)==TESTDISK_O_RDWR)
    return 0;
  if(*current_cmd!=NULL)
    return 0;
  log_warning("Media is opened in read-only.\n");
  log_flush();
#ifdef HAVE_NCURSES
  return interface_check_disk_access_ncurses(disk_car);
#else
  return 0;
#endif
}
