/*

    File: tlog.c

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
#include "tlog.h"

#ifdef HAVE_NCURSES
int ask_testdisk_log_creation(void)
{
  unsigned int menu=0;
  static const struct MenuItem menuLogCreation[]=
  {
    {'C',"Create","Create a new log file"},
    {'A',"Append","Append information to log file"},
    {'Q',"No Log","Don't record anything"},
    {0,NULL,NULL}
  };
  aff_copy(stdscr);
  wmove(stdscr,5,0);
  wprintw(stdscr,"TestDisk is free data recovery software designed to help recover lost");
  wmove(stdscr,6,0);
  wprintw(stdscr,"partitions and/or make non-booting disks bootable again when these symptoms");
  wmove(stdscr,7,0);
  wprintw(stdscr,"are caused by faulty software, certain types of viruses or human error.");
  wmove(stdscr,8,0);
  wprintw(stdscr,"It can also be used to repair some filesystem errors.");
  wmove(stdscr,10,0);
  wprintw(stdscr,"Information gathered during TestDisk use can be recorded for later");
  wmove(stdscr,11,0);
  wprintw(stdscr,"review. If you choose to create the text file, ");
  if(has_colors())
    wbkgdset(stdscr,' ' | A_BOLD | COLOR_PAIR(0));
  wprintw(stdscr,"testdisk.log");
  if(has_colors())
    wbkgdset(stdscr,' ' | COLOR_PAIR(0));
  wprintw(stdscr," , it");
  wmove(stdscr,12,0);
  wprintw(stdscr,"will contain TestDisk options, technical information and various");
  wmove(stdscr,13,0);
  wprintw(stdscr,"outputs; including any folder/file names TestDisk was used to find and");
  wmove(stdscr,14,0);
  wprintw(stdscr,"list onscreen.");
  wmove(stdscr,16,0);
  wprintw(stdscr,"Use arrow keys to select, then press Enter key:");
  while(1)
  {
    const int command = wmenuSelect_ext(stdscr, 23, 17, 0, menuLogCreation, 8,
	"CAQ", MENU_VERT | MENU_VERT_WARN | MENU_BUTTON, &menu,NULL);
    switch(command)
    {
      case 'C':
      case 'c':
        return TD_LOG_CREATE;
      case 'A':
      case 'a':
        return TD_LOG_APPEND;
      case 'Q':
      case 'q':
        return TD_LOG_NONE;
      default:
        break;
    }
  }
}
#else
int ask_testdisk_log_creation()
{
  return TD_LOG_NONE;
}
#endif
