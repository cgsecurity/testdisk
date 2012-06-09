/*

    File: nodisk.c

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
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include "types.h"
#include "common.h"
#include "intrf.h"
#include "intrfn.h"
#include "nodisk.h"

int intrf_no_disk_ncurses(const char *prog_name)
{
  aff_copy(stdscr);
  wmove(stdscr,4,0);
  wprintw(stdscr,"  %s is free software, and",prog_name);
  wmove(stdscr,5,0);
  wprintw(stdscr,"comes with ABSOLUTELY NO WARRANTY.");
  wmove(stdscr,7,0);
  wprintw(stdscr,"No harddisk found\n");
#if defined(__CYGWIN__) || defined(__MINGW32__)
  wmove(stdscr,8,0);
  wprintw(stdscr,"You need to be administrator to use %s.\n", prog_name);
  wmove(stdscr,9,0);
  wprintw(stdscr,"Under Win9x, use the DOS version instead.\n");
  wmove(stdscr,10,0);
  wprintw(stdscr,"Under Vista or later, select %s, right-click and\n", prog_name);
  wmove(stdscr,11,0);
  wprintw(stdscr,"choose \"Run as administrator\".\n");
#elif defined(DJGPP)
#else
#ifdef HAVE_GETEUID
  if(geteuid()!=0)
  {
    wmove(stdscr,8,0);
    wprintw(stdscr,"You need to be root to use %s.\n", prog_name);
#ifdef SUDO_BIN
    {
      static const struct MenuItem menuSudo[]=
      {
	{'S',"Sudo","Use the sudo command to restart as root"},
	{'Q',"Quit",""},
	{0,NULL,NULL}
      };
      unsigned int menu=0;
      int command;
      command = wmenuSelect_ext(stdscr,23, 20, 0, menuSudo, 8,
	  "SQ", MENU_VERT | MENU_VERT_WARN | MENU_BUTTON, &menu,NULL);
      if(command=='s' || command=='S')
	return 1;
      return 0;
    }
#endif
  }
#endif
#endif
  wmove(stdscr,22,0);
  wattrset(stdscr, A_REVERSE);
  waddstr(stdscr,"[ Quit ]");
  wattroff(stdscr, A_REVERSE);
  wrefresh(stdscr);
  while(wgetch(stdscr)==ERR);
  return 0;
}
#endif
