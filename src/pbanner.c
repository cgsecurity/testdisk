/*

    File: pbanner.c

    Copyright (C) 2009 Christophe GRENIER <grenier@cgsecurity.org>
  
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

void aff_copy_short(WINDOW *window)
{
  wclear(window);
  keypad(window, TRUE); /* Need it to get arrow key */
  wmove(window,0,0);
  wprintw(window, "PhotoRec %s, Data Recovery Utility, %s\n",VERSION,TESTDISKDATE);
}

void aff_copy(WINDOW *window)
{
  aff_copy_short(window);
  wmove(window,1,0);
  wprintw(window, "Christophe GRENIER <grenier@cgsecurity.org>");
  wmove(window,2,0);
  wprintw(window, "https://www.cgsecurity.org");
}
#endif
