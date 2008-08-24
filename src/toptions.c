/*

    File: toptions.c

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
 
#include "types.h"
#include "common.h"
#include "intrf.h"
#ifdef HAVE_NCURSES
#include "intrfn.h"
#else
#include <stdio.h>
#endif
#include "log.h"
#include "toptions.h"

#ifdef HAVE_NCURSES
static void interface_options_ncurses(int *dump_ind, int *align, int *allow_partial_last_cylinder, unsigned int *expert)
{
  unsigned int menu = 4;
  /* ncurses interface */
  while (1)
  {
    int car;
    int real_key;
    struct MenuItem menuOptions[]=
    {
      { 'E',NULL,"Expert mode adds some functionalities"},
      { 'C',NULL,"Partitions are aligned on cylinder/head boundaries" },
      { 'A',NULL,""},
      { 'D',NULL,"Dump essential sectors" },
      { 'Q',"[ Ok ]","Done with changing options"},
      { 0, NULL, NULL }
    };
    menuOptions[0].name=*expert?"Expert mode : Yes":"Expert mode : No";
    switch(*align)
    {
      case 0:
	menuOptions[1].name="Cylinder boundary : No";
	break;
      case 1:
	menuOptions[1].name="Cylinder boundary : Head boundary only";
	break;
      case 2:
	menuOptions[1].name="Cylinder boundary : Yes";
	break;
    }
    menuOptions[2].name=*allow_partial_last_cylinder?"Allow partial last cylinder : Yes":"Allow partial last cylinder : No";
    menuOptions[3].name=*dump_ind?"Dump : Yes":"Dump : No";
    aff_copy(stdscr);
    car=wmenuSelect_ext(stdscr, 24, INTER_OPTION_Y, INTER_OPTION_X, menuOptions, 0, "ECADQ", MENU_VERT|MENU_VERT_ARROW2VALID, &menu,&real_key);
    switch(car)
    {
      case 'd':
      case 'D':
	*dump_ind=!*dump_ind;
	break;
      case 'c':
      case 'C':
	if(*align<2)
	  (*align)++;
	else
	  *align=0;
	break;
      case 'a':
      case 'A':
	*allow_partial_last_cylinder=!*allow_partial_last_cylinder;
	break;
      case 'e':
      case 'E':
	*expert=!*expert;
	break;
      case key_ESC:
      case 'q':
      case 'Q':
	return;
    }
  }
}
#endif

void interface_options(int *dump_ind, int *align, int *allow_partial_last_cylinder, unsigned int *expert, char**current_cmd)
{
  if(*current_cmd==NULL)
  {
#ifdef HAVE_NCURSES
    interface_options_ncurses(dump_ind, align, allow_partial_last_cylinder, expert);
#endif
  }
  /* write new options to log file */
  log_info("New options :\n Dump : %s\n ", (*dump_ind?"Yes":"No"));
  switch(*align)
  {
    case 0:
      log_info("Cylinder boundary : No");
      break;
    case 1:
      log_info("Cylinder boundary : Head boundary only");
      break;
    case 2:
      log_info("Cylinder boundary : Yes");
      break;
  }
  log_info("\n Allow partial last cylinder : %s\n Expert mode : %s\n",
      *allow_partial_last_cylinder?"Yes":"No",
      *expert?"Yes":"No");
}
