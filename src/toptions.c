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
 
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "types.h"
#include "common.h"
#include "intrf.h"
#ifdef HAVE_NCURSES
#include "intrfn.h"
#endif
#include "log.h"
#include "toptions.h"

#ifdef HAVE_NCURSES
static void interface_options_ncurses(int *dump_ind, int *align, unsigned int *expert)
{
  unsigned int menu = 3;
  /* ncurses interface */
  while (1)
  {
    int car;
    int real_key;
    struct MenuItem menuOptions[]=
    {
      { 'E',NULL,"Expert mode adds some functionalities"},
      { 'C',NULL,"Align partitions to cylinder or 1MiB boundaries" },
      { 'D',NULL,"Dump essential sectors" },
      { 'Q',"[ Ok ]","Done with changing options"},
      { 0, NULL, NULL }
    };
    menuOptions[0].name=*expert?"Expert mode : Yes":"Expert mode : No";
    menuOptions[1].name=*align?"Align partition: Yes":"Align partition: No";
    menuOptions[2].name=*dump_ind?"Dump : Yes":"Dump : No";
    aff_copy(stdscr);
    car=wmenuSelect_ext(stdscr, 23, INTER_OPTION_Y, INTER_OPTION_X, menuOptions, 0, "ECDQ", MENU_VERT|MENU_VERT_ARROW2VALID, &menu,&real_key);
    switch(car)
    {
      case 'd':
      case 'D':
	*dump_ind=!*dump_ind;
	break;
      case 'c':
      case 'C':
	*align=!*align;
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

void interface_options(int *dump_ind, int *align, unsigned int *expert, char**current_cmd)
{
  assert(current_cmd!=NULL);
  if(*current_cmd!=NULL)
  {
    int keep_asking=1;
    do
    {
      skip_comma_in_command(current_cmd);
      if(check_command(current_cmd,"dump",4)==0)
      {
	*dump_ind=1;
      }
      else if(check_command(current_cmd,"nodump",6)==0)
      {
	*dump_ind=0;
      }
      else if(check_command(current_cmd,"align",5)==0)
      {
	*align=1;
      }
      else if(check_command(current_cmd,"noalign",7)==0)
      {
	*align=0;
      }
      else if(check_command(current_cmd,"expert",6)==0)
      {
	*expert=1;
      }
      else if(check_command(current_cmd,"noexpert",8)==0)
      {
	*expert=0;
      }
      else
	keep_asking=0;
    } while(keep_asking>0);
  }
  else
  {
#ifdef HAVE_NCURSES
    interface_options_ncurses(dump_ind, align, expert);
#endif
  }
  /* write new options to log file */
  log_info("New options :\n");
  log_info(" Dump : %s\n", (*dump_ind?"Yes":"No"));
  log_info(" Align partition: %s\n", (*align?"Yes":"No"));
  log_info(" Expert mode : %s\n", (*expert?"Yes":"No"));
}
