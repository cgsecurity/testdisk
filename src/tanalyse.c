/*

    File: tanalyse.c

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
 
#include <stdio.h>
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include "types.h"
#include "common.h"
#include "lang.h"
#include "intrf.h"
#include "intrfn.h"
#include "savehdr.h"
#include "log.h"
#include "tanalyse.h"

extern const arch_fnct_t arch_none;

static list_part_t *interface_analyse_ncurses(disk_t *disk_car, const int verbose, const int saveheader, char**current_cmd)
{
  list_part_t *list_part;
  int command;
#ifdef HAVE_NCURSES
  const struct MenuItem menuAnalyse[]=
  {
    { 'P', "Previous",""},
    { 'N', "Next","" },
    { 'Q',"Quick Search","Try to locate partition"},
    { 'B', "Backup","Save current partition list to backup.log file and proceed"},
    { 0, NULL, NULL }
  };
#endif
  screen_buffer_reset();
  /* ncurses interface */
#ifdef HAVE_NCURSES
  aff_copy(stdscr);
  wmove(stdscr,4,0);
  wprintw(stdscr,"%s\n",disk_car->description(disk_car));
  mvwaddstr(stdscr,5,0,"Checking current partition structure");
  wrefresh(stdscr);
#endif
  list_part=disk_car->arch->read_part(disk_car,verbose,saveheader);
  log_info("Current partition structure:\n");
  screen_buffer_to_log();
#ifdef HAVE_NCURSES
  wmove(stdscr,5,0);
  wclrtoeol(stdscr);	/* before addstr for BSD compatibility */
  waddstr(stdscr,"Current partition structure:");
  wmove(stdscr,6,0);
  wprintw(stdscr,msg_PART_HEADER_LONG);
  if(disk_car->arch->msg_part_type!=NULL)
    mvwaddstr(stdscr,LINES-3,0,disk_car->arch->msg_part_type);
#endif
  command='Q';
  if(*current_cmd!=NULL)
  {
    skip_comma_in_command(current_cmd);
    if(check_command(current_cmd,"backup",6)==0)
    {
      if(list_part!=NULL)
	command='B';
    }
  }
  else
  {
    log_flush();
#ifdef HAVE_NCURSES
    command=screen_buffer_display(stdscr,
	(list_part!=NULL && disk_car->arch != &arch_none?"QB":"Q"),
	menuAnalyse);
#endif
  }
  if(command=='B')
  {
    log_info("Backup partition structure\n");
    if(partition_save(disk_car,list_part,verbose)<0)
    {
      display_message("Can't create backup.log.\n");
    }
  }
  return list_part;
}

list_part_t *interface_analyse(disk_t *disk_car, const int verbose, const int saveheader, char**current_cmd)
{
  log_info("\nAnalyse ");
  log_info("%s\n",disk_car->description(disk_car));
  return interface_analyse_ncurses(disk_car, verbose, saveheader, current_cmd);
}

