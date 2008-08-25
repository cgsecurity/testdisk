/*

    File: pdisksel.c

    Copyright (C) 1998-2008 Christophe GRENIER <grenier@cgsecurity.org>

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
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>	/* geteuid */
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include "types.h"
#include "common.h"
#include "intrf.h"
#ifdef HAVE_NCURSES
#include "intrfn.h"
#else
#include <stdio.h>
#endif
#include "dir.h"
#include "list.h"
#include "filegen.h"
#include "photorec.h"
#include "sessionp.h"
#include "partauto.h"
#include "log.h"
#include "pdisksel.h"
#include "ppartsel.h"

#ifdef HAVE_NCURSES
#define NBR_DISK_MAX 		(LINES-6-8)
#define INTER_DISK_X		0
#define INTER_DISK_Y		(8+NBR_DISK_MAX)
#define INTER_NOTE_Y		(LINES-4)

static void photorec_disk_selection_ncurses(int verbose, const char *recup_dir, const list_disk_t *list_disk, file_enable_t *file_enable)
{
  char * current_cmd=NULL;
  int command;
  int real_key;
  int done=0;
  unsigned int menu=0;
  int offset=0;
  int pos_num=0;
  const list_disk_t *element_disk;
  const list_disk_t *current_disk=list_disk;
  static const struct MenuItem menuMain[]=
  {
    { 'P', "Previous",""},
    { 'N', "Next","" },
    { 'O',"Proceed",""},
    { 'Q',"Quit","Quit program"},
    { 0,NULL,NULL}
  };
  static alloc_data_t list_search_space={
    .list = TD_LIST_HEAD_INIT(list_search_space.list)
  };
  /* ncurses interface */
  while(done==0)
  {
    const char *options;
    int i;
    aff_copy(stdscr);
    wmove(stdscr,4,0);
    wprintw(stdscr,"  PhotoRec is free software, and");
    wmove(stdscr,5,0);
    wprintw(stdscr,"comes with ABSOLUTELY NO WARRANTY.");
    wmove(stdscr,7,0);
    wprintw(stdscr,"Select a media (use Arrow keys, then press Enter):");
    for(i=0,element_disk=list_disk;
	element_disk!=NULL && i<offset+NBR_DISK_MAX;
	i++, element_disk=element_disk->next)
    {
      if(i<offset)
	continue;
      wmove(stdscr,8+i-offset,0);
      if(element_disk!=current_disk)
	wprintw(stdscr,"%s\n",element_disk->disk->description_short(element_disk->disk));
      else
      {
	wattrset(stdscr, A_REVERSE);
	wprintw(stdscr,"%s\n",element_disk->disk->description_short(element_disk->disk));
	wattroff(stdscr, A_REVERSE);
      }
    }
    if(i<=NBR_DISK_MAX && element_disk==NULL)
      options="OQ";
    else
      options="PNOQ";
    {
      int line=INTER_NOTE_Y;
      mvwaddstr(stdscr,line++,0,"Note: ");
#if defined(__CYGWIN__) || defined(__MINGW32__)
#else
#ifndef DJGPP
#ifdef HAVE_GETEUID
      if(geteuid()!=0)
      {
	if(has_colors())
	  wbkgdset(stdscr,' ' | A_BOLD | COLOR_PAIR(1));
	wprintw(stdscr,"Some disks won't appear unless you're root user.");
        if(has_colors())
          wbkgdset(stdscr,' ' | COLOR_PAIR(0));
      }
#endif
#endif
#endif
      wmove(stdscr,line++,0);
      wprintw(stdscr,"Disk capacity must be correctly detected for a successful recovery.");
      wmove(stdscr,line++,0);
      wprintw(stdscr,"If a disk listed above has incorrect size, check HD jumper settings, BIOS");
      wmove(stdscr,line++,0);
      wprintw(stdscr,"detection, and install the latest OS patches and disk drivers."); 
    }
    command = wmenuSelect_ext(stdscr, INTER_NOTE_Y-1, INTER_DISK_Y, INTER_DISK_X, menuMain, 8,
	options, MENU_HORIZ | MENU_BUTTON | MENU_ACCEPT_OTHERS, &menu,&real_key);
    switch(command)
    {
      case KEY_UP:
      case 'P':
	if(current_disk->prev!=NULL)
	{
	  current_disk=current_disk->prev;
	  pos_num--;
	}
	break;
      case KEY_DOWN:
      case 'N':
	if(current_disk->next!=NULL)
	{
	  current_disk=current_disk->next;
	  pos_num++;
	}
	break;
      case KEY_PPAGE:
	for(i=0;i<NBR_DISK_MAX-1 && current_disk->prev!=NULL;i++)
	{
	  current_disk=current_disk->prev;
	  pos_num--;
	}
	break;
      case KEY_NPAGE:
	for(i=0;i<NBR_DISK_MAX-1 && current_disk->next!=NULL;i++)
	{
	  current_disk=current_disk->next;
	  pos_num++;
	}
	break;
      case 'o':
      case 'O':
	{
	  disk_t *disk=current_disk->disk;
	  autodetect_arch(disk);
	  if(interface_partition_type(disk, verbose, &current_cmd)==0)
	    menu_photorec(disk, verbose, recup_dir, file_enable, &current_cmd, &list_search_space);
	}
	break;
      case 'q':
      case 'Q':
	done=1;
	break;
    }
    if(pos_num<offset)
      offset=pos_num;
    if(pos_num>=offset+NBR_DISK_MAX)
      offset=pos_num-NBR_DISK_MAX+1;
  }
}
#endif

int do_curses_photorec(int verbose, const char *recup_dir, const list_disk_t *list_disk, file_enable_t *file_enable, char *cmd_device, char **current_cmd)
{
  static alloc_data_t list_search_space={
    .list = TD_LIST_HEAD_INIT(list_search_space.list)
  };
  if(list_disk==NULL)
  {
    return intrf_no_disk("PhotoRec");
  }
  if(cmd_device==NULL)
  {
    char *saved_device=NULL;
    char *saved_cmd=NULL;
    session_load(&saved_device, &saved_cmd,&list_search_space);
    if(saved_device!=NULL && saved_cmd!=NULL && !td_list_empty(&list_search_space.list) && ask_confirmation("Continue previous session ? (Y/N)")!=0)
    {
      /* yes */
      *current_cmd=saved_cmd;
      cmd_device=saved_device;
    }
    else
    {
      free(saved_device);
      free(saved_cmd);
      free_list_search_space(&list_search_space);
    }
  }
  if(cmd_device!=NULL && *current_cmd!=NULL)
  {
    const list_disk_t *element_disk;
    disk_t *disk=NULL;
    for(element_disk=list_disk;element_disk!=NULL;element_disk=element_disk->next)
    {
      if(strcmp(element_disk->disk->device,cmd_device)==0)
	disk=element_disk->disk;
    }
    if(disk==NULL)
    {
      return intrf_no_disk("PhotoRec");
    }
    {
      /* disk sector size is now known, fix the sector ranges */
      struct td_list_head *search_walker = NULL;
      td_list_for_each(search_walker, &list_search_space.list)
      {
	alloc_data_t *current_search_space;
	current_search_space=td_list_entry(search_walker, alloc_data_t, list);
	current_search_space->start=current_search_space->start*disk->sector_size;
	current_search_space->end=current_search_space->end*disk->sector_size+disk->sector_size-1;
      }
    }
    autodetect_arch(disk);
    if(interface_partition_type(disk, verbose, current_cmd)==0)
      menu_photorec(disk, verbose, recup_dir, file_enable, current_cmd, &list_search_space);
  }
  else
  {
#ifdef HAVE_NCURSES
    photorec_disk_selection_ncurses(verbose, recup_dir, list_disk, file_enable);
#endif
  }
  log_info("\n");
  return 0;
}
