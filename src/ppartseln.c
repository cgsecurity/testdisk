/*

    File: ppartseln.c

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

#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <ctype.h>      /* isdigit */
#include "types.h"
#include "common.h"
#include "intrf.h"
#include "fnctdsk.h"
#include "dir.h"
#include "list.h"
#include "lang.h"
#include "filegen.h"
#include "photorec.h"
#include "phrecn.h"
#include "log.h"
#include "log_part.h"
#include "hdaccess.h"
#include "pfree_whole.h"
#include "phcli.h"
#include "ppartseln.h"
#include "askloc.h"
#include "geometryn.h"
#include "addpartn.h"
#include "intrfn.h"

extern const arch_fnct_t arch_none;

#ifdef HAVE_NCURSES
#define INTER_SELECT_X	0
#define INTER_SELECT_Y	(LINES-2)
#define INTER_SELECT	(LINES-2-7-1)
#endif

void menu_photorec(struct ph_param *params, struct ph_options *options, alloc_data_t*list_search_space)
{
  list_part_t *list_part;
#ifdef HAVE_NCURSES
  list_part_t *current_element;
  unsigned int current_element_num;
  int done=0;
  int command;
  unsigned int offset=0;
  unsigned int menu=0;
  static const struct MenuItem menuMain[]=
  {
	{'S',"Search","Start file recovery"},
	{'O',"Options","Modify options"},
	{'F',"File Opt","Modify file options"},
	{'G',"Geometry", "Change disk geometry" },
	{'Q',"Quit","Return to disk selection"},
	{0,NULL,NULL}
  };
#endif
  params->blocksize=0;
  list_part=init_list_part(params->disk, options);
  if(list_part==NULL)
    return;
  log_all_partitions(params->disk, list_part);
  if(params->cmd_run!=NULL)
  {
    if(menu_photorec_cli(list_part, params, options, list_search_space) > 0)
    {
      if(params->recup_dir==NULL)
      {
	char *res;
#ifdef HAVE_NCURSES
	res=ask_location("Please select a destination to save the recovered files.\nDo not choose to write the files to the same partition they were stored on.", "", NULL);
#else
	res=get_default_location();
#endif
	if(res!=NULL)
	{
	  params->recup_dir=(char *)MALLOC(strlen(res)+1+strlen(DEFAULT_RECUP_DIR)+1);
	  strcpy(params->recup_dir,res);
	  strcat(params->recup_dir,"/");
	  strcat(params->recup_dir,DEFAULT_RECUP_DIR);
	  free(res);
	}
      }
      if(params->recup_dir!=NULL)
	photorec(params, options, list_search_space);
    }
  }
  if(params->cmd_run!=NULL)
  {
    part_free_list(list_part);
    return;
  }
#ifdef HAVE_NCURSES
  if(list_part->next!=NULL)
  {
    current_element_num=1;
    current_element=list_part->next;
  }
  else
  {
    current_element_num=0;
    current_element=list_part;
  }
  while(done==0)
  { /* ncurses interface */
    list_part_t *element;
    unsigned int i;
    aff_copy(stdscr);
    wmove(stdscr,4,0);
    wprintw(stdscr,"%s",params->disk->description_short(params->disk));
    mvwaddstr(stdscr,6,0,msg_PART_HEADER_LONG);
#if defined(KEY_MOUSE) && defined(ENABLE_MOUSE)
    mousemask(ALL_MOUSE_EVENTS, NULL);
#endif
    for(i=0,element=list_part; element!=NULL && i<offset+INTER_SELECT;element=element->next,i++)
    {
      if(i<offset)
	continue;
      wmove(stdscr,7+i-offset,0);
      wclrtoeol(stdscr);	/* before addstr for BSD compatibility */
      if(element==current_element)
      {
	wattrset(stdscr, A_REVERSE);
	waddstr(stdscr, ">");
	aff_part(stdscr,AFF_PART_ORDER|AFF_PART_STATUS,params->disk,element->part);
	wattroff(stdscr, A_REVERSE);
      } else
      {
	waddstr(stdscr, " ");
	aff_part(stdscr,AFF_PART_ORDER|AFF_PART_STATUS,params->disk,element->part);
      }
    }
    wmove(stdscr,7+INTER_SELECT,5);
    wclrtoeol(stdscr);
    if(element!=NULL)
      wprintw(stdscr, "Next");
    command = wmenuSelect(stdscr, INTER_SELECT_Y+1, INTER_SELECT_Y, INTER_SELECT_X, menuMain, 8,
	(options->expert==0?"SOFQ":"SOFGQ"), MENU_HORIZ | MENU_BUTTON | MENU_ACCEPT_OTHERS, menu);
#if defined(KEY_MOUSE) && defined(ENABLE_MOUSE)
    if(command == KEY_MOUSE)
    {
      MEVENT event;
      if(getmouse(&event) == OK)
      {	/* When the user clicks left mouse button */
	if((event.bstate & BUTTON1_CLICKED) || (event.bstate & BUTTON1_DOUBLE_CLICKED))
	{
	  if(event.y >=7 && event.y<7+INTER_SELECT)
	  {
	    /* Disk selection */
	    while(current_element_num > event.y-(7-offset) && current_element->prev!=NULL)
	    {
	      current_element=current_element->prev;
	      current_element_num--;
	    }
	    while(current_element_num < event.y-(7-offset) && current_element->next!=NULL)
	    {
	      current_element=current_element->next;
	      current_element_num++;
	    }
	    if(event.bstate & BUTTON1_DOUBLE_CLICKED)
	      command='S';
	  }
	  else
	    command = menu_to_command(INTER_SELECT_Y+1, INTER_SELECT_Y, INTER_SELECT_X, menuMain, 8,
		(options->expert==0?"SOFQ":"SOFGQ"), MENU_HORIZ | MENU_BUTTON | MENU_ACCEPT_OTHERS, event.y, event.x);
	}
      }
    }
#endif
    switch(command)
    {
      case KEY_UP:
	if(current_element!=NULL && current_element->prev!=NULL)
	{
	  current_element=current_element->prev;
	  current_element_num--;
	}
	break;
      case KEY_PPAGE:
	for(i=0; (signed)i<INTER_SELECT && current_element->prev!=NULL; i++)
	{
	  current_element=current_element->prev;
	  current_element_num--;
	}
	break;
      case KEY_DOWN:
	if(current_element->next!=NULL)
	{
	  current_element=current_element->next;
	  current_element_num++;
	}
	break;
      case KEY_NPAGE:
	for(i=0; (signed)i<INTER_SELECT && current_element->next!=NULL; i++)
	{
	  current_element=current_element->next;
	  current_element_num++;
	}
	break;
      case 's':
      case 'S':
	if(current_element!=NULL)
	{
	  params->partition=current_element->part;
	  ask_mode_ext2(params->disk, params->partition, &options->mode_ext2, &params->carve_free_space_only);
	  menu=0;
	  if(params->recup_dir==NULL)
	  {
	    char *res;
	    res=ask_location("Please select a destination to save the recovered files.\nDo not choose to write the files to the same partition they were stored on.", "", NULL);
	    if(res!=NULL)
	    {
	      params->recup_dir=(char *)MALLOC(strlen(res)+1+strlen(DEFAULT_RECUP_DIR)+1);
	      strcpy(params->recup_dir,res);
	      strcat(params->recup_dir,"/");
	      strcat(params->recup_dir,DEFAULT_RECUP_DIR);
	      free(res);
	    }
	  }
	  if(params->recup_dir!=NULL)
	  {
	    if(td_list_empty(&list_search_space->list))
	    {
	      init_search_space(list_search_space, params->disk, params->partition);
	    }
	    if(params->carve_free_space_only>0)
	    {
	      aff_copy(stdscr);
	      wmove(stdscr,5,0);
	      wprintw(stdscr, "Filesystem analysis, please wait...\n");
	      wrefresh(stdscr);
	      params->blocksize=remove_used_space(params->disk, params->partition, list_search_space);
	      /* Only free space is carved, list_search_space is modified.
	       * To carve the whole space, need to quit and reselect the params->partition */
	      done = 1;
	    }
	    photorec(params, options, list_search_space);
	  }
	}
	break;
      case 'o':
      case 'O':
	{
	  interface_options_photorec_ncurses(options);
	  menu=1;
	}
	break;
      case 'f':
      case 'F':
	interface_file_select_ncurses(options->list_file_format);
	menu=2;
	break;
      case 'g':
      case 'G':
	if(options->expert!=0)
	  if(change_geometry_ncurses(params->disk))
	    done=1;
	break;
      case 'a':
      case 'A':
	if(params->disk->arch != &arch_none)
	{
	  list_part=add_partition_ncurses(params->disk, list_part);
	  current_element=list_part;
	  current_element_num=0;
	}
	break;
      case 'q':
      case 'Q':
	done = 1;
	break;
    }
    if(current_element_num<offset)
      offset=current_element_num;
    if(current_element_num>=offset+INTER_SELECT)
      offset=current_element_num-INTER_SELECT+1;
  }
#endif
  log_info("\n");
  part_free_list(list_part);
}
