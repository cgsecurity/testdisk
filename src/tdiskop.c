/*

    File: tdiskop.c

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
#include "godmode.h"
#include "fnctdsk.h"
#include "testdisk.h"
#include "adv.h"
#include "edit.h"
#include "log.h"
#include "hdaccess.h"
#include "toptions.h"
#include "tanalyse.h"
#include "tmbrcode.h"
#include "tdelete.h"
#include "tdiskop.h"
#include "geometry.h"

extern const arch_fnct_t arch_i386;
#define INTER_DISK_X	0
#define INTER_DISK_Y	7


static int menu_disk_cli(disk_t *disk_car, const int verbose,int dump_ind, const int saveheader, char **current_cmd)
{
  int align=2;
  int allow_partial_last_cylinder=0;
  int ask_part_order=0;
  unsigned int expert=0;
  char options[16];
  strcpy(options, "AGOPTQ");
  while(1)
  {
    while(*current_cmd[0]==',')
      (*current_cmd)++;
    if(strncmp(*current_cmd,"analyze",7)==0 || strncmp(*current_cmd,"analyse",7)==0)
    {
      (*current_cmd)+=7;
      {
	int search_vista_part=0;
	list_part_t *list_part;
	list_part=interface_analyse(disk_car, verbose, saveheader, current_cmd);
	if(disk_car->arch==&arch_i386)
	{
	  const int old_allow_partial_last_cylinder=allow_partial_last_cylinder;
	  const list_part_t *element;
	  for(element=list_part;element!=NULL;element=element->next)
	  {
	    if(element->part->part_offset%(2048*512)==0 && element->part->part_size%(2048*512)==0)
	      search_vista_part=1;
	  }
	  while(*current_cmd[0]==',')
	    (*current_cmd)++;
	  if(strncmp(*current_cmd,"mode_vista",10)==0)
	  {
	    (*current_cmd)+=10;
	    search_vista_part=1;
	  }
	  if(search_vista_part==1)
	    allow_partial_last_cylinder=1;
	  if(old_allow_partial_last_cylinder!=allow_partial_last_cylinder)
	    hd_update_geometry(disk_car,allow_partial_last_cylinder,verbose);
	  log_info("Allow partial last cylinder : %s\n", allow_partial_last_cylinder>0?"Yes":"No");
	  log_info("search_vista_part: %d\n", search_vista_part);
	}
	interface_recovery(disk_car, list_part, verbose, dump_ind, align, ask_part_order, expert, search_vista_part, current_cmd);
	part_free_list(list_part);
      }
    }
    else if(strncmp(*current_cmd,"geometry,",9)==0)
    {
      (*current_cmd)+=9;
      change_geometry(disk_car, current_cmd);
    }
    else if(strncmp(*current_cmd,"advanced",8)==0)
    {
      (*current_cmd)+=8;
      interface_adv(disk_car, verbose, dump_ind, expert,current_cmd);
    }
    else if(strncmp(*current_cmd,"options,",8)==0)
    {
      const int old_allow_partial_last_cylinder=allow_partial_last_cylinder;
      (*current_cmd)+=8;
      interface_options(&dump_ind, &align,&allow_partial_last_cylinder,&expert,current_cmd);
      if(old_allow_partial_last_cylinder!=allow_partial_last_cylinder)
	hd_update_geometry(disk_car,allow_partial_last_cylinder,verbose);
    }
    else if(strncmp(*current_cmd,"delete",6)==0)
    {
      (*current_cmd)+=6;
      write_clean_table(disk_car);
    }
    else if(strncmp(*current_cmd,"mbr_code",8)==0)
    {
      (*current_cmd)+=8;
      write_MBR_code(disk_car);
    }
    else
    {
      return 0;
    }
  }
}

#ifdef HAVE_NCURSES
static int menu_disk_ncurses(disk_t *disk_car, const int verbose,int dump_ind, const int saveheader, char **current_cmd)
{
  int align=2;
  int allow_partial_last_cylinder=0;
  int ask_part_order=0;
  int command;
  unsigned int menu=0;
  int real_key;
  unsigned int expert=0;
  char options[16];
  static struct MenuItem menuMain[]=
  {
	{'A',"Analyse","Analyse current partition structure and search for lost partitions"},
	{'T',"Advanced","Filesystem Utils"},
	{'G',"Geometry", "Change disk geometry" },
	{'O',"Options","Modify options"},
	{'C',"MBR Code","Write TestDisk MBR code to first sector"},
	{'D',"Delete","Delete all data in the partition table"},
	{'Q',"Quit","Return to disk selection"},
	{'E',"Editor","Basic disk editor"},
	{0,NULL,NULL}
  };
  strcpy(options, "AGOPTQ");
  if(disk_car->arch->write_MBR_code!=NULL)
    strcat(options,"C");
  if(disk_car->arch->erase_list_part!=NULL)
    strcat(options,"D");
  while(1)
  {
    aff_copy(stdscr);
    wmove(stdscr,5,0);
    wprintw(stdscr,"%s\n",disk_car->description(disk_car));
    wmove(stdscr,20,0);
    wprintw(stdscr,"Note: Correct disk geometry is required for a successful recovery. 'Analyse'");
    wmove(stdscr,21,0);
    wprintw(stdscr,"process may give some warnings if it thinks the logical geometry is mismatched.");
    command = wmenuSelect_ext(stdscr, 23, INTER_DISK_Y, INTER_DISK_X, menuMain, 10,
	options, MENU_VERT | MENU_VERT_WARN | MENU_BUTTON | MENU_ACCEPT_OTHERS, &menu,&real_key);
    /* e for editor will be added when the editor will be better */
    switch(command)
    {
      case 'a':
      case 'A':
	{
	  int search_vista_part=0;
	  list_part_t *list_part;
	  list_part=interface_analyse(disk_car, verbose, saveheader, current_cmd);
	  if(disk_car->arch==&arch_i386)
	  {
	    const int old_allow_partial_last_cylinder=allow_partial_last_cylinder;
	    const list_part_t *element;
	    for(element=list_part;element!=NULL;element=element->next)
	    {
	      if(element->part->part_offset%(2048*512)==0 && element->part->part_size%(2048*512)==0)
		search_vista_part=1;
	    }
	    if(search_vista_part==0)
	    {
	      log_info("Ask the user for vista mode\n");
	      if(ask_confirmation("Should TestDisk search for partition created under Vista ? [Y/N] (answer Yes if unsure)")!=0)
		search_vista_part=1;
	    }
	    if(search_vista_part==1)
	      allow_partial_last_cylinder=1;
	    if(old_allow_partial_last_cylinder!=allow_partial_last_cylinder)
	      hd_update_geometry(disk_car,allow_partial_last_cylinder,verbose);
	    log_info("Allow partial last cylinder : %s\n", allow_partial_last_cylinder>0?"Yes":"No");
	    log_info("search_vista_part: %d\n", search_vista_part);
	  }
	  interface_recovery(disk_car, list_part, verbose, dump_ind, align, ask_part_order, expert, search_vista_part, current_cmd);
	  part_free_list(list_part);
	}
	break;
      case 'd':
      case 'D':
	write_clean_table(disk_car);
	break;
      case 'c':
      case 'C':
	write_MBR_code(disk_car);
	break;
      case 'g':
      case 'G':
	change_geometry(disk_car, current_cmd);
	break;
      case 'o':
      case 'O':
	{
	  const int old_allow_partial_last_cylinder=allow_partial_last_cylinder;
	  interface_options(&dump_ind, &align,&allow_partial_last_cylinder,&expert, current_cmd);
	  if(old_allow_partial_last_cylinder!=allow_partial_last_cylinder)
	    hd_update_geometry(disk_car,allow_partial_last_cylinder,verbose);
	}
	break;
      case 't':
      case 'T':
	interface_adv(disk_car, verbose, dump_ind, expert, current_cmd);
	break;
      case 'e':
      case 'E':
	interface_editor(disk_car);
	break;
      case 'q':
      case 'Q':
	return 0;
    }
  }
}
#endif

int menu_disk(disk_t *disk_car, const int verbose,int dump_ind, const int saveheader, char **current_cmd)
{
  if(*current_cmd!=NULL)
    return menu_disk_cli(disk_car, verbose, dump_ind, saveheader, current_cmd);
#ifdef HAVE_NCURSES
  return menu_disk_ncurses(disk_car, verbose, dump_ind, saveheader, current_cmd);
#else
  return 0;
#endif
}
