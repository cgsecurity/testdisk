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
 
#include <stdio.h>
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include "types.h"
#include "common.h"
#include "intrf.h"
#ifdef HAVE_NCURSES
#include "intrfn.h"
#endif
#include "godmode.h"
#include "fnctdsk.h"
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
#include "geometryn.h"

extern const arch_fnct_t arch_none;
#define INTER_DISK_X	0
#define INTER_DISK_Y	8


static int menu_disk_cli(disk_t *disk_car, const int verbose,int dump_ind, const int saveheader, char **current_cmd)
{
  int align=1;
  int ask_part_order=0;
  unsigned int expert=0;
  while(1)
  {
    skip_comma_in_command(current_cmd);
    if(check_command(current_cmd,"analyze",7)==0 || check_command(current_cmd,"analyse",7)==0)
    {
      list_part_t *list_part;
      list_part=interface_analyse(disk_car, verbose, saveheader, current_cmd);
      interface_recovery(disk_car, list_part, verbose, dump_ind, align, ask_part_order, expert, current_cmd);
      part_free_list(list_part);
    }
    else if(check_command(current_cmd,"geometry,",9)==0)
    {
      change_geometry_cli(disk_car, current_cmd);
    }
    else if(check_command(current_cmd,"advanced",8)==0)
    {
      interface_adv(disk_car, verbose, dump_ind, expert,current_cmd);
    }
    else if(check_command(current_cmd,"options,",8)==0)
    {
      interface_options(&dump_ind, &align, &expert,current_cmd);
    }
    else if(check_command(current_cmd,"delete",6)==0)
    {
      write_clean_table(disk_car);
    }
    else if(check_command(current_cmd,"mbr_code",8)==0)
    {
      write_MBR_code(disk_car);
    }
    else
    {
      return 0;
    }
  }
}

#ifdef HAVE_NCURSES
static int menu_disk_ncurses(disk_t *disk, const int verbose,int dump_ind, const int saveheader, char **current_cmd)
{
  int align=1;
  int ask_part_order=0;
  unsigned int expert=0;
  char options[16];
  static const struct MenuItem menuMain[]=
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
  unsigned int menu=(disk->arch == &arch_none ? 1 : 0);
  if(disk->arch == &arch_none)
  {
    interface_adv(disk, verbose, dump_ind, expert, current_cmd);
  }
  strcpy(options, "AGOPTQ");
  if(disk->arch->write_MBR_code!=NULL)
    strcat(options,"C");
  if(disk->arch->erase_list_part!=NULL)
    strcat(options,"D");
  while(1)
  {
    int real_key;
    int command;
    aff_copy(stdscr);
    wmove(stdscr,5,0);
    wprintw(stdscr, "%s\n", disk->description_short(disk));
    wmove(stdscr,6,0);
    if(disk->geom.heads_per_cylinder == 1 && disk->geom.sectors_per_head == 1)
      wprintw(stdscr, "     %llu sectors", (long long unsigned)(disk->disk_size / disk->sector_size));
    else
      wprintw(stdscr, "     CHS %lu %u %u",
	  disk->geom.cylinders, disk->geom.heads_per_cylinder, disk->geom.sectors_per_head);
    wprintw(stdscr, " - sector size=%u", disk->sector_size);
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
	  list_part_t *list_part;
	  list_part=interface_analyse(disk, verbose, saveheader, current_cmd);
	  interface_recovery(disk, list_part, verbose, dump_ind, align, ask_part_order, expert, current_cmd);
	  part_free_list(list_part);
	}
	break;
      case 'd':
      case 'D':
	write_clean_table(disk);
	break;
      case 'c':
      case 'C':
	write_MBR_code(disk);
	break;
      case 'g':
      case 'G':
	change_geometry_ncurses(disk);
	break;
      case 'o':
      case 'O':
	{
	  interface_options(&dump_ind, &align, &expert, current_cmd);
	}
	break;
      case 't':
      case 'T':
	interface_adv(disk, verbose, dump_ind, expert, current_cmd);
	break;
      case 'e':
      case 'E':
	interface_editor(disk);
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
