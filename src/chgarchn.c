/*

    File: chgarchn.c

    Copyright (C) 1998-2013 Christophe GRENIER <grenier@cgsecurity.org>

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
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include "types.h"
#include "common.h"
#include "intrf.h"
#include "intrfn.h"
#include "log.h"
#include "hdaccess.h"
#include "autoset.h"
#include "chgarchn.h"

extern const arch_fnct_t arch_i386;
extern const arch_fnct_t arch_gpt;
extern const arch_fnct_t arch_humax;
extern const arch_fnct_t arch_mac;
extern const arch_fnct_t arch_none;
extern const arch_fnct_t arch_sun;
extern const arch_fnct_t arch_xbox;

int change_arch_type_ncurses(disk_t *disk, const int verbose)
{
  /* arch_list must match the order from menuOptions */
  const arch_fnct_t *arch_list[]={&arch_i386, &arch_gpt, &arch_humax, &arch_mac, &arch_none, &arch_sun, &arch_xbox, NULL};
  unsigned int menu;
  for(menu=0;
      arch_list[menu]!=NULL && disk->arch!=arch_list[menu];
      menu++);
  if(arch_list[menu]==NULL)
  {
    menu=0;
    disk->arch=arch_list[menu];
  }
  /* ncurses interface */
  {
    int car;
    int real_key;
    const struct MenuItem menuOptions[]=
    {
      { 'I', arch_i386.part_name, "Intel/PC partition" },
      { 'G', arch_gpt.part_name, "EFI GPT partition map (Mac i386, some x86_64...)" },
      { 'H', arch_humax.part_name, "Humax partition table" },
      { 'M', arch_mac.part_name, "Apple partition map (legacy)" },
      { 'N', arch_none.part_name, "Non partitioned media" },
      { 'S', arch_sun.part_name, "Sun Solaris partition"},
      { 'X', arch_xbox.part_name, "XBox partition"},
      { 'Q', "Return", "Return to disk selection"},
      { 0, NULL, NULL }
    };
    aff_copy(stdscr);
    wmove(stdscr,5,0);
    wprintw(stdscr,"%s\n",disk->description_short(disk));
    wmove(stdscr,INTER_PARTITION_Y-1,0);
    wprintw(stdscr,"Please select the partition table type, press Enter when done.");
    if(disk->arch_autodetected!=NULL)
    {
      wmove(stdscr,19,0);
      wprintw(stdscr, "Hint: ");
      if(has_colors())
	wbkgdset(stdscr,' ' | COLOR_PAIR(2));
      wprintw(stdscr, "%s", disk->arch_autodetected->part_name);
      if(has_colors())
	wbkgdset(stdscr,' ' | COLOR_PAIR(0));
      wprintw(stdscr, " partition table type has been detected.");
    }
    if(disk->arch_autodetected!=&arch_none)
    {
      wmove(stdscr,20,0);
      wprintw(stdscr,"Note: Do NOT select 'None' for media with only a single partition. It's very");
      wmove(stdscr,21,0);
      wprintw(stdscr,"rare for a disk to be 'Non-partitioned'.");
    }
    car=wmenuSelect_ext(stdscr, 23, INTER_PARTITION_Y, INTER_PARTITION_X, menuOptions, 7, "IGHMNSXQ", MENU_BUTTON | MENU_VERT | MENU_VERT_WARN, &menu,&real_key);
    switch(car)
    {
      case 'i':
      case 'I':
        disk->arch=&arch_i386;
        break;
      case 'g':
      case 'G':
        disk->arch=&arch_gpt;
        break;
      case 'h':
      case 'H':
        disk->arch=&arch_humax;
        break;
      case 'm':
      case 'M':
        disk->arch=&arch_mac;
        break;
      case 'n':
      case 'N':
        disk->arch=&arch_none;
        break;
      case 's':
      case 'S':
        disk->arch=&arch_sun;
        break;
      case 'x':
      case 'X':
        disk->arch=&arch_xbox;
        break;
      case 'q':
      case 'Q':
        return 1;
    }
  }
  autoset_unit(disk);
  hd_update_geometry(disk, verbose);
  log_info("%s\n", disk->description_short(disk));
  log_info("Partition table type: %s\n", disk->arch->part_name);
  return 0;
}
#endif
