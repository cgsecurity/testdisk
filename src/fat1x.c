/*

    File: fat1x.c

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
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include "types.h"
#include "common.h"
#include "lang.h"
#include "intrf.h"
#include "intrfn.h"
#include "dirpart.h"
#include "fat.h"
#include "log.h"
#include "log_part.h"
#include "fat_adv.h"
#include "fat1x.h"

#ifdef HAVE_NCURSES
static void dump_fat1x_ncurses(disk_t *disk_car, partition_t *partition, const unsigned char *buffer_bs)
{
  WINDOW *window=newwin(LINES, COLS, 0, 0);	/* full screen */
  keypad(window, TRUE); /* Need it to get arrow key */
  aff_copy(window);
  wmove(window,4,0);
  wprintw(window,"%s",disk_car->description(disk_car));
  wmove(window,5,0);
  aff_part(window,AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition);
  mvwaddstr(window,6,0, "Boot sector");
  dump(window,buffer_bs,FAT1x_BOOT_SECTOR_SIZE);
  delwin(window);
  (void) clearok(stdscr, TRUE);
#ifdef HAVE_TOUCHWIN
  touchwin(stdscr);
#endif
}
#endif

static void dump_fat1x(disk_t *disk_car, partition_t *partition, const unsigned char *buffer_bs, char **current_cmd)
{
  log_info("Boot sector\n");
  dump_log(buffer_bs, FAT1x_BOOT_SECTOR_SIZE);
  if(current_cmd==NULL || *current_cmd==NULL)
  {
#ifdef HAVE_NCURSES
    dump_fat1x_ncurses(disk_car, partition, buffer_bs);
#endif
  }
}

int fat1x_boot_sector(disk_t *disk_car, partition_t *partition, const int verbose, const int dump_ind, const unsigned int expert, char **current_cmd)
{
  unsigned char *buffer_bs;
#ifdef HAVE_NCURSES
  const struct MenuItem menu_fat1x[]=
  {
    { 'P', "Previous",""},
    { 'N', "Next","" },
    { 'Q', "Quit","Return to Advanced menu"},
    { 'R', "Rebuild BS","Rebuild boot sector"},
    { 'L', "List", "List directories and files, copy and undelete data from FAT" },
    { 'D', "Dump","Dump boot sector and backup boot sector"},
    { 'C', "Repair FAT","Very Dangerous! Expert only"},
    { 'I', "Init Root","Init root directory: Very Dangerous! Expert only"},
    { 0, NULL, NULL }
  };
#endif
  buffer_bs=(unsigned char*)MALLOC(FAT1x_BOOT_SECTOR_SIZE);
  while(1)
  {
    const char *options;
#ifdef HAVE_NCURSES
    unsigned int menu=3;
#endif
    int command;
    screen_buffer_reset();
    {
#ifdef HAVE_NCURSES
      aff_copy(stdscr);
      wmove(stdscr,4,0);
      wprintw(stdscr,"%s",disk_car->description(disk_car));
      mvwaddstr(stdscr,5,0,msg_PART_HEADER_LONG);
      wmove(stdscr,6,0);
      aff_part(stdscr,AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition);
#endif
      log_info("\nfat1x_boot_sector\n");
      log_partition(disk_car,partition);
      screen_buffer_add("Boot sector\n");
      if(disk_car->pread(disk_car, buffer_bs, FAT1x_BOOT_SECTOR_SIZE, partition->part_offset) != FAT1x_BOOT_SECTOR_SIZE)
      {
	screen_buffer_add("fat1x_boot_sector: Can't read boot sector.\n");
	memset(buffer_bs,0,FAT1x_BOOT_SECTOR_SIZE);
      }
      if(test_FAT(disk_car,(const struct fat_boot_sector *)buffer_bs,partition,verbose,0)==0)
      {
	screen_buffer_add("OK\n");
	if(expert==0)
	  options="DRCL";
	else
	  options="DRCIL";
      }
      else
      {
	screen_buffer_add("Bad\n");
	options="DRC";
      }
      screen_buffer_add("\n");
      screen_buffer_add("A valid FAT Boot sector must be present in order to access\n");
      screen_buffer_add("any data; even if the partition is not bootable.\n");
    }
    screen_buffer_to_log();
    if(*current_cmd!=NULL)
    {
      command=0;
      skip_comma_in_command(current_cmd);
      if(check_command(current_cmd,"rebuildbs",9)==0)
      {
	command='R';
      }
      else if(check_command(current_cmd,"dump",4)==0)
      {
	command='D';
      }
      else if(check_command(current_cmd,"list",4)==0)
      {
	if(strchr(options,'L')!=NULL)
	  command='L';
      }
      else if(check_command(current_cmd,"repairfat",9)==0)
      {
	if(strchr(options,'C')!=NULL)
	  command='C';
      }
      else if(check_command(current_cmd,"initroot",8)==0)
      {
	if(strchr(options,'I')!=NULL)
	    command='I';
      }
    }
    else
    {
      log_flush();
#ifdef HAVE_NCURSES
      command=screen_buffer_display_ext(stdscr, options, menu_fat1x, &menu);
#else
      command=0;
#endif
    }
    switch(command)
    {
      case 0:
	free(buffer_bs);
	return 0;
      case 'R': /* R : rebuild boot sector */
	rebuild_FAT_BS(disk_car, partition, verbose, dump_ind, expert, current_cmd);
	break;
      case 'D':
	dump_fat1x(disk_car, partition, buffer_bs, current_cmd);
	break;
      case 'C':
	repair_FAT_table(disk_car, partition, verbose, current_cmd);
	break;
      case 'I':
	FAT_init_rootdir(disk_car, partition, verbose, current_cmd);
	break;
      case 'L':
	dir_partition(disk_car, partition, 0, 0, current_cmd);
	break;
    }
  }
}
