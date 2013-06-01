/*

    File: thfs.c

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
#include <ctype.h>
#include "types.h"
#include "common.h"
#include "lang.h"
#include "intrf.h"
#include "intrfn.h"
#include "hfs.h"
#include "hfsp.h"
#include "log.h"
#include "log_part.h"
#include "thfs.h"

#ifdef HAVE_NCURSES
static void hfs_dump_ncurses(disk_t *disk_car, const partition_t *partition, const unsigned char *buffer_bs, const unsigned char *buffer_backup_bs)
{
  WINDOW *window=newwin(LINES, COLS, 0, 0);	/* full screen */
  keypad(window, TRUE); /* Need it to get arrow key */
  aff_copy(window);
  wmove(window,4,0);
  wprintw(window,"%s",disk_car->description(disk_car));
  wmove(window,5,0);
  aff_part(window,AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition);
  mvwaddstr(window,6,0, "Superblock                        Backup superblock");
  dump2(window, buffer_bs, buffer_backup_bs, HFSP_BOOT_SECTOR_SIZE);
  delwin(window);
  (void) clearok(stdscr, TRUE);
#ifdef HAVE_TOUCHWIN
  touchwin(stdscr);
#endif
}
#endif

static void hfs_dump(disk_t *disk_car, const partition_t *partition, const unsigned char *buffer_bs, const unsigned char *buffer_backup_bs, char **current_cmd)
{
  log_info("Superblock                        Backup superblock\n");
  dump2_log(buffer_bs, buffer_backup_bs, HFSP_BOOT_SECTOR_SIZE);
  if(*current_cmd==NULL)
  {
#ifdef HAVE_NCURSES
    hfs_dump_ncurses(disk_car, partition, buffer_bs, buffer_backup_bs);
#endif
  }
}

int HFS_HFSP_boot_sector(disk_t *disk_car, partition_t *partition, const int verbose, char **current_cmd)
{
  unsigned char *buffer_bs;
  unsigned char *buffer_backup_bs;
  const char *options="";
  int rescan=1;
#ifdef HAVE_NCURSES
  const struct MenuItem menu_hfsp[]=
  {
    { 'P', "Previous",""},
    { 'N', "Next","" },
    { 'Q', "Quit","Return to Advanced menu"},
    { 'O', "Org. BS","Copy superblock over backup sector"},
    { 'B', "Backup BS","Copy backup superblock over superblock"},
    { 'D', "Dump","Dump superblock and backup superblock"},
    { 0, NULL, NULL }
  };
#endif
  buffer_bs=(unsigned char*)MALLOC(HFSP_BOOT_SECTOR_SIZE);
  buffer_backup_bs=(unsigned char*)MALLOC(HFSP_BOOT_SECTOR_SIZE);

  while(1)
  {
#ifdef HAVE_NCURSES
    unsigned int menu=0;
#endif
    int command;
    screen_buffer_reset();
    if(rescan==1)
    {
      int opt_over=0;
      int opt_B=0;
      int opt_O=0;
      options="D";
#ifdef HAVE_NCURSES
      aff_copy(stdscr);
      wmove(stdscr,4,0);
      wprintw(stdscr,"%s",disk_car->description(disk_car));
      mvwaddstr(stdscr,5,0,msg_PART_HEADER_LONG);
      wmove(stdscr,6,0);
      aff_part(stdscr,AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition);
#endif
      log_info("\nHFS_HFSP_boot_sector\n");
      log_partition(disk_car,partition);
      screen_buffer_add("Volume header\n");
      if(disk_car->pread(disk_car, buffer_bs, HFSP_BOOT_SECTOR_SIZE, partition->part_offset + 0x400) != HFSP_BOOT_SECTOR_SIZE)
      {
	screen_buffer_add("Bad: can't read HFS/HFS+ volume header.\n");
	memset(buffer_bs,0,HFSP_BOOT_SECTOR_SIZE);
      }
      else if(test_HFSP(disk_car,(const struct hfsp_vh*)buffer_bs,partition,verbose,0)==0)
      {
	screen_buffer_add("HFS+ OK\n");
	opt_O=1;
	opt_over=1;
      }
      else if(test_HFS(disk_car,(const hfs_mdb_t*)buffer_bs,partition,verbose,0)==0)
      {
	screen_buffer_add("HFS Ok\n");
	opt_O=1;
	opt_over=1;
      }
      else
	screen_buffer_add("Bad\n");
      screen_buffer_add("\nBackup volume header\n");
      if(disk_car->pread(disk_car, buffer_backup_bs, HFSP_BOOT_SECTOR_SIZE, partition->part_offset + partition->part_size - 0x400) != HFSP_BOOT_SECTOR_SIZE)
      {
	screen_buffer_add("Bad: can't read HFS/HFS+ backup volume header.\n");
	memset(buffer_backup_bs,0,HFSP_BOOT_SECTOR_SIZE);
      }
      else if(test_HFSP(disk_car,(const struct hfsp_vh*)buffer_backup_bs,partition,verbose,0)==0)
      {
	screen_buffer_add("HFS+ OK\n");
	opt_B=1;
	opt_over=1;
      }
      else if(test_HFS(disk_car,(const hfs_mdb_t*)buffer_backup_bs,partition,verbose,0)==0)
      {
	screen_buffer_add("HFS Ok\n");
	opt_B=1;
	opt_over=1;
      }
      else
	screen_buffer_add("Bad\n");
      screen_buffer_add("\n");
      if(memcmp(buffer_bs,buffer_backup_bs,HFSP_BOOT_SECTOR_SIZE)==0)
      {
	screen_buffer_add("Sectors are identical.\n");
	opt_over=0;
      }
      else
      {
	screen_buffer_add("Sectors are not identical.\n");
      }
      if(opt_over!=0)
      {
	if(opt_B!=0 && opt_O!=0)
	  options="DOB";
	else if(opt_B!=0)
	  options="DB";
	else if(opt_O!=0)
	  options="DO";
      }
      rescan=0;
    }
    screen_buffer_to_log();
    if(*current_cmd!=NULL)
    {
      command=0;
      while(*current_cmd[0]==',')
	(*current_cmd)++;
      if(strncmp(*current_cmd,"dump",4)==0)
      {
	(*current_cmd)+=4;
	command='D';
      }
      else if(strncmp(*current_cmd,"originalhfsp",11)==0)
      {
	(*current_cmd)+=11;
	if(strchr(options,'O')!=NULL)
	    command='O';
      }
      else if(strncmp(*current_cmd,"backuphfsp",9)==0)
      {
	(*current_cmd)+=9;
	if(strchr(options,'B')!=NULL)
	    command='B';
      }
    }
    else
    {
      log_flush();
#ifdef HAVE_NCURSES
      wredrawln(stdscr,0,getmaxy(stdscr));
      command=screen_buffer_display_ext(stdscr, options, menu_hfsp, &menu);
#else
      command=0;
#endif
    }
    switch(command)
    {
      case 0:
        free(buffer_bs);
        free(buffer_backup_bs);
	return 0;
      case 'O': /* O : copy original superblock over backup boot */
#ifdef HAVE_NCURSES
	if(ask_confirmation("Copy original HFS/HFS+ volume header over backup, confirm ? (Y/N)")!=0)
	{
	  log_info("copy original superblock over backup boot\n");
	  if(disk_car->pwrite(disk_car, buffer_bs, HFSP_BOOT_SECTOR_SIZE, partition->part_offset + partition->part_size - 0x400) != HFSP_BOOT_SECTOR_SIZE)
	  {
	    display_message("Write error: Can't overwrite HFS/HFS+ backup volume header\n");
	  }
          disk_car->sync(disk_car);
	  rescan=1;
	}
#endif
	break;
      case 'B': /* B : copy backup superblock over main superblock */
#ifdef HAVE_NCURSES
	if(ask_confirmation("Copy backup HFS/HFS+ volume header over main volume header, confirm ? (Y/N)")!=0)
	{
	  log_info("copy backup superblock over main superblock\n");
	  /* Reset information about backup boot sector */
	  partition->sb_offset=0;
	  if(disk_car->pwrite(disk_car, buffer_backup_bs, HFSP_BOOT_SECTOR_SIZE, partition->part_offset + 0x400) != HFSP_BOOT_SECTOR_SIZE)
	  {
	    display_message("Write error: Can't overwrite HFS/HFS+ main volume header\n");
	  }
          disk_car->sync(disk_car);
	  rescan=1;
	}
#endif
	break;
      case 'D':
	hfs_dump(disk_car, partition, buffer_bs, buffer_backup_bs, current_cmd);
	break;
    }
  }
}
