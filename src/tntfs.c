/*

    File: tntfs.c

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
#include "ntfs.h"
#include "ntfs_fix.h"
#include "io_redir.h"
#include "log.h"
#include "log_part.h"
#include "tntfs.h"

#ifdef HAVE_NCURSES
static void dump_NTFS_ncurses(disk_t *disk_car, const partition_t *partition, const unsigned char *buffer_bs, const unsigned char *buffer_backup_bs)
{
  WINDOW *window=newwin(LINES, COLS, 0, 0);	/* full screen */
  keypad(window, TRUE); /* Need it to get arrow key */
  aff_copy(window);
  wmove(window,4,0);
  wprintw(window,"%s",disk_car->description(disk_car));
  wmove(window,5,0);
  aff_part(window,AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition);
  mvwaddstr(window,6,0, "Boot sector                        Backup boot sector");
  dump2(window, buffer_bs, buffer_backup_bs, NTFS_BOOT_SECTOR_SIZE);
  delwin(window);
  (void) clearok(stdscr, TRUE);
#ifdef HAVE_TOUCHWIN
  touchwin(stdscr);
#endif
}
#endif

static void dump_NTFS(disk_t *disk_car, const partition_t *partition, const unsigned char *buffer_bs, const unsigned char *buffer_backup_bs)
{
  log_info("Boot sector                        Backup boot sector\n");
  dump2_log(buffer_bs, buffer_backup_bs, NTFS_BOOT_SECTOR_SIZE);
#ifdef HAVE_NCURSES
  dump_NTFS_ncurses(disk_car, partition, buffer_bs, buffer_backup_bs);
#endif
}

static int ntfs_boot_sector_command(char **current_cmd, const char *options)
{
  skip_comma_in_command(current_cmd);
  if(check_command(current_cmd,"rebuildbs",9)==0)
  {
    return 'R';
  }
  else if(check_command(current_cmd,"dump",4)==0)
  {
    return 'D';
  }
  else if(check_command(current_cmd,"list",4)==0)
  {
    return 'L';
  }
  else if(check_command(current_cmd,"originalntfs",12)==0)
  {
    if(strchr(options,'O')!=NULL)
      return 'O';
  }
  else if(check_command(current_cmd,"backupntfs",10)==0)
  {
    if(strchr(options,'B')!=NULL)
      return 'B';
  }
  else if(check_command(current_cmd,"repairmft",9)==0)
  {
    if(strchr(options,'M')!=NULL)
      return 'M';
  }
  return 0;
}

static int is_no_confirm_command(char **current_cmd)
{
  skip_comma_in_command(current_cmd);
  if(check_command(current_cmd,"noconfirm",9)==0)
  {
    return 1;
  }
  return 0;
}

static const char *ntfs_boot_sector_scan(disk_t *disk, partition_t *partition, unsigned char *buffer_bs, unsigned char *buffer_backup_bs, unsigned int *menu, const int verbose, const unsigned int expert)
{
  int identical_sectors;
  int opt_B=0;
  int opt_O=0;
#ifdef HAVE_NCURSES
  aff_copy(stdscr);
  wmove(stdscr,4,0);
  wprintw(stdscr,"%s",disk->description(disk));
  mvwaddstr(stdscr,5,0,msg_PART_HEADER_LONG);
  wmove(stdscr,6,0);
  aff_part(stdscr,AFF_PART_ORDER|AFF_PART_STATUS,disk,partition);
#endif
  log_info("\nntfs_boot_sector\n");
  log_partition(disk,partition);
  screen_buffer_add("Boot sector\n");
  if(disk->pread(disk, buffer_bs, NTFS_BOOT_SECTOR_SIZE, partition->part_offset) != NTFS_BOOT_SECTOR_SIZE)
  {
    screen_buffer_add("ntfs_boot_sector: Can't read boot sector.\n");
    memset(buffer_bs,0,NTFS_BOOT_SECTOR_SIZE);
  }
  if(test_NTFS(disk,(struct ntfs_boot_sector*)buffer_bs,partition,verbose,0)==0)
  {
    screen_buffer_add("Status: OK\n");
    opt_O=1;
  }
  else
  {
    screen_buffer_add("Status: Bad\n");
  }
  screen_buffer_add("\nBackup boot sector\n");
  if(disk->pread(disk, buffer_backup_bs, NTFS_BOOT_SECTOR_SIZE, partition->part_offset + partition->part_size - disk->sector_size) != NTFS_BOOT_SECTOR_SIZE)
  {
    screen_buffer_add("ntfs_boot_sector: Can't read backup boot sector.\n");
    memset(buffer_backup_bs,0,NTFS_BOOT_SECTOR_SIZE);
  }
  if(test_NTFS(disk,(struct ntfs_boot_sector*)buffer_backup_bs,partition,verbose,0)==0)
  {
    screen_buffer_add("Status: OK\n");
    opt_B=1;
  }
  else
  {
    screen_buffer_add("Status: Bad\n");
  }
  screen_buffer_add("\n");
  if(memcmp(buffer_bs,buffer_backup_bs,NTFS_BOOT_SECTOR_SIZE)==0)
  {
    log_ntfs_info((const struct ntfs_boot_sector *)buffer_bs);
    screen_buffer_add("Sectors are identical.\n");
    identical_sectors=1;
  }
  else
  {
    log_ntfs2_info((const struct ntfs_boot_sector *)buffer_bs, (const struct ntfs_boot_sector *)buffer_backup_bs);
    screen_buffer_add("Sectors are not identical.\n");
    identical_sectors=0;
  }
  screen_buffer_add("\n");
  screen_buffer_add("A valid NTFS Boot sector must be present in order to access\n");
  screen_buffer_add("any data; even if the partition is not bootable.\n");
  if(opt_B!=0 && opt_O!=0)
  {
    if(identical_sectors==0)
      return "DOBRL";
    else
      return "DRML";
  }
  else if(opt_B!=0)
  {
    *menu=5;
    if(expert>0)
      return "DBRML";
    else
      return "DBRL";
  }
  else if(opt_O!=0)
  {
    *menu=4;
    return "DORL";
  }
  return "DR";
}

int ntfs_boot_sector(disk_t *disk, partition_t *partition, const int verbose, const unsigned int expert, char **current_cmd)
{
  unsigned char *buffer_bs;
  unsigned char *buffer_backup_bs;
#ifdef HAVE_NCURSES
  const struct MenuItem menu_ntfs[]=
  {
    { 'P', "Previous",""},
    { 'N', "Next","" },
    { 'Q', "Quit","Return to Advanced menu"},
    { 'L', "List", "List directories and files, copy data from NTFS" },
    { 'O', "Org. BS","Copy boot sector over backup sector"},
    { 'B', "Backup BS","Copy backup boot sector over boot sector"},
    { 'R', "Rebuild BS","Rebuild boot sector"},
    { 'M', "Repair MFT","Check MFT"},
    { 'D', "Dump","Dump boot sector and backup boot sector"},
    { 0, NULL, NULL }
  };
#endif
  buffer_bs=(unsigned char*)MALLOC(NTFS_BOOT_SECTOR_SIZE);
  buffer_backup_bs=(unsigned char*)MALLOC(NTFS_BOOT_SECTOR_SIZE);

  while(1)
  {
    unsigned int menu=0;
    int no_confirm = 0;
    int command;
    const char *options;
    screen_buffer_reset();
    options=ntfs_boot_sector_scan(disk, partition, buffer_bs, buffer_backup_bs, &menu, verbose, expert);
    screen_buffer_to_log();
    if(*current_cmd!=NULL)
    {
      no_confirm=is_no_confirm_command(current_cmd);
      command=ntfs_boot_sector_command(current_cmd, options);
    }
    else
    {
      log_flush();
#ifdef HAVE_NCURSES
      command=screen_buffer_display_ext(stdscr, options, menu_ntfs, &menu);
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
      case 'O': /* O : copy original boot sector over backup boot */
#ifdef HAVE_NCURSES
	if(no_confirm == 1 || ask_confirmation("Copy original NTFS boot sector over backup boot, confirm ? (Y/N)")!=0)
#endif
	{
	  log_info("copy original boot sector over backup boot\n");
	  if(disk->pwrite(disk, buffer_bs, NTFS_BOOT_SECTOR_SIZE, partition->part_offset + partition->part_size - disk->sector_size) != NTFS_BOOT_SECTOR_SIZE)
	  {
	    display_message("Write error: Can't overwrite NTFS backup boot sector\n");
	  }
          disk->sync(disk);
	}
	break;
      case 'B': /* B : copy backup boot sector over boot sector */
#ifdef HAVE_NCURSES
	if(no_confirm == 1 || ask_confirmation("Copy backup NTFS boot sector over boot sector, confirm ? (Y/N)")!=0)
#endif
	{
	  log_info("copy backup boot sector over boot sector\n");
	  /* Reset information about backup boot sector */
	  partition->sb_offset=0;
	  if(disk->pwrite(disk, buffer_backup_bs, NTFS_BOOT_SECTOR_SIZE, partition->part_offset) != NTFS_BOOT_SECTOR_SIZE)
	  {
	    display_message("Write error: Can't overwrite NTFS boot sector\n");
	  }
          disk->sync(disk);
	}
	break;
      case 'L':
	if(strchr(options,'O')==NULL && strchr(options,'B')!=NULL)
	{
	  io_redir_add_redir(disk,partition->part_offset,NTFS_BOOT_SECTOR_SIZE,0,buffer_backup_bs);
	  dir_partition(disk, partition, 0, expert, current_cmd);
	  io_redir_del_redir(disk,partition->part_offset);
	}
	else
	  dir_partition(disk, partition, 0, expert, current_cmd);
	break;
      case 'M':
        repair_MFT(disk, partition, verbose, expert, current_cmd);
	break;
      case 'R': /* R : rebuild boot sector */
	rebuild_NTFS_BS(disk, partition, verbose, expert, current_cmd);
	break;
      case 'D':
	dump_NTFS(disk, partition, buffer_bs, buffer_backup_bs);
	break;
    }
  }
}
