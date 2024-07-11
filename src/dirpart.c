/*

    File: dirpart.c

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
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include "types.h"
#include "common.h"
#include "fat.h"
#include "intrf.h"
#ifdef HAVE_NCURSES
#include "intrfn.h"
#endif
#include "dir.h"
#include "dirn.h"
#include "exfat_dir.h"
#include "ext2_dir.h"
#include "fat_dir.h"
#include "ntfs_dir.h"
#include "rfs_dir.h"
#include "dirpart.h"
#include "ntfs.h"
#include "adv.h"
#include "log.h"
#include "log_part.h"

static dir_partition_t dir_partition_init(disk_t *disk, const partition_t *partition, const int verbose, const int expert, dir_data_t *dir_data)
{
  if(is_part_fat(partition))
  {
    if(dir_partition_fat_init(disk, partition, dir_data, verbose)==DIR_PART_OK)
      return DIR_PART_OK;
  }
  else if(is_part_ntfs(partition))
  {
    if(dir_partition_ntfs_init(disk, partition, dir_data, verbose, expert)==DIR_PART_OK)
      return DIR_PART_OK;
    if(dir_partition_exfat_init(disk, partition, dir_data, verbose)==DIR_PART_OK)
      return DIR_PART_OK;
  }
  else if(is_part_linux(partition))
  {
    if(dir_partition_ext2_init(disk, partition, dir_data, verbose)==DIR_PART_OK)
      return DIR_PART_OK;
    if(dir_partition_reiser_init(disk, partition, dir_data, verbose)==DIR_PART_OK)
      return DIR_PART_OK;
  }
  switch(partition->upart_type)
  {
    case UP_FAT12:
    case UP_FAT16:
    case UP_FAT32:
      return dir_partition_fat_init(disk, partition, dir_data, verbose);
    case UP_EXT4:
    case UP_EXT3:
    case UP_EXT2:
      return dir_partition_ext2_init(disk, partition, dir_data, verbose);
    case UP_RFS:
    case UP_RFS2:
    case UP_RFS3:
      return dir_partition_reiser_init(disk, partition, dir_data, verbose);
    case UP_NTFS:
      return dir_partition_ntfs_init(disk, partition, dir_data, verbose, expert);
    case UP_EXFAT:
      return dir_partition_exfat_init(disk, partition, dir_data, verbose);
    default:
      return DIR_PART_ENOIMP;
  }
}

dir_partition_t dir_partition(disk_t *disk, const partition_t *partition, const int verbose, const int expert, char **current_cmd)
{
  dir_data_t dir_data;
#ifdef HAVE_NCURSES
  WINDOW *window;
#endif
  dir_partition_t res;
  fflush(stderr);
  dir_data.local_dir=NULL;
  res=dir_partition_init(disk, partition, verbose, expert, &dir_data);
#ifdef HAVE_NCURSES
  window=newwin(LINES, COLS, 0, 0);	/* full screen */
  dir_data.display=window;
  aff_copy(window);
#else
  dir_data.display=NULL;
#endif
  log_info("\n");
  switch(res)
  {
    case DIR_PART_ENOIMP:
      screen_buffer_reset();
#ifdef HAVE_NCURSES
      aff_copy(window);
      wmove(window,4,0);
      aff_part(window,AFF_PART_ORDER|AFF_PART_STATUS,disk,partition);
#endif
      log_partition(disk,partition);
      screen_buffer_add("Support for this filesystem hasn't been implemented.\n");
      screen_buffer_to_log();
      if(current_cmd==NULL || *current_cmd==NULL)
      {
#ifdef HAVE_NCURSES
	screen_buffer_display(window,"",NULL);
#endif
      }
      break;
    case DIR_PART_ENOSYS:
      screen_buffer_reset();
#ifdef HAVE_NCURSES
      aff_copy(window);
      wmove(window,4,0);
      aff_part(window,AFF_PART_ORDER|AFF_PART_STATUS,disk,partition);
#endif
      log_partition(disk,partition);
      screen_buffer_add("Support for this filesystem wasn't enabled during compilation.\n");
      screen_buffer_to_log();
      if(current_cmd==NULL || *current_cmd==NULL)
      {
#ifdef HAVE_NCURSES
	screen_buffer_display(window,"",NULL);
#endif
      }
      break;
    case DIR_PART_EIO:
      screen_buffer_reset();
#ifdef HAVE_NCURSES
      aff_copy(window);
      wmove(window,4,0);
      aff_part(window,AFF_PART_ORDER|AFF_PART_STATUS,disk,partition);
#endif
      log_partition(disk,partition);
      screen_buffer_add("Can't open filesystem. Filesystem seems damaged.\n");
      screen_buffer_to_log();
      if(current_cmd==NULL || *current_cmd==NULL)
      {
#ifdef HAVE_NCURSES
	screen_buffer_display(window,"",NULL);
#endif
      }
      break;
    case DIR_PART_OK:
      {
	int recursive=0;
	int copy_files=0;
	if(current_cmd!=NULL && *current_cmd!=NULL)
	{
	  int do_continue;
	  do
	  {
	    do_continue=0;
	    skip_comma_in_command(current_cmd);
	    if(check_command(current_cmd,"recursive",9)==0)
	    {
	      recursive=1;
	      do_continue=1;
	    }
	    else if(check_command(current_cmd,"fullpathname",12)==0)
	    {
	      dir_data.param|=FLAG_LIST_PATHNAME;
	      do_continue=1;
	    }
	    else if(check_command(current_cmd, "filecopy", 8)==0)
	    {
	      copy_files=1;
	      do_continue=1;
	    }
	  } while(do_continue==1);
	}
	if(recursive>0)
	  dir_whole_partition_log(disk,partition,&dir_data,dir_data.current_inode);
	else
	{
#ifdef HAVE_NCURSES
	  dir_partition_aff(disk, partition, &dir_data, dir_data.current_inode, current_cmd);
#else
	  if(dir_data.verbose>0)
	  {
	    log_info("\ndir_partition inode=%lu\n", dir_data.current_inode);
	    log_partition(disk, partition);
	  }
	  {
	    file_info_t dir_list;
	    TD_INIT_LIST_HEAD(&dir_list.list);
	    dir_data.get_dir(disk, partition, &dir_data, dir_data.current_inode, &dir_list);
	    dir_aff_log(&dir_data, &dir_list);
	    delete_list_file(&dir_list);
	  }
#endif
	}
	if(copy_files>0)
	  dir_whole_partition_copy(disk,partition,&dir_data,dir_data.current_inode);
	dir_data.close(&dir_data);
      }
      break;
  }
#ifdef HAVE_NCURSES
  delwin(window);
  (void) clearok(stdscr, TRUE);
#ifdef HAVE_TOUCHWIN
  touchwin(stdscr);
#endif
  wrefresh(stdscr);
#endif
  fflush(stderr);
  free(dir_data.local_dir);
  return res;
}
