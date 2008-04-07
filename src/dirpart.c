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
 
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#include "types.h"
#include "common.h"
#include "fat.h"
#include "lang.h"
#include "fnctdsk.h"
#include "testdisk.h"
#include "intrf.h"
#ifdef HAVE_NCURSES
#include "intrfn.h"
#else
#include <stdio.h>
#endif
#include "dir.h"
#include "ext2_dir.h"
#include "fat_dir.h"
#include "ntfs_dir.h"
#include "rfs_dir.h"
#include "dirpart.h"
#include "ntfs.h"
#include "adv.h"
#include "log.h"

int dir_partition(disk_t *disk_car, const partition_t *partition, const int verbose, char **current_cmd)
{
  dir_data_t dir_data;
#ifdef HAVE_NCURSES
  WINDOW *window;
#endif
  int res=-3;
  if(is_part_fat(partition))
    res=dir_partition_fat_init(disk_car,partition,&dir_data,verbose);
  else if(is_part_ntfs(partition))
    res=dir_partition_ntfs_init(disk_car,partition,&dir_data,verbose);
  else if(is_part_linux(partition))
  {
    res=dir_partition_ext2_init(disk_car,partition,&dir_data,verbose);
    if(res!=0)
      res=dir_partition_reiser_init(disk_car,partition,&dir_data,verbose);
  }
  if(res!=0)
  {
    switch(partition->upart_type)
    {
      case UP_FAT12:
      case UP_FAT16:
      case UP_FAT32:
	res=dir_partition_fat_init(disk_car,partition,&dir_data,verbose);
	break;
      case UP_EXT3:
      case UP_EXT2:
	res=dir_partition_ext2_init(disk_car,partition,&dir_data,verbose);
	break;
      case UP_RFS:
      case UP_RFS2:
      case UP_RFS3:
	res=dir_partition_reiser_init(disk_car,partition,&dir_data,verbose);
	break;
      case UP_NTFS:
	res=dir_partition_ntfs_init(disk_car,partition,&dir_data,verbose);
	break;
      default:
	return res;
    }
  }
#ifdef HAVE_NCURSES
  window=newwin(0,0,0,0);	/* full screen */
  dir_data.display=window;
  aff_copy(window);
#else
  dir_data.display=NULL;
#endif
  log_info("\n");
  switch(res)
  {
    case -2:
      screen_buffer_reset();
#ifdef HAVE_NCURSES
      aff_copy(window);
      wmove(window,4,0);
      aff_part(window,AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition);
#endif
      log_partition(disk_car,partition);
      screen_buffer_add("Support for this filesystem hasn't been enable during compilation.\n");
      screen_buffer_to_log();
      if(*current_cmd==NULL)
      {
#ifdef HAVE_NCURSES
	screen_buffer_display(window,"",NULL);
#endif
      }
      break;
    case -1:
      screen_buffer_reset();
#ifdef HAVE_NCURSES
      aff_copy(window);
      wmove(window,4,0);
      aff_part(window,AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition);
#endif
      log_partition(disk_car,partition);
      screen_buffer_add("Can't open filesystem. Filesystem seems damaged.\n");
      screen_buffer_to_log();
      if(*current_cmd==NULL)
      {
#ifdef HAVE_NCURSES
	screen_buffer_display(window,"",NULL);
#endif
      }
      break;
    default:
      if(*current_cmd!=NULL)
      {
	while(*current_cmd[0]==',')
	  (*current_cmd)++;
	if(strncmp(*current_cmd,"recursive",9)==0)
	{
	  (*current_cmd)+=9;
	  dir_whole_partition_log(disk_car,partition,&dir_data,dir_data.current_inode);
	}
      }
      dir_partition_aff(disk_car,partition,&dir_data,dir_data.current_inode,current_cmd);
      dir_data.close(&dir_data);
      break;
  }
#ifdef HAVE_NCURSES
  delwin(window);
  (void) clearok(stdscr, TRUE);
#ifdef HAVE_TOUCHWIN
  touchwin(stdscr);
#endif
#endif
  return res;
}
