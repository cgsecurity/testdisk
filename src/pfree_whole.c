/*

    File: pfree_whole.c

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
#include "types.h"
#include "common.h"
#include "intrf.h"
#ifdef HAVE_NCURSES
#include "intrfn.h"
#endif
#include "log.h"
#include "pfree_whole.h"

#ifdef HAVE_NCURSES
int ask_mode_ext2(const disk_t *disk_car, const partition_t *partition, unsigned int *mode_ext2, unsigned int *carve_free_space_only)
{
  static const struct MenuItem menuMode[]=
    {
      {'E',"ext2/ext3","ext2/ext3/ext4 filesystem"},
      {'O',"Other","FAT/NTFS/HFS+/ReiserFS/..."},
      {0,NULL,NULL}
    };
  static const struct MenuItem menuexFAT[]=
  {
    {'F',"Free", "Scan for files from exFAT unallocated space only"},
    {'W',"Whole","Extract files from whole partition"},
    {0,NULL,NULL}
  };
  static const struct MenuItem menuFAT12[]=
  {
    {'F',"Free", "Scan for files from FAT12 unallocated space only"},
    {'W',"Whole","Extract files from whole partition"},
    {0,NULL,NULL}
  };
  static const struct MenuItem menuFAT16[]=
  {
    {'F',"Free", "Scan for files from FAT16 unallocated space only"},
    {'W',"Whole","Extract files from whole partition"},
    {0,NULL,NULL}
  };
  static const struct MenuItem menuFAT32[]=
  {
    {'F',"Free", "Scan for file from FAT32 unallocated space only"},
    {'W',"Whole","Extract files from whole partition"},
    {0,NULL,NULL}
  };
#if defined(HAVE_LIBNTFS) || defined(HAVE_LIBNTFS3G)
  static const struct MenuItem menuNTFS[]=
  {
    {'F',"Free", "Scan for file from NTFS unallocated space only"},
    {'W',"Whole","Extract files from whole partition"},
    {0,NULL,NULL}
  };
#endif
#ifdef HAVE_LIBEXT2FS
  static const struct MenuItem menuEXT2[]=
  {
    {'F',"Free", "Scan for file from ext2/ext3 unallocated space only"},
    {'W',"Whole","Extract files from whole partition"},
    {0,NULL,NULL}
  };
#endif
  const char *options="EO";
  WINDOW *window;
  unsigned int menu;
  int command;
  if(partition->upart_type==UP_EXT2 ||
      partition->upart_type==UP_EXT3 ||
      partition->upart_type==UP_EXT4)
    menu=0;
  else
    menu=1;
  window=newwin(LINES, COLS, 0, 0);	/* full screen */
  aff_copy(window);
  wmove(window,4,0);
  aff_part(window, AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition);
  wmove(window,6,0);
  waddstr(window,"To recover lost files, PhotoRec needs to know the filesystem type where the");
  wmove(window,7,0);
  waddstr(window,"file were stored:");
  command = wmenuSelect_ext(window, 23, 8, 0, menuMode, 11,
      options, MENU_VERT | MENU_VERT_WARN | MENU_BUTTON, &menu,NULL);
  *mode_ext2=(command=='E' || command=='e');
  if(*mode_ext2>0)
  {
    log_info("ext2/ext3/ext4 mode activated.\n");
  }
  {
    menu=0;
    options="FW";
    wmove(window,6,0);
    wclrtoeol(window);
    wmove(window,7,0);
    wclrtoeol(window);
    waddstr(window,"Please choose if all space needs to be analysed:");
    if(partition->upart_type==UP_EXFAT)
      command = wmenuSelect_ext(window, 23, 8, 0, menuexFAT, 11,
	  options, MENU_VERT | MENU_VERT_WARN | MENU_BUTTON, &menu,NULL);
    else if(partition->upart_type==UP_FAT12)
      command = wmenuSelect_ext(window, 23, 8, 0, menuFAT12, 11,
	  options, MENU_VERT | MENU_VERT_WARN | MENU_BUTTON, &menu,NULL);
    else if(partition->upart_type==UP_FAT16)
      command = wmenuSelect_ext(window, 23, 8, 0, menuFAT16, 11,
	  options, MENU_VERT | MENU_VERT_WARN | MENU_BUTTON, &menu,NULL);
    else if(partition->upart_type==UP_FAT32)
      command = wmenuSelect_ext(window, 23, 8, 0, menuFAT32, 11,
	  options, MENU_VERT | MENU_VERT_WARN | MENU_BUTTON, &menu,NULL);
#if defined(HAVE_LIBNTFS) || defined(HAVE_LIBNTFS3G)
    else if(partition->upart_type==UP_NTFS)
      command = wmenuSelect_ext(window, 23, 8, 0, menuNTFS, 11,
	  options, MENU_VERT | MENU_VERT_WARN | MENU_BUTTON, &menu,NULL);
#endif
#ifdef HAVE_LIBEXT2FS
    else if(partition->upart_type==UP_EXT2 || partition->upart_type==UP_EXT3 || partition->upart_type==UP_EXT4)
      command = wmenuSelect_ext(window, 23, 8, 0, menuEXT2, 11,
	  options, MENU_VERT | MENU_VERT_WARN | MENU_BUTTON, &menu,NULL);
#endif
    else
      command='W';
    *carve_free_space_only=(command=='F' || command=='f')?1:0;
    if(*carve_free_space_only>0)
    {
      log_info("Carve free space only.\n");
    }
  }
  delwin(window);
  return 0;
}
#endif
