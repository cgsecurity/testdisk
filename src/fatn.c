/*

    File: fatn.c

    Copyright (C) 1998-2009 Christophe GRENIER <grenier@cgsecurity.org>

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
#include "types.h"
#include "common.h"
#include "intrf.h"
#include "intrfn.h"
#include "fat.h"
#include "fatn.h"
#include "fat_common.h"

int dump_fat_info_ncurses(const struct fat_boot_sector*fh1, const upart_type_t upart_type, const unsigned int sector_size)
{
  switch(upart_type)
  {
    case UP_FAT12:
      wprintw(stdscr,"FAT : 12\n");
      break;
    case UP_FAT16:
      wprintw(stdscr,"FAT : 16\n");
      break;
    case UP_FAT32:
      wprintw(stdscr,"FAT : 32\n");
      break;
    default:
      wprintw(stdscr,"Not a FAT\n");
      return 0;
  }
  wprintw(stdscr,"cluster_size %u\n", fh1->sectors_per_cluster);
  wprintw(stdscr,"reserved     %u\n", le16(fh1->reserved));
  if(fat_sectors(fh1)!=0)
    wprintw(stdscr,"sectors      %u\n", fat_sectors(fh1));
  if(le32(fh1->total_sect)!=0)
    wprintw(stdscr,"total_sect   %u\n", (unsigned int)le32(fh1->total_sect));
  if(upart_type==UP_FAT32)
  {
    wprintw(stdscr,"fat32_length %u\n", (unsigned int)le32(fh1->fat32_length));
    wprintw(stdscr,"root_cluster %u\n", (unsigned int)le32(fh1->root_cluster));
    wprintw(stdscr,"flags        %04X\n", le16(fh1->flags));
    wprintw(stdscr,"version      %u.%u\n", fh1->version[0], fh1->version[1]);
    wprintw(stdscr,"root_cluster %u\n", (unsigned int)le32(fh1->root_cluster));
    wprintw(stdscr,"info_sector  %u\n", le16(fh1->info_sector));
    wprintw(stdscr,"backup_boot  %u\n", le16(fh1->backup_boot));
    if(fat32_get_free_count((const unsigned char*)fh1,sector_size)==0xFFFFFFFF)
      wprintw(stdscr,"free_count   uninitialised\n");
    else
      wprintw(stdscr,"free_count   %lu\n",fat32_get_free_count((const unsigned char*)fh1,sector_size));
    if(fat32_get_next_free((const unsigned char*)fh1,sector_size)==0xFFFFFFFF)
      wprintw(stdscr,"next_free    uninitialised\n");
    else
      wprintw(stdscr,"next_free    %lu\n",fat32_get_next_free((const unsigned char*)fh1,sector_size));
  } else {
    wprintw(stdscr,"fat_length   %u\n", le16(fh1->fat_length));
    wprintw(stdscr,"dir_entries  %u\n", get_dir_entries(fh1));
  }
  return 0;
}

int dump_2fat_info_ncurses(const struct fat_boot_sector*fh1, const struct fat_boot_sector*fh2, const upart_type_t upart_type, const unsigned int sector_size)
{
  switch(upart_type)
  {
    case UP_FAT12:
      wprintw(stdscr,"FAT : 12\n");
      break;
    case UP_FAT16:
      wprintw(stdscr,"FAT : 16\n");
      break;
    case UP_FAT32:
      wprintw(stdscr,"FAT : 32\n");
      break;
    default:
      wprintw(stdscr,"Not a FAT\n");
      return 1;
  }
  wprintw(stdscr,"cluster_size %u %u\n", fh1->sectors_per_cluster, fh2->sectors_per_cluster);
  wprintw(stdscr,"reserved     %u %u\n", le16(fh1->reserved),le16(fh2->reserved));
  if(fat_sectors(fh1)!=0 || fat_sectors(fh2)!=0)
    wprintw(stdscr,"sectors      %u %u\n", fat_sectors(fh1), fat_sectors(fh2));
  if(le32(fh1->total_sect)!=0 || le32(fh2->total_sect)!=0)
    wprintw(stdscr,"total_sect   %u %u\n", (unsigned int)le32(fh1->total_sect), (unsigned int)le32(fh2->total_sect));
  if(upart_type==UP_FAT32)
  {
    wprintw(stdscr,"fat32_length %u %u\n", (unsigned int)le32(fh1->fat32_length), (unsigned int)le32(fh2->fat32_length));
    wprintw(stdscr,"root_cluster %u %u\n", (unsigned int)le32(fh1->root_cluster), (unsigned int)le32(fh2->root_cluster));
    wprintw(stdscr,"free_count   ");
    if(fat32_get_free_count((const unsigned char*)fh1,sector_size)==0xFFFFFFFF)
      wprintw(stdscr,"uninitialised ");
    else
      wprintw(stdscr,"%lu ",fat32_get_free_count((const unsigned char*)fh1,sector_size));
    if(fat32_get_free_count((const unsigned char*)fh2,sector_size)==0xFFFFFFFF)
      wprintw(stdscr,"uninitialised\n");
    else
      wprintw(stdscr,"%lu\n",fat32_get_free_count((const unsigned char*)fh2,sector_size));
    wprintw(stdscr,"next_free    ");
    if(fat32_get_next_free((const unsigned char*)fh1,sector_size)==0xFFFFFFFF)
      wprintw(stdscr,"uninitialised ");
    else
      wprintw(stdscr,"%lu ",fat32_get_next_free((const unsigned char*)fh1,sector_size));
    if(fat32_get_next_free((const unsigned char*)fh2,sector_size)==0xFFFFFFFF)
      wprintw(stdscr,"uninitialised\n");
    else
      wprintw(stdscr,"%lu\n",fat32_get_next_free((const unsigned char*)fh2,sector_size));
  } else {
    wprintw(stdscr,"fat_length   %u %u\n", le16(fh1->fat_length), le16(fh2->fat_length));
    wprintw(stdscr,"dir_entries  %u %u\n", get_dir_entries(fh1), get_dir_entries(fh2));
  }
  return 0;
}
#endif
