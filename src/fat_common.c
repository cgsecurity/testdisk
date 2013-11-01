/*

    File: fat_common.c

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

#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include "types.h"
#include "common.h"
#include "fat.h"
#include "fat_common.h"

unsigned int fat_sector_size(const struct fat_boot_sector *fat_header)
{ return (fat_header->sector_size[1]<<8)+fat_header->sector_size[0]; }

unsigned int get_dir_entries(const struct fat_boot_sector *fat_header)
{ return (fat_header->dir_entries[1]<<8)+fat_header->dir_entries[0]; }

unsigned int fat_sectors(const struct fat_boot_sector *fat_header)
{ return (fat_header->sectors[1]<<8)+fat_header->sectors[0]; }

unsigned int fat_get_cluster_from_entry(const struct msdos_dir_entry *entry)
{
  return (((unsigned long int)le16(entry->starthi))<<16) | le16(entry->start);
}

int is_fat_directory(const unsigned char *buffer)
{
  return(buffer[0]=='.' &&
      memcmp(buffer,         ".          ", 8+3)==0 &&
      memcmp(&buffer[0x20], "..         ", 8+3)==0 &&
      buffer[0xB]!=ATTR_EXT && (buffer[0xB]&ATTR_DIR)!=0 &&
      buffer[1*0x20+0xB]!=ATTR_EXT && (buffer[1*0x20+0xB]&ATTR_DIR)!=0);
}
