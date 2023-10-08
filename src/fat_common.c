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
#include "fat_common.h"

unsigned int fat_sector_size(const struct fat_boot_sector *fat_header)
{
  const unsigned int hi=fat_header->sector_size[1];
  const unsigned int lo=fat_header->sector_size[0];
  /*@ assert 0 <= hi < 1<<8; */
  /*@ assert 0 <= hi<<8 < 1<<16; */
  /*@ assert 0 <= lo < 1<<8; */
  const unsigned int res=(hi<<8)|lo;
  /*@ assert res <= 65535; */
  return res;
}

unsigned int get_dir_entries(const struct fat_boot_sector *fat_header)
{
  const unsigned int hi=fat_header->dir_entries[1];
  const unsigned int lo=fat_header->dir_entries[0];
  /*@ assert 0 <= hi < 1<<8; */
  /*@ assert 0 <= hi<<8 < 1<<16; */
  /*@ assert 0 <= lo < 1<<8; */
  const unsigned int res=(hi<<8)|lo;
  /*@ assert res <= 65535; */
  return res;
}

unsigned int fat_sectors(const struct fat_boot_sector *fat_header)
{
  const unsigned int hi=fat_header->sectors[1];
  const unsigned int lo=fat_header->sectors[0];
  /*@ assert 0 <= hi < 1<<8; */
  /*@ assert 0 <= hi<<8 < 1<<16; */
  /*@ assert 0 <= lo < 1<<8; */
  const unsigned int res=(hi<<8)|lo;
  /*@ assert res <= 65535; */
  return res;
}

unsigned int fat_get_cluster_from_entry(const struct msdos_dir_entry *entry)
{
  const unsigned int hi=le16(entry->starthi);
  const unsigned int lo=le16(entry->start);
  /*@ assert 0 <= hi < 1<<16; */
  /*@ assert 0 <= hi<<16 < 1<<32; */
  /*@ assert 0 <= lo < 1<<16; */
  return (hi<<16) | lo;
}

int is_fat_directory(const unsigned char *buffer)
{
  return(buffer[0]=='.' &&
      memcmp(buffer,         ".          ", 8+3)==0 &&
      memcmp(&buffer[0x20], "..         ", 8+3)==0 &&
      buffer[0xB]!=ATTR_EXT && (buffer[0xB]&ATTR_DIR)!=0 &&
      buffer[1*0x20+0xB]!=ATTR_EXT && (buffer[1*0x20+0xB]&ATTR_DIR)!=0);
}
