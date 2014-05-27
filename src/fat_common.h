/*

    File: fat_common.h

    Copyright (C) 2013 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifndef _FAT_COMMON_H
#define _FAT_COMMON_H
#ifdef __cplusplus
extern "C" {
#endif
unsigned int fat_get_cluster_from_entry(const struct msdos_dir_entry *entry);
int is_fat_directory(const unsigned char *buffer);
unsigned int get_dir_entries(const struct fat_boot_sector *fat_header);
unsigned int fat_sector_size(const struct fat_boot_sector *fat_header);
unsigned int fat_sectors(const struct fat_boot_sector *fat_header);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
