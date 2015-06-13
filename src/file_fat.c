/*

    File: file_fat.c

    Copyright (C) 2009 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "common.h"
#include "filegen.h"
#include "log.h"
#include "memmem.h"
#include "fat.h"
#include "fat_common.h"

static void register_header_check_fat(file_stat_t *file_stat);
static int header_check_fat(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_fat= {
  .extension="fat",
  .description="FAT",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=0,
  .register_header_check=&register_header_check_fat
};

static const unsigned char fat_sign[2]= { 0x55, 0xAA};

static void register_header_check_fat(file_stat_t *file_stat)
{
  register_header_check(0x1fe, fat_sign, sizeof(fat_sign), &header_check_fat, file_stat);
}

static int header_check_fat(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct fat_boot_sector *fat_header=(const struct fat_boot_sector *)buffer;
  uint64_t start_fat1,start_data,part_size;
  unsigned long int no_of_cluster,fat_length,fat_length_calc;
  if(!(le16(fat_header->marker)==0xAA55
        && (fat_header->ignored[0]==0xeb || fat_header->ignored[0]==0xe9)
        && (fat_header->fats==1 || fat_header->fats==2)))
    return 0;   /* Obviously not a FAT */
  if(!((fat_header->ignored[0]==0xeb && fat_header->ignored[2]==0x90)||fat_header->ignored[0]==0xe9))
    return 0;
  if(fat_sector_size(fat_header)==0 || fat_sector_size(fat_header)%512!=0)
    return 0;
  switch(fat_header->sectors_per_cluster)
  {
    case 1:
    case 2:
    case 4:
    case 8:
    case 16:
    case 32:
    case 64:
    case 128:
      break;
    default:
      return 0;
  }
  if(fat_header->fats!=1 && fat_header->fats!=2)
    return 0;
  if(fat_header->media!=0xF0 && fat_header->media<0xF8)
    return 0;
  fat_length=le16(fat_header->fat_length)>0?le16(fat_header->fat_length):le32(fat_header->fat32_length);
  part_size=(fat_sectors(fat_header)>0?fat_sectors(fat_header):le32(fat_header->total_sect));
  start_fat1=le16(fat_header->reserved);
  start_data=start_fat1+fat_header->fats*fat_length+(get_dir_entries(fat_header)*32+fat_sector_size(fat_header)-1)/fat_sector_size(fat_header);
  if(part_size < start_data)
    return 0;
  no_of_cluster=(part_size-start_data)/fat_header->sectors_per_cluster;
  if(no_of_cluster<4085)
  {
    /* FAT12 */
    if((get_dir_entries(fat_header)==0)||(get_dir_entries(fat_header)%16!=0))
      return 0;
    if((le16(fat_header->fat_length)>256)||(le16(fat_header->fat_length)==0))
      return 0;
    fat_length_calc=((no_of_cluster+2+fat_sector_size(fat_header)*2/3-1)*3/2/fat_sector_size(fat_header));
  }
  else if(no_of_cluster<65525)
  {
    /* FAT16 */
    if(le16(fat_header->fat_length)==0)
      return 0;
    if((get_dir_entries(fat_header)==0)||(get_dir_entries(fat_header)%16!=0))
      return 0;
    fat_length_calc=((no_of_cluster+2+fat_sector_size(fat_header)/2-1)*2/fat_sector_size(fat_header));
  }
  else
  {
    /* FAT32 */
    if(fat_sectors(fat_header)!=0)
      return 0;
    if(get_dir_entries(fat_header)!=0)
      return 0;
    if((le32(fat_header->root_cluster)<2) ||(le32(fat_header->root_cluster)>=2+no_of_cluster))
      return 0;
    fat_length_calc=((no_of_cluster+2+fat_sector_size(fat_header)/4-1)*4/fat_sector_size(fat_header));
  }
  if(fat_length<fat_length_calc)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_fat.extension;
  file_recovery_new->calculated_file_size=(uint64_t)
    (fat_sectors(fat_header)>0?fat_sectors(fat_header):le32(fat_header->total_sect)) *
    fat_sector_size(fat_header);
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}
