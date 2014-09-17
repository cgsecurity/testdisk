/*

    File: file_ico.c

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
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "common.h"
#include "filegen.h"

static void register_header_check_ico(file_stat_t *file_stat);
static int header_check_ico(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_ico= {
  .extension="ico",
  .description="Windows Icon",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_ico
};

static const unsigned char header_ico[6]= 	{0x00 , 0x00, 0x01, 0x00, 0x01, 0x00};

static void register_header_check_ico(file_stat_t *file_stat)
{
  register_header_check(0, header_ico, sizeof(header_ico), &header_check_ico, file_stat);
}

/*
 * http://en.wikipedia.org/wiki/ICO_(icon_image_file_format)
 */

struct ico_header
{
  uint16_t	reserved;
  uint16_t	type;
  uint16_t	count;
} __attribute__ ((__packed__));

struct ico_directory
{
  uint8_t	width;
  uint8_t	heigth;
  uint8_t	color_count;
  uint8_t	reserved;
  uint16_t	color_planes;
  uint16_t	bits_per_pixel;
  uint32_t	bitmap_size;
  uint32_t	bitmap_offset;
} __attribute__ ((__packed__));

static int header_check_ico(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct ico_header *ico=(const struct ico_header*)buffer;
  const struct ico_directory *ico_dir=(const struct ico_directory*)(ico+1);
  /* Recover square icon with a single image */
  if(le16(ico->reserved)==0 && le16(ico->type)==1 && le16(ico->count)==1 &&
      (ico_dir->reserved==0 || ico_dir->reserved==255) &&
      (ico_dir->color_planes==0 || ico_dir->color_planes==1) &&
      ico_dir->width==ico_dir->heigth &&
      ico_dir->width>=16 &&
      (le16(ico_dir->bits_per_pixel)==1 ||
       le16(ico_dir->bits_per_pixel)==4 ||
       le16(ico_dir->bits_per_pixel)==8 ||
       le16(ico_dir->bits_per_pixel)==16 ||
       le16(ico_dir->bits_per_pixel)==32) &&
       le32(ico_dir->bitmap_offset) >= sizeof(struct ico_header)+le16(ico->count)*sizeof(struct ico_directory) &&
       le32(ico_dir->bitmap_size) > 0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_ico.extension;
    file_recovery_new->calculated_file_size=(uint64_t)le32(ico_dir->bitmap_size) + le32(ico_dir->bitmap_offset);
    file_recovery_new->data_check=&data_check_size;
    file_recovery_new->file_check=&file_check_size;
    return 1;
  }
  return 0;
}
