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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ico)
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
#include "log.h"

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_ico(file_stat_t *file_stat);

const file_hint_t file_hint_ico= {
  .extension="ico",
  .description="Windows Icon",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_ico
};

static const unsigned char header_ico1[6]=	{0x00 , 0x00, 0x01, 0x00, 0x01, 0x00};
static const unsigned char header_ico2[6]=	{0x00 , 0x00, 0x01, 0x00, 0x02, 0x00};
static const unsigned char header_ico3[6]=	{0x00 , 0x00, 0x01, 0x00, 0x03, 0x00};
static const unsigned char header_ico4[6]=	{0x00 , 0x00, 0x01, 0x00, 0x04, 0x00};
static const unsigned char header_ico5[6]=	{0x00 , 0x00, 0x01, 0x00, 0x05, 0x00};
static const unsigned char header_ico6[6]=	{0x00 , 0x00, 0x01, 0x00, 0x06, 0x00};
static const unsigned char header_ico7[6]=	{0x00 , 0x00, 0x01, 0x00, 0x07, 0x00};
static const unsigned char header_ico8[6]=	{0x00 , 0x00, 0x01, 0x00, 0x08, 0x00};
static const unsigned char header_ico9[6]=	{0x00 , 0x00, 0x01, 0x00, 0x09, 0x00};

/*
 * http://en.wikipedia.org/wiki/ICO_(icon_image_file_format)
 */

struct ico_header
{
  uint16_t	reserved;
  uint16_t	type;
  uint16_t	count;
} __attribute__ ((gcc_struct, __packed__));

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
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires buffer_size >= sizeof(struct ico_header);
  @ requires separation: \separated(&file_hint_ico, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_ico(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct ico_header *ico=(const struct ico_header*)buffer;
  const struct ico_directory *ico_dir;
  unsigned int i;
  uint64_t fs=0;
#ifdef DEBUG_ICO
  log_info("ICO: reserved=%u type=%u count=%u\n", le16(ico->reserved), le16(ico->type), le16(ico->count));
#endif
  if(le16(ico->reserved)!=0 || le16(ico->type)!=1 || le16(ico->count)==0)
    return 0;
  /*@
    @ loop assigns ico_dir, i, fs;
    @ loop variant le16(ico->count) - i;
    @*/
  for(i=0, ico_dir=(const struct ico_directory*)(ico+1);
      (const unsigned char *)(ico_dir+1) <= buffer+buffer_size && i<le16(ico->count);
      i++, ico_dir++)
  {
#ifdef DEBUG_ICO
    log_info("ICO%u: reserved=%u color_planes=%u width=%u heigth=%u bps=%u offset=%u size=%u\n",
	i, ico_dir->reserved, le16(ico_dir->color_planes), ico_dir->width, ico_dir->heigth, le16(ico_dir->bits_per_pixel),
	le32(ico_dir->bitmap_offset), le32(ico_dir->bitmap_size));
#endif
    if(ico_dir->reserved!=0 && ico_dir->reserved!=255)
      return 0;
    if(le16(ico_dir->color_planes)>1)
      return 0;
    if(ico_dir->width!=ico_dir->heigth)
      return 0; /* Reject non square icon */
    switch(ico_dir->width)
    {
      case 16:
      case 24:
      case 32:
      case 48:
      case 64:
      case 128:
      case 0:	/* 256 */
	break;
      default:
	return 0;
    }
    switch(le16(ico_dir->bits_per_pixel))
    {
      case 0:
      case 1:
      case 4:
      case 8:
      case 16:
      case 24:
      case 32:
	break;
      default:
	return 0;
    }
    if(le32(ico_dir->bitmap_size)==0)
      return 0;
    if(le32(ico_dir->bitmap_offset) < sizeof(struct ico_header)+le16(ico->count)*sizeof(struct ico_directory))
      return 0;
    if(fs < (uint64_t)le32(ico_dir->bitmap_size) + le32(ico_dir->bitmap_offset))
      fs=(uint64_t)le32(ico_dir->bitmap_size) + le32(ico_dir->bitmap_offset);
  }
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_ico.extension;
  file_recovery_new->calculated_file_size=fs;
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static void register_header_check_ico(file_stat_t *file_stat)
{
  register_header_check(0, header_ico1, sizeof(header_ico1), &header_check_ico, file_stat);
#ifndef DISABLED_FOR_FRAMAC
  register_header_check(0, header_ico2, sizeof(header_ico2), &header_check_ico, file_stat);
  register_header_check(0, header_ico3, sizeof(header_ico3), &header_check_ico, file_stat);
  register_header_check(0, header_ico4, sizeof(header_ico4), &header_check_ico, file_stat);
  register_header_check(0, header_ico5, sizeof(header_ico5), &header_check_ico, file_stat);
  register_header_check(0, header_ico6, sizeof(header_ico6), &header_check_ico, file_stat);
  register_header_check(0, header_ico7, sizeof(header_ico7), &header_check_ico, file_stat);
  register_header_check(0, header_ico8, sizeof(header_ico8), &header_check_ico, file_stat);
  register_header_check(0, header_ico9, sizeof(header_ico9), &header_check_ico, file_stat);
#endif
}
#endif
