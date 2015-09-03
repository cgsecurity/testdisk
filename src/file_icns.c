/*

    File: file_icns.c

    Copyright (C) 2015 Christophe GRENIER <grenier@cgsecurity.org>

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
#include "filegen.h"
#include "common.h"

static void register_header_check_icns(file_stat_t *file_stat);

const file_hint_t file_hint_icns= {
  .extension="icns",
  .description="Apple Icon Image",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_icns
};

struct icns_header
{
  uint32_t magic;
  uint32_t size;
};

struct icon_data
{
  char type[4];
  uint32_t size;
  uint8_t  data[0];
};

static int check_icon_type(const char *type)
{
  /* https://en.wikipedia.org/wiki/Apple_Icon_Image_format */
  if(memcmp(type, "ICON", 4)==0 ||
      memcmp(type, "ICN#", 4)==0 ||
      memcmp(type, "icm#", 4)==0 ||
      memcmp(type, "icm4", 4)==0 ||
      memcmp(type, "icm8", 4)==0 ||
      memcmp(type, "ics#", 4)==0 ||
      memcmp(type, "ics4", 4)==0 ||
      memcmp(type, "ics8", 4)==0 ||
      memcmp(type, "is32", 4)==0 ||
      memcmp(type, "s8mk", 4)==0 ||
      memcmp(type, "icl4", 4)==0 ||
      memcmp(type, "icl8", 4)==0 ||
      memcmp(type, "il32", 4)==0 ||
      memcmp(type, "l8mk", 4)==0 ||
      memcmp(type, "ich#", 4)==0 ||
      memcmp(type, "ich4", 4)==0 ||
      memcmp(type, "ich8", 4)==0 ||
      memcmp(type, "ih32", 4)==0 ||
      memcmp(type, "h8mk", 4)==0 ||
      memcmp(type, "it32", 4)==0 ||
      memcmp(type, "t8mk", 4)==0 ||
      memcmp(type, "icp4", 4)==0 ||
      memcmp(type, "icp5", 4)==0 ||
      memcmp(type, "icp6", 4)==0 ||
      memcmp(type, "ic07", 4)==0 ||
      memcmp(type, "ic08", 4)==0 ||
      memcmp(type, "ic09", 4)==0 ||
      memcmp(type, "ic10", 4)==0 ||
      memcmp(type, "ic11", 4)==0 ||
      memcmp(type, "ic12", 4)==0 ||
      memcmp(type, "ic13", 4)==0 ||
      memcmp(type, "ic14", 4)==0 ||
      memcmp(type, "TOC ", 4)==0 ||
      memcmp(type, "icnV", 4)==0)
      return 1;
  return 0;
}

static int header_check_icns(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct icns_header *hdr=(const struct icns_header *)buffer;
  const struct icon_data *icon=(const struct icon_data *)&buffer[8];
  if(be32(hdr->size) < sizeof(struct icns_header))
    return 0;
  if(be32(icon->size) < sizeof(struct icon_data))
    return 0;
  if(8 + be32(icon->size) > be32(hdr->size))
    return 0;
  if(!check_icon_type(icon->type))
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_icns.extension;
  file_recovery_new->calculated_file_size=be32(hdr->size);
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static void register_header_check_icns(file_stat_t *file_stat)
{
  register_header_check(0, "icns", 4, &header_check_icns, file_stat);
}
