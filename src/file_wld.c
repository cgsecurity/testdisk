/*

    File: file_wld.c

    Copyright (C) 2016 Christophe GRENIER <grenier@cgsecurity.org>

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_wld)
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

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_wld(file_stat_t *file_stat);

const file_hint_t file_hint_wld = {
  .extension = "wld",
  .description = "Terraria world",
  .max_filesize = PHOTOREC_MAX_FILE_SIZE,
  .recover = 1,
  .enable_by_default = 1,
  .register_header_check = &register_header_check_wld
};

/* See http://ludwig.schafer.free.fr for WLD file format */

/*@
  @ requires file_recovery->file_rename==&file_rename_wld;
  @ requires valid_file_rename_param(file_recovery);
  @ ensures  valid_file_rename_result(file_recovery);
  @*/
static void file_rename_wld(file_recovery_t *file_recovery)
{
  uint32_t offset;
  unsigned char buffer[256];
  FILE *file;
  if((file = fopen(file_recovery->filename, "rb")) == NULL)
    return;
  if(fseek(file, 0x1a, SEEK_SET) == -1 || fread(&offset, 4, 1, file) != 1 || fseek(file, le32(offset), SEEK_SET) == -1 || fread(&buffer, 256, 1, file) != 1)
  {
    fclose(file);
    return;
  }
  fclose(file);
  file_rename(file_recovery, &buffer[1], buffer[0], 0, NULL, 1);
}

/*@
  @ requires buffer_size >= 0xc;
  @ requires separation: \separated(&file_hint_wld, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_wld(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(buffer[0xB] <= 0 || buffer[0xB] > 3)
    return 0;
  reset_file_recovery(file_recovery_new);
  switch(buffer[0xb])
  {
  case 0x01:
    file_recovery_new->extension = "map";
    break;
  case 0x02:
    file_recovery_new->extension = file_hint_wld.extension;
    file_recovery_new->file_rename = &file_rename_wld;
    break;
  case 0x03:
    file_recovery_new->extension = "plr";
    break;
  }
  return 1;
}

static void register_header_check_wld(file_stat_t *file_stat)
{
  static const unsigned char wld_header[10] = {
    0x00, 0x00, 0x00,
    'r', 'e', 'l', 'o', 'g', 'i', 'c'
  };
  register_header_check(1, wld_header, sizeof(wld_header), &header_check_wld, file_stat);
}
#endif
