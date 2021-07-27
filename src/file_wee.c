/*

    File: file_wee.c

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_wee)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "filegen.h"

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_wee(file_stat_t *file_stat);

const file_hint_t file_hint_wee = {
  .extension = "wee",
  .description = "weecast",
  .max_filesize = PHOTOREC_MAX_FILE_SIZE,
  .recover = 1,
  .enable_by_default = 1,
  .register_header_check = &register_header_check_wee
};

/*@
  @ requires file_recovery->file_check == &file_check_wee;
  @ requires valid_file_check_param(file_recovery);
  @ ensures  valid_file_check_result(file_recovery);
  @ assigns *file_recovery->handle, errno, file_recovery->file_size;
  @ assigns Frama_C_entropy_source;
  @*/
static void file_check_wee(file_recovery_t *file_recovery)
{
  const unsigned char wee_footer[7] = {
    'W', 'E', 'E', 'X', 0x21, 0x01, 0x00
  };
  file_search_footer(file_recovery, wee_footer, sizeof(wee_footer), 17);
}

/*@
  @ requires buffer_size >= 0x1b + 0xa;
  @ requires separation: \separated(&file_hint_wee, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_wee(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(buffer[0x1a] != 0xa || memcmp(&buffer[0x1b], "onMetaData", 0x0a) != 0)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension = file_hint_wee.extension;
  file_recovery_new->file_check = &file_check_wee;
  return 1;
}

static void register_header_check_wee(file_stat_t *file_stat)
{
  static const unsigned char wee_header[7] = {
    'W', 'E', 'E', 'X', 0x21, 0x01, 0x00
  };
  register_header_check(0, wee_header, sizeof(wee_header), &header_check_wee, file_stat);
}
#endif
