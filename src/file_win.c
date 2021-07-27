/*

    File: file_win.c

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_win)
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
#include "filegen.h"
#include "utfsize.h"
#include "common.h"

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_win(file_stat_t *file_stat);

const file_hint_t file_hint_win = {
  .extension = "win",
  .description = "Opera preferences",
  .max_filesize = PHOTOREC_MAX_FILE_SIZE,
  .recover = 1,
  .enable_by_default = 1,
  .register_header_check = &register_header_check_win
};

/*@
  @ requires file_recovery->data_check==&data_check_win;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ assigns  file_recovery->calculated_file_size;
  @*/
static data_check_t data_check_win(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  unsigned int i;
  unsigned int offset = 0;
  if(file_recovery->calculated_file_size == 0)
    offset = 3;
  i = UTFsize(&buffer[buffer_size / 2 + offset], buffer_size / 2 - offset);
  if(i < buffer_size / 2 - offset)
  {
    if(i >= 10)
      file_recovery->calculated_file_size = file_recovery->file_size + offset + i;
    return DC_STOP;
  }
  file_recovery->calculated_file_size = file_recovery->file_size + (buffer_size / 2);
  return DC_CONTINUE;
}

/*@
  @ requires separation: \separated(&file_hint_win, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_win(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension = file_hint_win.extension;
  file_recovery_new->data_check = &data_check_win;
  file_recovery_new->file_check = &file_check_size;
  /*@ assert valid_file_recovery(file_recovery_new); */
  return 1;
}

static void register_header_check_win(file_stat_t *file_stat)
{
  static const unsigned char win_header[31] = {
    0xef, 0xbb, 0xbf, 'O', 'p', 'e', 'r', 'a',
    ' ', 'P', 'r', 'e', 'f', 'e', 'r', 'e',
    'n', 'c', 'e', 's', ' ', 'v', 'e', 'r',
    's', 'i', 'o', 'n', ' ', '2', '.'
  };
  register_header_check(0, win_header, sizeof(win_header), &header_check_win, file_stat);
}
#endif
