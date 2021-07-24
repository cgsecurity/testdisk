/*

    File: file_sdsk.c

    Copyright (C) 2019 Christophe GRENIER <grenier@cgsecurity.org>

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_sdsk)
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
static void register_header_check_sdsk(file_stat_t *file_stat);

const file_hint_t file_hint_sdsk= {
  .extension="sdsk",
  .description="SafeHouse virtual disk",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_sdsk
};

/*@
  @ requires separation: \separated(&file_hint_sdsk, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_sdsk(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_sdsk.extension;
  file_recovery_new->min_filesize=0x1000;
  return 1;
}

static void register_header_check_sdsk(file_stat_t *file_stat)
{
  static const unsigned char sdsk_header[0x48]=  {
    'W' , 'A' , 'R' , 'N' , 'I' , 'N' , 'G' , 0x3a,
    ' ' , 'T' , 'h' , 'i' , 's' , ' ' , 'f' , 'i' ,
    'l' , 'e' , ' ' , 'i' , 's' , ' ' , 'a' , ' ' ,
    'S' , 'a' , 'f' , 'e' , 'H' , 'o' , 'u' , 's' ,
    'e' , ' ' , 'v' , 'i' , 'r' , 't' , 'u' , 'a' ,
    'l' , ' ' , 'd' , 'i' , 's' , 'k' , ' ' , 'v' ,
    'o' , 'l' , 'u' , 'm' , 'e' , '.' , 0x0d, 0x0a,
    'h' , 'e' , 'a' , 'd' , 'e' , 'r' , ' ' , 'v' ,
    'e' , 'r' , 's' , 'i' , 'o' , 'n' , 0x3a, ' ' ,
  };
  register_header_check(0, sdsk_header, sizeof(sdsk_header), &header_check_sdsk, file_stat);
}
#endif
