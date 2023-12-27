/*

    File: file_ds2.c

    Copyright (C) 2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ds2)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#include <stdio.h>
#include <ctype.h>
#include "types.h"
#include "filegen.h"

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_ds2(file_stat_t *file_stat);

const file_hint_t file_hint_ds2= {
  .extension="ds2",
  .description="Digital Speech Standard v2",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_ds2
};

/* 
   Digital Speech Standard (.ds2) is a digital speech recording format
   that is an evolution from dss standard which was jointly developed
   and introduced by Olympus, Grundig and Phillips in 1994.
   0x00 char magic[4];
   0x26 char create_date[12];
   0x32 char complete_date[12];

   Filesize is always a multiple of 512
*/

/*@
  @ requires buffer_size >= 0x32;
  @ requires separation: \separated(&file_hint_ds2, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_ds2(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const unsigned char *date_asc=&buffer[0x26];
  unsigned int i;
  /*@
    @ loop assigns i;
    @ loop variant 24 - i;
    @ */
  for(i=0; i<24; i++)
    if(!isdigit(date_asc[i]))
      return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_ds2.extension;
  file_recovery_new->min_filesize=0x200;
  file_recovery_new->time=get_time_from_YYMMDDHHMMSS(date_asc);
  return 1;
}

static void register_header_check_ds2(file_stat_t *file_stat)
{
  static const unsigned char ds2_header[4]= { 0x03, 'd','s','2'};
  register_header_check(0, ds2_header,sizeof(ds2_header), &header_check_ds2, file_stat);
}
#endif
