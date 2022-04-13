/*

    File: file_steuer2014.c

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_steuer2014)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include <time.h>
#include "types.h"
#include "filegen.h"
#include "common.h"

#if defined(DISABLED_FOR_FRAMAC)
#undef HAVE_STRPTIME
#endif

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_steuer(file_stat_t *file_stat);
static const char *extension_steuer2014="steuer2014";
static const char *extension_steuer2015="steuer2015";
static const char *extension_steuer2016="steuer2016";
static const char *extension_steuer2017="steuer2017";
static const char *extension_steuer2018="steuer2018";
static const char *extension_steuer2019="steuer2019";
static const char *extension_steuer2020="steuer2020";

const file_hint_t file_hint_steuer2014= {
  .extension="steuer2014",
  .description="Steuer 2014/...",
  .max_filesize=100*1024*1024,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_steuer
};

struct steuer_header
{
  uint8_t 	magic[8];
  uint32_t 	version1;
  uint32_t 	version2;
  char 		date_string[0x18];
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires buffer_size >= sizeof(struct steuer_header);
  @ requires separation: \separated(&file_hint_steuer2014, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_steuer(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct steuer_header *h=(const struct steuer_header *)buffer;
  struct tm tm_time;
  if(h->version1!=h->version2)
    return 0;
  reset_file_recovery(file_recovery_new);
  switch(le32(h->version1))
  {
    case 0x00 ... 0x12:
      file_recovery_new->extension=extension_steuer2014;
      break;
    case 0x13:
      file_recovery_new->extension=extension_steuer2015;
      break;
    case 0x14:
      file_recovery_new->extension=extension_steuer2016;
      break;
    case 0x15:
      file_recovery_new->extension=extension_steuer2017;
      break;
    case 0x16:
      file_recovery_new->extension=extension_steuer2018;
      break;
    case 0x17:
      file_recovery_new->extension=extension_steuer2019;
      break;
    default:
      file_recovery_new->extension=extension_steuer2020;
      break;
  }
#ifdef HAVE_STRPTIME
  strptime(h->date_string, "%b %d %Y %H:%M:%S", &tm_time);
  file_recovery_new->time=mktime(&tm_time);
#endif
  return 1;
}

static void register_header_check_steuer(file_stat_t *file_stat)
{
  static const unsigned char steuer_header[8]=  {
    'R' , 0x26, 'S' , 0x1a, 0x11, 0x01, 0x01, 0x00
  };
  register_header_check(0, steuer_header, sizeof(steuer_header), &header_check_steuer, file_stat);
}
#endif
