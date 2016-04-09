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

static void register_header_check_steuer(file_stat_t *file_stat);

const file_hint_t file_hint_steuer2014= {
  .extension="steuer2014",
  .description="Steuer 2014/2015",
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

static int header_check_steuer(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct steuer_header *h=(const struct steuer_header *)buffer;
  struct tm tm_time;
  if(h->version1!=h->version2)
    return 0;
  memset(&tm_time, 0, sizeof(struct tm));
  reset_file_recovery(file_recovery_new);
  if(le32(h->version1)>=0x13)
    file_recovery_new->extension="steuer2015";
  else
    file_recovery_new->extension=file_hint_steuer2014.extension;
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
