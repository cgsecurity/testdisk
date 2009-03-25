/*

    File: file_skd.c

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
#include "filegen.h"

static void register_header_check_skd(file_stat_t *file_stat);
static int header_check_skd(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_skd= {
  .extension="skd",
  .description="AutoSketch drawing",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_skd
};

static const unsigned char skd_header[29]= {
   'A',  'u',  't',  'o',  'S',  'k',  'e',  't', 
   'c',  'h', 0x20,  'd',  'r',  'a',  'w',  'i', 
   'n',  'g', 0x20,  'd',  'a',  't',  'a',  'b', 
   'a',  's',  'e', 0x0d, 0x0a
};

static void register_header_check_skd(file_stat_t *file_stat)
{
  register_header_check(0, skd_header,sizeof(skd_header), &header_check_skd, file_stat);
}

static int header_check_skd(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(buffer,skd_header,sizeof(skd_header))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_skd.extension;
    return 1;
  }
  return 0;
}
