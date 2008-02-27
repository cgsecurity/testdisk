/*

    File: file_skp.c

    Copyright (C) 2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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

static void register_header_check_skp(file_stat_t *file_stat);
static int header_check_skp(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_skp= {
  .extension="skp",
  .description="SketchUp",
  .min_header_distance=0,
  .max_filesize=10*1024*1024,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_skp
};

static const unsigned char skp_header[32]= {
  0xff, 0xfe, 0xff, 0x0e, 'S', 0x00, 'k', 0x00, 'e', 0x00, 't', 0x00, 'c', 0x00, 'h', 0x00,
  'U',  0x00,  'p', 0x00, ' ', 0x00, 'M', 0x00, 'o', 0x00, 'd', 0x00, 'e', 0x00, 'l', 0x00 };

static void register_header_check_skp(file_stat_t *file_stat)
{
  register_header_check(0, skp_header,sizeof(skp_header), &header_check_skp, file_stat);
}

static int header_check_skp(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(buffer,skp_header, sizeof(skp_header))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_skp.extension;
    return 1;
  }
  return 0;
}
