/*

    File: file_axp.c

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

static void register_header_check_axp(file_stat_t *file_stat);

const file_hint_t file_hint_axp= {
  .extension="axp",
  .description="Pinnacle Studio",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_axp
};

static data_check_t data_check_axp(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  const unsigned char axp_footer[34]= {
    '<', 0, '/', 0, 'V', 0, 'F', 0,
    'N', 0, 'G', 0, 'D', 0, 'o', 0,
    'c', 0, 'u', 0, 'm', 0, 'e', 0,
    'n', 0, 't', 0, '>', 0, 0x0d, 0,
    0x0a, 0
  };
  unsigned int j;
  for(j=(buffer_size/2>sizeof(axp_footer)?buffer_size/2-sizeof(axp_footer):0);
      j+sizeof(axp_footer) < buffer_size;
      j++)
  {
    if(buffer[j]=='<' && memcmp((const char *)&buffer[j], axp_footer, sizeof(axp_footer))==0)
    {
      file_recovery->calculated_file_size+=j-buffer_size/2+sizeof(axp_footer);
      return DC_STOP;
    }
  }
  file_recovery->calculated_file_size=file_recovery->file_size+(buffer_size/2);
  return DC_CONTINUE;
}

static int header_check_axp(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_axp.extension;
  file_recovery_new->data_check=&data_check_axp;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static void register_header_check_axp(file_stat_t *file_stat)
{
  static const unsigned char axp_header[0x70]=  {
    0xff, 0xfe, 0x3c, 0x00, 0x3f, 0x00, 'x' , 0x00,
    'm' , 0x00, 'l' , 0x00, ' ' , 0x00, 'v' , 0x00,
    'e' , 0x00, 'r' , 0x00, 's' , 0x00, 'i' , 0x00,
    'o' , 0x00, 'n' , 0x00, 0x3d, 0x00, 0x22, 0x00,
    '1' , 0x00, '.' , 0x00, '0' , 0x00, 0x22, 0x00,
    ' ' , 0x00, 'e' , 0x00, 'n' , 0x00, 'c' , 0x00,
    'o' , 0x00, 'd' , 0x00, 'i' , 0x00, 'n' , 0x00,
    'g' , 0x00, 0x3d, 0x00, 0x22, 0x00, 'U' , 0x00,
    'T' , 0x00, 'F' , 0x00, 0x2d, 0x00, '1' , 0x00,
    '6' , 0x00, 0x22, 0x00, 0x3f, 0x00, 0x3e, 0x00,
    0x0d, 0x00, 0x0a, 0x00, 0x3c, 0x00, 'V' , 0x00,
    'F' , 0x00, 'N' , 0x00, 'G' , 0x00, 'D' , 0x00,
    'o' , 0x00, 'c' , 0x00, 'u' , 0x00, 'm' , 0x00,
    'e' , 0x00, 'n' , 0x00, 't' , 0x00, 0x3e, 0x00,
  };
  register_header_check(0, axp_header, sizeof(axp_header), &header_check_axp, file_stat);
}
