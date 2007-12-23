/*

    File: file_pcx.c

    Copyright (C) 2006-2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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


static void register_header_check_pcx(file_stat_t *file_stat);
static int header_check_pcx(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_pcx= {
  .extension="pcx",
  .description="PCX bitmap image",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .register_header_check=&register_header_check_pcx
};

static const unsigned char pcx_header[1]= {0x0a};

static void register_header_check_pcx(file_stat_t *file_stat)
{
  register_header_check(0, pcx_header,sizeof(pcx_header), &header_check_pcx, file_stat);
}

static int header_check_pcx(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /*
  0x0a 0x00  PCX ver. 2.5 image data
  0x0a 0x02  PCX ver. 2.8 image data, with palette
  0x0a 0x03  PCX ver. 2.8 image data, without palette
  0x0a 0x04  PCX for Windows image data
  0x0a 0x05  PCX ver. 3.0 image data
  buffer[2]==0 uncompressed
  buffer[2]==1 RLE compressed
  buffer[3]	Number of bits of color used for each pixel
  buffer[64]  Reserved
  */
  if(buffer[0]==0x0a && (buffer[1]<=5 && buffer[1]!=1) && buffer[2]<=1 &&
    (buffer[3]==1 || buffer[3]==4 || buffer[3]==8 || buffer[3]==24) &&
    buffer[64]==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_pcx.extension;
    return 1;
  }
  return 0;
}

