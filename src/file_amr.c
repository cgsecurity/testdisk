/*

    File: file_amr.c

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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "filegen.h"
#include "log.h"

static void register_header_check_amr(file_stat_t *file_stat);
static int header_check_amr(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_amr= {
  .extension="amr",
  .description="Adaptive Multi-Rate",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_amr
};

/* AMR file format is described in
 * http://wiki.forum.nokia.com/index.php?title=Special:PdfPrint&page=AMR_format
 * ftp://ftp.rfc-editor.org/in-notes/rfc3267.txt */

static const unsigned char amr_header[6]= {'#','!','A','M','R','\n'};

static void register_header_check_amr(file_stat_t *file_stat)
{
  register_header_check(0, amr_header,sizeof(amr_header), &header_check_amr, file_stat);
}

#if 0
static int data_check_amr(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 2 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size - file_recovery->file_size + buffer_size/2;
    switch(buffer[i]&0x70)
    {
      case 0x00: file_recovery->calculated_file_size+=13; break;
      case 0x10: file_recovery->calculated_file_size+=14; break;
      case 0x20: file_recovery->calculated_file_size+=16; break;
      case 0x30: file_recovery->calculated_file_size+=18; break;
      case 0x40: file_recovery->calculated_file_size+=20; break;
      case 0x50: file_recovery->calculated_file_size+=21; break;
      case 0x60: file_recovery->calculated_file_size+=27; break;
      case 0x70: file_recovery->calculated_file_size+=32; break;
    }
  }
  return 1;
}
#endif
static int header_check_amr(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(buffer,amr_header,sizeof(amr_header))==0)
  {
    reset_file_recovery(file_recovery_new);
#if 0
    file_recovery_new->calculated_file_size=6;
    file_recovery_new->data_check=&data_check_amr;
    file_recovery_new->file_check=&file_check_size;
#endif
    file_recovery_new->extension=file_hint_amr.extension;
    return 1;
  }
  return 0;
}
