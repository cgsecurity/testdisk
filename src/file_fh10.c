/*

    File: file_fh10.c

    Copyright (C) 2007 Christophe GRENIER <grenier@cgsecurity.org>
    Copyright (C) 2007 Peter Turczak <pnospamt@netconsequence.de>

  
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

static void register_header_check_fh10(file_stat_t *file_stat);
static int header_check_fh10(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_fh10= {
  .extension="fh10",
  .description="Macromedia Freehand 10",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_fh10
};

static const unsigned char fh10_header[]  = { 
  0x1c, 0x01 ,0x00, 0x00, 0x02, 0x00, 0x04, 0x1c, 0x01 , 0x14, 0x00, 0x02, 0x00, 0x14, 0x1c, 0x01,
  0x16, 0x00 ,0x02, 0x00, 0x08, 0x1c, 0x01, 0x1e, 0x00 , 0xa , 0x46, 0x72, 0x65, 0x65, 0x48, 0x61,
  0x6e, 0x64, 0x31, 0x30
};

static void register_header_check_fh10(file_stat_t *file_stat)
{
  register_header_check(0, fh10_header,sizeof(fh10_header), &header_check_fh10, file_stat);
}

static int header_check_fh10(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(buffer,fh10_header,sizeof(fh10_header))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->min_filesize=4096;
#ifdef DJGPP
    file_recovery_new->extension="fh1";
#else
    file_recovery_new->extension=file_hint_fh10.extension;
#endif
    return 1;
  }
  return 0;
}
