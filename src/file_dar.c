/*

    File: file_dar.c

    Copyright (C) 2011 Christophe GRENIER <grenier@cgsecurity.org>
  
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

static void register_header_check_dar(file_stat_t *file_stat);

const file_hint_t file_hint_dar= {
  .extension="dar",
  .description="dar archive",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_dar
};

static const unsigned char dar_header[4]=  {
  0, 0, 0, 0x7b
};

static int header_check_dar(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /* http://darbinding.sourceforge.net/specs/dar3.html */
  if(memcmp(buffer, dar_header, sizeof(dar_header))==0 && 
    (buffer[0xe]=='N' || buffer[0xe]=='T') &&
    (buffer[0xf]=='N' || buffer[0xf]=='S'))
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_dar.extension;
    return 1;
  }
  return 0;
}

static void register_header_check_dar(file_stat_t *file_stat)
{
  register_header_check(0, dar_header, sizeof(dar_header), &header_check_dar, file_stat);
}
