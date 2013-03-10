/*

    File: file_nsf.c

    Copyright (C) 2010 Christophe GRENIER <grenier@cgsecurity.org>
  
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

static void register_header_check_nsf(file_stat_t *file_stat);

const file_hint_t file_hint_nsf= {
  .extension="nsf",
  .description="Lotus Notes",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_nsf
};

static int header_check_nsf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /* I hope it's a valid check */
  if(buffer[0x10]!=0x25 || buffer[0x11]!=0x85)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_nsf.extension;
  return 1;
}

static void register_header_check_nsf(file_stat_t *file_stat)
{
  static const unsigned char nsf_header[6]=  {
    0x1a, 0x00, 0x00, 0x04, 0x00, 0x00
  };
  register_header_check(0, nsf_header, sizeof(nsf_header), &header_check_nsf, file_stat);
}

