/*

    File: file_flac.c

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
#include "common.h"

static void register_header_check_flac(file_stat_t *file_stat);

const file_hint_t file_hint_flac= {
  .extension="flac",
  .description="FLAC audio",
  .min_header_distance=0,
  .max_filesize=100*1024*1024,
  .recover=1,
  .enable_by_default=1,
	.register_header_check=&register_header_check_flac
};

static int header_check_flac(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  reset_file_recovery(file_recovery_new);
#ifdef DJGPP
  file_recovery_new->extension="flc";
#else
  file_recovery_new->extension=file_hint_flac.extension;
#endif
  return 1;
}

static void register_header_check_flac(file_stat_t *file_stat)
{
  /* Stream marker followed by STREAMINFO Metadata block */
  static const unsigned char flac_header[5]= {'f', 'L', 'a', 'C', 0x00};
  static const unsigned char flac_header2[5]= {'f', 'L', 'a', 'C', 0x80};
  register_header_check(0, flac_header,sizeof(flac_header), &header_check_flac, file_stat);
  register_header_check(0, flac_header2,sizeof(flac_header2), &header_check_flac, file_stat);
}
