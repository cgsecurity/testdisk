/*

    File: file_bz2.c

    Copyright (C) 1998-2005,2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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

static void register_header_check_bz2(file_stat_t *file_stat);
static int header_check_bz2(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_bz2= {
  .extension="bz2",
  .description="bzip2 compressed data",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_bz2
};

static const unsigned char bz2_header[3]= {'B','Z','h'};

static void register_header_check_bz2(file_stat_t *file_stat)
{
  register_header_check(0, bz2_header,sizeof(bz2_header), &header_check_bz2, file_stat);
}

static int header_check_bz2(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(buffer[0]=='B' && buffer[1]=='Z' && buffer[2]=='h' && buffer[3]>='0' && buffer[4]=='1' && buffer[5]=='A' && buffer[6]=='Y' && buffer[7]=='&' && buffer[8]=='S' && buffer[9]=='Y')
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_bz2.extension;
    return 1;
  }
  return 0;
}
