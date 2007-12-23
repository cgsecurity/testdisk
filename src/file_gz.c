/*

    File: file_gz.c

    Copyright (C) 1998-2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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

static void register_header_check_gz(file_stat_t *file_stat);
static int header_check_gz(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_gz= {
  .extension="gz",
  .description="gzip compressed data",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .register_header_check=&register_header_check_gz
};

static const unsigned char gz_header[3]= {0x1F, 0x8B, 0x08};

static void register_header_check_gz(file_stat_t *file_stat)
{
  register_header_check(0, gz_header,sizeof(gz_header), &header_check_gz, file_stat);
}

static int header_check_gz(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /* gzip file format:
   * a 10-byte header, containing a magic number, a version number and a timestamp
   * optional extra headers, such as the original file name,
   * a body, containing a deflate-compressed payload
   * a CRC-32 checksum
   * the length (32 bits) of the original uncompressed data
   */
  /* gzip, deflate */
  if(buffer[0]==0x1F && buffer[1]==0x8B && buffer[2]==0x08 && (buffer[3]&0xe0)==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_gz.extension;
    file_recovery_new->min_filesize=22;
    return 1;
  }
  return 0;
}
