/*

    File: file_pct.c

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

static void register_header_check_pct(file_stat_t *file_stat);
static int header_check_pct(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);
static void file_check_pct(file_recovery_t *file_recovery);

const file_hint_t file_hint_pct= {
  .extension="pct",
  .description="Macintosh Picture",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_pct
};

static const unsigned char pct_header[6]= { 0x00, 0x11, 0x02, 0xff, 0x0c, 0x00};
/* We are searching for PICTv2 files
   http://www.fileformat.info/format/macpict/
   SHORT    Version operator (0x0011)
   SHORT    Version number (0x02ff)
   SHORT    Header opcode for Version 2 (0C00)
 */
static void register_header_check_pct(file_stat_t *file_stat)
{
  register_header_check(0x20a, pct_header,sizeof(pct_header), &header_check_pct, file_stat);
}

static int header_check_pct(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(&buffer[0x20a],pct_header,sizeof(pct_header))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_pct.extension;
    /* We only have the low 16bits of the filesystem */
    file_recovery_new->min_filesize=0x200+(buffer[0x200]<<8)+buffer[0x201];
    file_recovery_new->file_check=&file_check_pct;
    return 1;
  }
  return 0;
}

static void file_check_pct(file_recovery_t *file_recovery)
{
  if(file_recovery->file_size<0x210 ||
      file_recovery->file_size<file_recovery->min_filesize)
  {
    file_recovery->file_size=0;
    return ;
  }
  file_recovery->file_size-=((file_recovery->file_size-file_recovery->min_filesize)&0xFFFF);
}

