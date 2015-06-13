/*

    File: file_dbf.c

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

static void register_header_check_dbf(file_stat_t *file_stat);
static int header_check_dbf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_dbf= {
  .extension="dbf",
  .description="DBase 3, prone to false positive",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=0,
  .register_header_check=&register_header_check_dbf
};

static const unsigned char dbf_header[1]= {0x3};

static void register_header_check_dbf(file_stat_t *file_stat)
{
  register_header_check(0, dbf_header,sizeof(dbf_header), &header_check_dbf, file_stat);
}

static int header_check_dbf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /* 0x03 YY MM DD reserved=0 */
  if(buffer[0]==0x3 && ((buffer[1]>80 && buffer[1]<120) || buffer[1]<20) &&
      (buffer[2]>=1 && buffer[2]<=12) && (buffer[3]>=1 && buffer[3]<=31) &&
      buffer[12]==0 && buffer[13]==0 && buffer[14]==0 && buffer[15]==0 &&
      buffer[16]==0 && buffer[17]==0 && buffer[18]==0 && buffer[19]==0 &&
      buffer[20]==0 && buffer[21]==0 && buffer[22]==0 && buffer[23]==0 &&
      buffer[24]==0 && buffer[25]==0 && buffer[26]==0 && buffer[27]==0 &&
      buffer[30]==0 && buffer[31]==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_dbf.extension;
    return 1;
  }
  return 0;
}
