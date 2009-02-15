/*

    File: file_ldf.c

    Copyright (C) 2009 Christophe GRENIER <grenier@cgsecurity.org>
  
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


static void register_header_check_ldf(file_stat_t *file_stat);
static int header_check_ldf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_ldf= {
  .extension="ldf",
  .description="Microsoft SQL Server Log Data File",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_ldf
};

static const unsigned char ldf_header[4]= { 0x01, 0x0f, 0x00, 0x00 };

static void register_header_check_ldf(file_stat_t *file_stat)
{
  register_header_check(0, ldf_header,sizeof(ldf_header), &header_check_ldf, file_stat);
}

static int header_check_ldf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(buffer[0x00]==0x01 && buffer[0x01]==0x0f && buffer[0x02]==0x00 && buffer[0x03]==0x00 &&
      buffer[0x08]==0x00 && buffer[0x09]==0x00 && buffer[0x0a]==0x00 && buffer[0x0b]==0x00 &&
      buffer[0x0c]==0x00 && buffer[0x0d]==0x00 && buffer[0x0e]==0x00 && buffer[0x0f]==0x00 &&
      buffer[0x10]==0x00 && buffer[0x11]==0x00 && buffer[0x12]==0x00 && buffer[0x13]==0x00 &&
      buffer[0x14]==0x00 && buffer[0x15]==0x00 && buffer[0x16]==0x02 && buffer[0x17]==0x00 &&
      buffer[0x18]==0x63 && buffer[0x19]==0x00 && buffer[0x1A]==0x00 && buffer[0x1B]==0x00)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_ldf.extension;
    return 1;
  }
  return 0;
}
