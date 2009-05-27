/*

    File: file_njx.c

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


static void register_header_check_njx(file_stat_t *file_stat);
static int header_check_njx(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);
static void file_check_njx(file_recovery_t *file_recovery);

const file_hint_t file_hint_njx= {
  .extension="njx",
  .description="NJStar Document",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_njx
};

static const unsigned char njx_header[4]= {0x04, 'N', 'j', 0x0f};

static void register_header_check_njx(file_stat_t *file_stat)
{
  register_header_check(0, njx_header,sizeof(njx_header), &header_check_njx, file_stat);
}

static int header_check_njx(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(buffer[0]==0x04 && buffer[1]=='N' && buffer[2]=='j' && buffer[3]==0x0f &&
      buffer[6]=='N' && buffer[7]=='J' && buffer[8]=='S' && buffer[9]=='t' && buffer[10]=='a' && buffer[11]=='r')
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->file_check=&file_check_njx;
    file_recovery_new->extension=file_hint_njx.extension;
    return 1;
  }
  return 0;
}

static void file_check_njx(file_recovery_t *file_recovery)
{
  const unsigned char njx_footer[4]= {'N', 'J', '*', 0x04};
  file_search_footer(file_recovery, njx_footer, sizeof(njx_footer), 0);
}
