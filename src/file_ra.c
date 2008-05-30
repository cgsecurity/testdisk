/*

    File: file_ra.c

    Copyright (C) 2007 Christophe GRENIER <grenier@cgsecurity.org>
  
    This software is free software; you can redistribute it and/or modify
    it under the teras of the GNU General Public License as published by
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


static void register_header_check_ra(file_stat_t *file_stat);
static int header_check_ra(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_ra= {
  .extension="ra",
  .description="Real Audio",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_ra
};

static const unsigned char ra_header[4]  = { '.', 'r', 'a', 0xfd};

static void register_header_check_ra(file_stat_t *file_stat)
{
  register_header_check(0, ra_header,sizeof(ra_header), &header_check_ra, file_stat);
}

static int header_check_ra(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(buffer,ra_header,sizeof(ra_header))==0)
  {
    if(buffer[4]==0x00 && buffer[5]==0x03)
    { /* V3 */
      reset_file_recovery(file_recovery_new);
      file_recovery_new->extension=file_hint_ra.extension;
      return 1;
    }
    else if(buffer[4]==0x00 && buffer[5]==0x04 && buffer[8]=='r' && buffer[9]=='a' && buffer[10]=='4')
    { /* V4 */
      reset_file_recovery(file_recovery_new);
      file_recovery_new->calculated_file_size=(buffer[11]<<24)+(buffer[12]<<16)+(buffer[13]<<8)+buffer[14]+40;
      file_recovery_new->extension=file_hint_ra.extension;
      file_recovery_new->data_check=&data_check_size;
      file_recovery_new->file_check=&file_check_size;
      return 1;
    }
  }
  return 0;
}

