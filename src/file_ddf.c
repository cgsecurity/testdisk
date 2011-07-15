/*

    File: file_ddf.c

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
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#include "types.h"
#include "filegen.h"

static void register_header_check_ddf(file_stat_t *file_stat);

const file_hint_t file_hint_ddf= {
  .extension="ddf",
  .description="Didson Data File",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_ddf
};

static const unsigned char ddf3_header[4]=  {
  'D' , 'D' , 'F' , 0x03
};
static const unsigned char ddf4_header[4]=  {
  'D' , 'D' , 'F' , 0x04
};

static int header_check_ddf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(buffer, ddf3_header, sizeof(ddf3_header))==0 ||
      memcmp(buffer, ddf4_header, sizeof(ddf4_header))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_ddf.extension;
    if(buffer[0x43]=='-' && buffer[0x46]=='-' && buffer[0x49]=='_')
    {
      struct tm tm_time;
      memset(&tm_time, 0, sizeof(tm_time));
      tm_time.tm_sec=(buffer[0x4e]-'0')*10+(buffer[0x4f]-'0');      /* seconds 0-59 */
      tm_time.tm_min=(buffer[0x4c]-'0')*10+(buffer[0x4d]-'0');      /* minutes 0-59 */
      tm_time.tm_hour=(buffer[0x4a]-'0')*10+(buffer[0x4b]-'0');      /* hours   0-23*/
      tm_time.tm_mday=(buffer[0x47]-'0')*10+(buffer[0x48]-'0');	/* day of the month 1-31 */
      tm_time.tm_mon=(buffer[0x44]-'0')*10+(buffer[0x45]-'0')-1;	/* month 0-11 */
      tm_time.tm_year=(buffer[0x3f]-'0')*1000+(buffer[0x40]-'0')*100+
	(buffer[0x41]-'0')*10+(buffer[0x42]-'0')-1900;        	/* year */
      tm_time.tm_isdst = -1;		/* unknown daylight saving time */
      file_recovery_new->time=mktime(&tm_time);
    }
    return 1;
  }
  return 0;
}

static void register_header_check_ddf(file_stat_t *file_stat)
{
  register_header_check(0, ddf3_header, sizeof(ddf3_header), &header_check_ddf, file_stat);
  register_header_check(0, ddf4_header, sizeof(ddf4_header), &header_check_ddf, file_stat);
}
