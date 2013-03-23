/*

    File: file_ds2.c

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
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#include <stdio.h>
#include <ctype.h>
#include "types.h"
#include "filegen.h"

static void register_header_check_ds2(file_stat_t *file_stat);

const file_hint_t file_hint_ds2= {
  .extension="ds2",
  .description="Digital Speech Standard v2",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_ds2
};

/* 
   Digital Speech Standard (.ds2) is a digital speech recording format
   that is an evolution from dss standard which was jointly developed
   and introduced by Olympus, Grundig and Phillips in 1994.
   0x00 char magic[4];
   0x26 char create_date[12];
   0x32 char complete_date[12];

   Filesize is always a multiple of 512
*/

static int header_check_ds2(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  struct tm tm_time;
  const unsigned char *date_asc=&buffer[0x26];
  unsigned int i;
  for(i=0; i<24; i++)
    if(!isdigit(date_asc[i]))
      return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_ds2.extension;
  file_recovery_new->min_filesize=0x200;
  memset(&tm_time, 0, sizeof(tm_time));
  tm_time.tm_sec=(date_asc[10]-'0')*10+(date_asc[11]-'0');	/* seconds 0-59 */
  tm_time.tm_min=(date_asc[8]-'0')*10+(date_asc[9]-'0');      /* minutes 0-59 */
  tm_time.tm_hour=(date_asc[6]-'0')*10+(date_asc[7]-'0');     /* hours   0-23*/
  tm_time.tm_mday=(date_asc[4]-'0')*10+(date_asc[5]-'0');	/* day of the month 1-31 */
  tm_time.tm_mon=(date_asc[2]-'0')*10+(date_asc[3]-'0')-1;	/* month 1-12 */
  tm_time.tm_year=(date_asc[0]-'0')*10+(date_asc[1]-'0');        	/* year */
  if(tm_time.tm_year<80)
    tm_time.tm_year+=100;	/* year 2000 - 2079 */
  tm_time.tm_isdst = -1;	/* unknown daylight saving time */
  file_recovery_new->time=mktime(&tm_time);
  return 1;
}

static void register_header_check_ds2(file_stat_t *file_stat)
{
  static const unsigned char ds2_header[4]= { 0x03, 'd','s','2'};
  register_header_check(0, ds2_header,sizeof(ds2_header), &header_check_ds2, file_stat);
}
