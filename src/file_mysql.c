/*

    File: file_mysql.c

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


static void register_header_check_mysql(file_stat_t *file_stat);
static int header_check_mysql(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_mysql= {
  .extension="MYI",
  .description="MySQL (myi/frm)",
  .min_header_distance=0,
  .max_filesize=0,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_mysql
};

static const unsigned char mysql_header[4]= {0xfe, 0xfe, 0x07, 0x01};
static const unsigned char mysql_header_def[2]= {0xfe, 0x01};

static void register_header_check_mysql(file_stat_t *file_stat)
{
  register_header_check(0, mysql_header,sizeof(mysql_header), &header_check_mysql, file_stat);
  register_header_check(0, mysql_header_def,sizeof(mysql_header_def), &header_check_mysql, file_stat);
}

static int header_check_mysql(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /* MySQL MYISAM compressed data file Version 1 */
  if(buffer[0]==0xfe && buffer[1]==0xfe && buffer[2]==0x07 && buffer[3]==0x01)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension="MYI";
    return 1;
  }
  /* MySQL table definition file Version 7 up to 10 */
  if(buffer[0]==0xfe && buffer[1]==0x01 && (buffer[2]>=0x07 && buffer[2]<=0x0A) && buffer[3]==0x09 && buffer[5]==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension="frm";
    return 1;
  }
  return 0;
}
