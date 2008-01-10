/*

    File: file_dss.c

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

static void register_header_check_dss(file_stat_t *file_stat);
static int header_check_dss(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_dss= {
  .extension="dss",
  .description="Digital Speech Standard",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .register_header_check=&register_header_check_dss
};

static const unsigned char dss_header[4]= { 0x02, 'd','s','s'};
/* 
   Digital Speech Standard (.dss) is a digital speech recording standard
   which was jointly developed and introduced by Olympus, Grundig and
   Phillips in 1994.
   0x00 char magic[4];
   0x26 char create_date[12];
   0x32 char complete_date[12];
   0x3e char length[6];
   0x31e char comments[100];
*/

static void register_header_check_dss(file_stat_t *file_stat)
{
  register_header_check(0, dss_header,sizeof(dss_header), &header_check_dss, file_stat);
}

static int header_check_dss(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(buffer,dss_header,sizeof(dss_header))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_dss.extension;
    /* File should be big enough to hold the comments */
    file_recovery_new->min_filesize=100+0x31E;
    return 1;
  }
  return 0;
}
