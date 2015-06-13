/*

    File: file_dta.c

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

static void register_header_check_dta(file_stat_t *file_stat);
static int header_check_dta(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_dta= {
  .extension="dta",
  .description="SPSS",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=0,
  .register_header_check=&register_header_check_dta
};

static int header_check_dta(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /*
     ds_format                1    byte      0x71 or 0x72
     byteorder                1    byte      0x01 -> HILO, 0x02 -> LOHI
     filetype                 1    byte      0x01
     unused                   1    byte      ?
     nvar (number of vars)    2    int       encoded per byteorder
     nobs (number of obs)     4    int       encoded per byteorder
     data_label              81    char      dataset label, \0 terminated
     time_stamp              18    char      date/time saved, \0 terminated
     */
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_dta.extension;
  return 1;
}

static void register_header_check_dta(file_stat_t *file_stat)
{
  static const unsigned char dta_header_71le[3]= {0x71, 0x02, 0x01};
  static const unsigned char dta_header_72le[3]= {0x72, 0x02, 0x01};
  register_header_check(0, dta_header_71le,sizeof(dta_header_71le), &header_check_dta, file_stat);
  register_header_check(0, dta_header_72le,sizeof(dta_header_72le), &header_check_dta, file_stat);
}
