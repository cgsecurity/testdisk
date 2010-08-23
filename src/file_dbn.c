/*

    File: file_dbn.c

    Copyright (C) 2010 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include "memmem.h"

static void register_header_check_dbn(file_stat_t *file_stat);
static int header_check_dbn(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_dbn= {
  .extension="dbn",
  .description="DriftBox",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_dbn
};

static const unsigned char dbn_header[16]=  {
  'F' , 'i' , 'l' , 'e' , ' ' , 'c' , 'r' , 'e' ,
  'a' , 't' , 'e' , 'd' , ' ' , 'o' , 'n' , ' ' 
};

static void register_header_check_dbn(file_stat_t *file_stat)
{
  register_header_check(0, dbn_header, sizeof(dbn_header), &header_check_dbn, file_stat);
}

static int header_check_dbn(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(buffer, dbn_header, sizeof(dbn_header))==0 &&
    td_memmem(buffer, 512, "[HEADER]", 8)!=NULL)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_dbn.extension;
    return 1;
  }
  return 0;
}
