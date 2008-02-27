/*

    File: file_aif.c

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

static void register_header_check_aif(file_stat_t *file_stat);
static int header_check_aif(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_aif= {
  .extension="aif",
  .description="Audio Interchange File Format",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_aif
};

static const unsigned char aif_header[4]= {'F','O','R','M'};

static void register_header_check_aif(file_stat_t *file_stat)
{
  register_header_check(0, aif_header,sizeof(aif_header), &header_check_aif, file_stat);
}

static int header_check_aif(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(buffer,aif_header,sizeof(aif_header))==0 && 
    buffer[8]=='A' && buffer[9]=='I' && buffer[10]=='F' && (buffer[11]=='F' || buffer[11]=='C'))
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_aif.extension;
    file_recovery_new->calculated_file_size=((uint64_t)buffer[7]+(((uint64_t)buffer[6])<<8)+(((uint64_t)buffer[5])<<16)+(((uint64_t)buffer[4])<<24))+8;
    file_recovery_new->data_check=&data_check_size;
    file_recovery_new->file_check=&file_check_size;
    return 1;
  }
  return 0;
}
