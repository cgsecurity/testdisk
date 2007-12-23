/*

    File: file_asf.c

    Copyright (C) 1998-2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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

static void register_header_check_asf(file_stat_t *file_stat);
static int header_check_asf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_asf= {
  .extension="asf",
  .description="ASF, WMA, WMV: Advanced Streaming Format used for Audio/Video",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .register_header_check=&register_header_check_asf
};

const unsigned char asf_header[4]= { 0x30,0x26,0xB2,0x75};

static void register_header_check_asf(file_stat_t *file_stat)
{
  register_header_check(0, asf_header,sizeof(asf_header), &header_check_asf, file_stat);
}

static int header_check_asf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(buffer,asf_header,sizeof(asf_header))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_asf.extension;
    /*
    file_recovery_new->calculated_file_size=(uint64_t)buffer[70]+(((uint64_t)buffer[71])<<8)+(((uint64_t)buffer[72])<<16)+(((uint64_t)buffer[73])<<24);
    log_info("asf calculated_file_size %llu\n", (long long unsigned)file_recovery_new->calculated_file_size);
    file_recovery_new->data_check=&data_check_size;
    file_recovery_new->file_check=&file_check_size;
    */
    return 1;
  }
  return 0;
}
