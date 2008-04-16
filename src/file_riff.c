/*

    File: file_riff.c

    Copyright (C) 1998-2005,2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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


static void register_header_check_riff(file_stat_t *file_stat);
static int header_check_riff(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_riff= {
  .extension="riff",
  .description="RIFF audio/video: wav, cdr, avi",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
	.register_header_check=&register_header_check_riff
};

static const unsigned char riff_header[4]= {'R','I','F','F'};

static void register_header_check_riff(file_stat_t *file_stat)
{
  register_header_check(0, riff_header,sizeof(riff_header), &header_check_riff, file_stat);
}

static int header_check_riff(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(buffer,riff_header,sizeof(riff_header))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->calculated_file_size=(uint64_t)buffer[4]+(((uint64_t)buffer[5])<<8)+(((uint64_t)buffer[6])<<16)+(((uint64_t)buffer[7])<<24)+8;
    file_recovery_new->data_check=&data_check_size;
    file_recovery_new->file_check=&file_check_size;
    if(memcmp(&buffer[8],"AVI ",4)==0)
      file_recovery_new->extension="avi";
    else if(memcmp(&buffer[8],"CDDA",4)==0)
      file_recovery_new->extension="cda";
    else if(memcmp(&buffer[8],"CDR",3)==0)
      file_recovery_new->extension="cdr";
    else if(memcmp(&buffer[8],"NUND",4)==0)
    {
      file_recovery_new->extension="cpr";
      file_recovery_new->calculated_file_size=(((uint64_t)buffer[4])<<24) + (((uint64_t)buffer[5])<<16) +
	(((uint64_t)buffer[6])<<8) + (uint64_t)buffer[7] + 12;
    }
    else if(memcmp(&buffer[8],"RMP3",4)==0 || memcmp(&buffer[8],"WAVE",4)==0)
      file_recovery_new->extension="wav";
    else
      file_recovery_new->extension="avi";
    return 1;
  }
  return 0;
}
