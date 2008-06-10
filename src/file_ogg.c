/*

    File: file_ogg.c

    Copyright (C) 1998-2005,2007-2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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

static void register_header_check_ogg(file_stat_t *file_stat);
static int header_check_ogg(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);
static int data_check_ogg(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery);

const file_hint_t file_hint_ogg= {
  .extension="ogg",
  .description="OGG audio",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_ogg
};

static const unsigned char ogg_header[4]= {'O','g','g','S'};

static void register_header_check_ogg(file_stat_t *file_stat)
{
  register_header_check(0, ogg_header,sizeof(ogg_header), &header_check_ogg, file_stat);
}

static int header_check_ogg(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(file_recovery!=NULL && file_recovery->file_stat!=NULL && file_recovery->file_stat->file_hint==&file_hint_ogg)
    return 0;
  if(memcmp(buffer,ogg_header,sizeof(ogg_header))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->calculated_file_size=0;
    file_recovery_new->data_check=&data_check_ogg;
    file_recovery_new->file_check=&file_check_size;
    file_recovery_new->extension=file_hint_ogg.extension;
    return 1;
  }
  return 0;
}

/* http://www.ietf.org/rfc/rfc3533.txt */
static int data_check_ogg(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 27 +255 < file_recovery->file_size + buffer_size/2)
  {
    unsigned int i=file_recovery->calculated_file_size - file_recovery->file_size + buffer_size/2;
    if(memcmp(&buffer[i],ogg_header,sizeof(ogg_header))==0)
    {
      unsigned int number_page_segments;
      unsigned int header_size;
      unsigned int page_size;
      unsigned int j;
      number_page_segments=buffer[i+26];
      header_size = number_page_segments + 27;
      page_size=header_size;
      for(j=0;j<number_page_segments;j++)
        page_size+=buffer[i+27+j];
      if(page_size<27)
      {
        return 2;
      }
      /* By definition, page_size<=27+255+255*255=65307 */
      file_recovery->calculated_file_size+=page_size;
      /*
      log_debug("+0x%x=0x%x\n",page_size,file_recovery->calculated_file_size);
      */
    }
    else
    {
      return 2;
    }
  }
  return 1;
}

