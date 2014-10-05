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
static data_check_t data_check_ogg(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery);

const file_hint_t file_hint_ogg= {
  .extension="ogg",
  .description="OGG audio",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_ogg
};

/* header=OggS, version=0 */
static const unsigned char ogg_header[5]= {'O','g','g','S', 0x00};
static const unsigned char sign_theora[7]= {0x80, 't', 'h', 'e', 'o', 'r', 'a'};

static int header_check_ogg(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /* http://en.wikipedia.org/wiki/Ogg#File_format */
  /* Return if not Beginning Of Stream and already saving the file */
  if((buffer[5]&0x02)!=0x02 &&
      file_recovery->file_stat!=NULL &&
      file_recovery->file_stat->file_hint==&file_hint_ogg &&
      (file_recovery->blocksize < 27+255 ||
       file_recovery->calculated_file_size == file_recovery->file_size))
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->calculated_file_size=0;
  if(file_recovery_new->blocksize > 27+255)
  {
    file_recovery_new->data_check=&data_check_ogg;
    file_recovery_new->file_check=&file_check_size;
  }
  /* Ogg data, Theora video */
  if(memcmp(&buffer[28], sign_theora, sizeof(sign_theora))==0)
    file_recovery_new->extension="ogm";
  else if(memcmp(&buffer[0x78], sign_theora, sizeof(sign_theora))==0)
    file_recovery_new->extension="ogv";
  else
    file_recovery_new->extension=file_hint_ogg.extension;
  return 1;
}

/* http://www.ietf.org/rfc/rfc3533.txt */
static data_check_t data_check_ogg(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 27 +255 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size - file_recovery->file_size + buffer_size/2;
    if(memcmp(&buffer[i],ogg_header,sizeof(ogg_header))==0)
    {
      const unsigned int number_page_segments=buffer[i+26];
      const unsigned int header_size = number_page_segments + 27;
      unsigned int page_size;
      unsigned int j;
      page_size=header_size;
      for(j=0;j<number_page_segments;j++)
        page_size+=buffer[i+27+j];
      if(page_size<27)
      {
        return DC_STOP;
      }
      /* By definition, page_size<=27+255+255*255=65307 */
      file_recovery->calculated_file_size+=page_size;
      /*
      log_debug("+0x%x=0x%x\n",page_size,file_recovery->calculated_file_size);
      */
    }
    else
    {
      return DC_STOP;
    }
  }
  return DC_CONTINUE;
}

static void register_header_check_ogg(file_stat_t *file_stat)
{
  register_header_check(0, ogg_header,sizeof(ogg_header), &header_check_ogg, file_stat);
}
