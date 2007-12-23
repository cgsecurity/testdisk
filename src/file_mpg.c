/*

    File: file_mpg.c

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


static void register_header_check_mpg(file_stat_t *file_stat);
static int header_check_mpg(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_mpg= {
  .extension="mpg",
  .description="Moving Picture Experts Group video",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .register_header_check=&register_header_check_mpg
};

static const unsigned char mpg_header[3]= {0x00, 0x00, 0x01};

static void register_header_check_mpg(file_stat_t *file_stat)
{
  register_header_check(0, mpg_header,sizeof(mpg_header), &header_check_mpg, file_stat);
}

static int header_check_mpg(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(file_recovery!=NULL && file_recovery->file_stat!=NULL && file_recovery->file_stat->file_hint==&file_hint_mpg)
    return 0;
  /* ISO/IEC 11172/13818-1 SYSTEM MULTIPLEXED PACKETIZED ELEMENTARY	*
   * STREAM AND HEADERS							*
   * 0x000001BA pack header start code			 		*
   * 0x000001BB system header start code				*
   * 0x000001BE padding block start code				*
   * 0x000001BD private 1 block start code				*
   * 0x000001BF private 2 block start code				*
   * 									*
   * ISO/IEC 11172-2/13818-2 (MPEG-1/2 video) ELEMENTARY VIDEO HEADER	*
   * 0x000001B3	video sequence start code				*
   * 0x000001B2	video user meta data start code				*
   * 									*
   * ISO/IEC 14496-2 (MPEG-4 video) ELEMENTARY VIDEO HEADER		*
   * 0x000001B0	visual object sequence start code			*
   * 0x000001B2 user meta data start code				*
   * 0x000001B5 visual object start code				*/

  if(buffer[0]==0x00 && buffer[1]==0x00 && buffer[2]==0x01 &&
      (buffer[3]==0xB0 || buffer[3]==0xB3 || buffer[3]==0xB5 || buffer[3]==0xBA || buffer[3]==0xBB))
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_mpg.extension;
    return 1;
  }
  return 0;
}


