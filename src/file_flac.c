/*

    File: file_flac.c

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
#include "common.h"
#include "log.h"

static void register_header_check_flac(file_stat_t *file_stat);

const file_hint_t file_hint_flac= {
  .extension="flac",
  .description="FLAC audio",
  .min_header_distance=0,
  .max_filesize=(uint64_t)1500*1024*1024,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_flac
};

/* https://xiph.org/flac/format.html */

#if 0
static data_check_t data_check_flac_frame(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  return DC_CONTINUE;
}

static data_check_t data_check_flac_metadata(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 4 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size - file_recovery->file_size + buffer_size/2;
    const uint32_t *p32=(const uint32_t *)&buffer[i];
    const uint32_t size=be32(*p32)&0x00ffffff;
#ifdef DEBUG_FLAC
    log_info("data_check_flac_metadata calculated_file_size=0x%llx: 0x%02x\n",
	(long long unsigned)file_recovery->calculated_file_size, buffer[i]);
#endif
    if((buffer[i]&0x7f)==0x7f)
	return DC_ERROR;
    file_recovery->calculated_file_size+=4+size;
    if((buffer[i]&0x80)==0x80)
    {
      file_recovery->data_check=&data_check_flac_frame;
      log_info("data_check_flac_frame    calculated_file_size=0x%llx\n",
	  (long long unsigned)file_recovery->calculated_file_size);
      return data_check_flac_frame(buffer, buffer_size, file_recovery);
    }
  }
  return DC_CONTINUE;
}
#endif

static int header_check_flac(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const uint32_t *p32=(const uint32_t *)&buffer[4];
  const uint32_t size=be32(*p32)&0x00ffffff;
  reset_file_recovery(file_recovery_new);
#ifdef DJGPP
  file_recovery_new->extension="flc";
#else
  file_recovery_new->extension=file_hint_flac.extension;
#endif
  file_recovery_new->min_filesize=4+size;
#if 0
  file_recovery_new->calculated_file_size=4;
  file_recovery_new->data_check=&data_check_flac_metadata;
#endif
  return 1;
}

static void register_header_check_flac(file_stat_t *file_stat)
{
  /* Stream marker followed by STREAMINFO Metadata block */
  static const unsigned char flac_header[5]= {'f', 'L', 'a', 'C', 0x00};
  static const unsigned char flac_header2[5]= {'f', 'L', 'a', 'C', 0x80};
  register_header_check(0, flac_header,sizeof(flac_header), &header_check_flac, file_stat);
  register_header_check(0, flac_header2,sizeof(flac_header2), &header_check_flac, file_stat);
}
