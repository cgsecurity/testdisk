/*

    File: file_au.c

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
#include "common.h"
#include "filegen.h"

static void register_header_check_au(file_stat_t *file_stat);
static int header_check_au(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only,  const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_au= {
  .extension="au",
  .description="Sun/NeXT audio data",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_au
};

static const unsigned char au_header[4]= {'.','s','n','d'};

static void register_header_check_au(file_stat_t *file_stat)
{
  register_header_check(0, au_header,sizeof(au_header), &header_check_au, file_stat);
}

/* http://en.wikipedia.org/wiki/Au_file_format */
struct header_au_s
{
  uint32_t magic;
  uint32_t offset;
  uint32_t size;
  uint32_t encoding;
  uint32_t sample_rate;
  uint32_t channels;
} __attribute__ ((__packed__));

static int header_check_au(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct header_au_s *au=(const struct header_au_s *)buffer;
  if(memcmp(buffer,au_header,sizeof(au_header))==0 &&
    (const uint32_t)be32(au->offset) >= sizeof(struct header_au_s) &&
    be32(au->encoding)>0 && be32(au->encoding)<=27 &&
    be32(au->channels)>0 && be32(au->channels)<=256)
  {
    if(be32(au->size)!=0xffffffff)
    {
      if(be32(au->offset)+be32(au->size) < 111)
	return 0;
      reset_file_recovery(file_recovery_new);
      file_recovery_new->min_filesize=111;
      file_recovery_new->extension=file_hint_au.extension;
      file_recovery_new->calculated_file_size=be32(au->offset)+be32(au->size);
      file_recovery_new->data_check=&data_check_size;
      file_recovery_new->file_check=&file_check_size;
      return 1;
    }
    reset_file_recovery(file_recovery_new);
    file_recovery_new->min_filesize=111;
    file_recovery_new->extension=file_hint_au.extension;
    return 1;
  }
  return 0;
}
