/*

    File: file_axx.c

    Copyright (C) 2012 Christophe GRENIER <grenier@cgsecurity.org>
  
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

static void register_header_check_axx(file_stat_t *file_stat);

const file_hint_t file_hint_axx= {
  .extension="axx",
  .description="AxCrypt",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_axx
};

struct SHeader
{
  uint32_t aoLength;
  uint8_t   oType;
} __attribute__ ((__packed__));

static void file_check_axx(file_recovery_t *fr)
{
  uint64_t	offset=0x10;
  while(1)
  {
    struct SHeader header;
    unsigned int len;
#ifdef HAVE_FSEEKO
    if(fseeko(fr->handle, offset, SEEK_SET) < 0)
#else
    if(fseek(fr->handle, offset, SEEK_SET) < 0)
#endif
      return ;
    if (fread(&header, sizeof(header), 1, fr->handle)!=1)
      return ;
    len=le32(header.aoLength);
#ifdef DEBUG_AAX
    log_info("axx 0x%llx 0x%x 0x%x/%d\n", (long long int)offset, len, header.oType, header.oType);
#endif
    if(len<5)
      return ;
    offset+=len;
    if(header.oType==63) // eData
    {
      uint64_t fsize;
      if(len!=13)
	return ;
      if (fread(&fsize, sizeof(fsize), 1, fr->handle)!=1)
	return ;
      fsize=le64(fsize);
      offset+=fsize;
      fr->file_size=(fr->file_size < offset ? 0 : offset);
      return ;
    }
  }
}

static int header_check_axx(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct SHeader *header=(const struct SHeader *)&buffer[0x10+0x15];
  if(le32(header->aoLength) < 5)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_axx.extension;
  file_recovery_new->file_check=&file_check_axx;
  file_recovery_new->min_filesize=0x25+le32(header->aoLength);
  return 1;
}

static void register_header_check_axx(file_stat_t *file_stat)
{
  // guidAxCryptFileIdInverse (32 bytes) + length (4) + ePreamble=2
  static const unsigned char axx_header[0x15]=  {
    0xc0, 0xb9, 0x07, 0x2e, 0x4f, 0x93, 0xf1, 0x46,
    0xa0, 0x15, 0x79, 0x2c, 0xa1, 0xd9, 0xe8, 0x21,
    0x15, 0x00, 0x00, 0x00, 0x02
  };
  register_header_check(0, axx_header, sizeof(axx_header), &header_check_axx, file_stat);
}
