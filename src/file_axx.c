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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_axx)
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

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_axx(file_stat_t *file_stat);

const file_hint_t file_hint_axx= {
  .extension="axx",
  .description="AxCrypt",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_axx
};

struct SHeader
{
  uint32_t aoLength;
  uint8_t   oType;
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires fr->file_check == &file_check_axx;
  @ requires valid_file_check_param(fr);
  @ ensures  valid_file_check_result(fr);
  @ assigns *fr->handle, errno, fr->file_size;
  @ assigns Frama_C_entropy_source;
  @*/
static void file_check_axx(file_recovery_t *fr)
{
  uint64_t	offset=0x10;
  /*@
    @ loop assigns *fr->handle, errno, fr->file_size;
    @ loop assigns offset, Frama_C_entropy_source;
    @ loop variant 0x8000000000000000 - offset;
    @ */
  while(offset < 0x8000000000000000)
  {
    char buffer[sizeof(struct SHeader)];
    const struct SHeader *header=(const struct SHeader *)&buffer;
    unsigned int len;
    if(my_fseek(fr->handle, offset, SEEK_SET) < 0)
      return ;
    if (fread(&buffer, sizeof(buffer), 1, fr->handle)!=1)
      return ;
#if defined(__FRAMAC__)
    Frama_C_make_unknown(&buffer, sizeof(buffer));
#endif
    len=le32(header->aoLength);
#ifdef DEBUG_AAX
    log_info("axx 0x%llx 0x%x 0x%x/%d\n", (long long int)offset, len, header->oType, header->oType);
#endif
    if(len<5)
      return ;
    offset+=len;
    if(offset >= 0x8000000000000000)
      break;
    if(header->oType==63) // eData
    {
      char buf[sizeof(uint64_t)];
      const uint64_t *fsize_ptr=(const uint64_t *)&buf;
      uint64_t fsize;
      if(len!=13)
	return ;
      if (fread(&buf, sizeof(buf), 1, fr->handle)!=1)
	return ;
#if defined(__FRAMAC__)
      Frama_C_make_unknown(&buf, sizeof(buf));
#endif
      fsize=le64(*fsize_ptr);
      if(fsize >= 0x8000000000000000)
	break;
      offset+=fsize;
      fr->file_size=(fr->file_size < offset ? 0 : offset);
      return ;
    }
  }
  fr->file_size=0;
}

/*@
  @ requires buffer_size > 0x25+sizeof(struct SHeader);
  @ requires separation: \separated(&file_hint_axx, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_axx(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct SHeader *header=(const struct SHeader *)&buffer[0x10+0x15];
  if(le32(header->aoLength) < 5)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_axx.extension;
  file_recovery_new->file_check=&file_check_axx;
  file_recovery_new->min_filesize=(uint64_t)0x25+le32(header->aoLength);
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
#endif
