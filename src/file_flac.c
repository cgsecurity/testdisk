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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_flac)
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
static void register_header_check_flac(file_stat_t *file_stat);

const file_hint_t file_hint_flac= {
  .extension="flac",
  .description="FLAC audio",
  .max_filesize=(uint64_t)1500*1024*1024,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_flac
};

/* https://xiph.org/flac/format.html */

/*@
  @ requires file_recovery->data_check==&data_check_flac_metadata;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ terminates \true;
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ assigns  file_recovery->calculated_file_size, file_recovery->data_check;
  @*/
static data_check_t data_check_flac_metadata(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@
    @ loop assigns file_recovery->calculated_file_size, file_recovery->data_check;
    @ loop variant file_recovery->file_size + buffer_size/2 - (file_recovery->calculated_file_size + 4);
    @*/
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 4 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size + buffer_size/2 - file_recovery->file_size;
    /*@ assert 0 <= i < buffer_size - 4; */
    const uint32_t *p32=(const uint32_t *)&buffer[i];
    const uint32_t size=be32(*p32)&0x00ffffff;
#ifdef DEBUG_FLAC
    log_info("data_check_flac_metadata calculated_file_size=0x%llx: 0x%02x\n",
	(long long unsigned)file_recovery->calculated_file_size, buffer[i]);
#endif
    if((buffer[i]&0x7f)==0x7f)
	return DC_ERROR;
    file_recovery->calculated_file_size+=(uint64_t)4+size;
    if((buffer[i]&0x80)==0x80)
    {
      file_recovery->data_check=NULL;
      return DC_CONTINUE;
    }
  }
  return DC_CONTINUE;
}

/*@
  @ requires buffer_size >= 8;
  @ requires separation: \separated(&file_hint_flac, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
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
  if(file_recovery_new->blocksize >= 4)
  {
    file_recovery_new->calculated_file_size=4;
    file_recovery_new->data_check=&data_check_flac_metadata;
  }
  return 1;
}

static void register_header_check_flac(file_stat_t *file_stat)
{
  /* Stream marker followed by STREAMINFO Metadata block */
  static const unsigned char flac_header[5]= {'f', 'L', 'a', 'C', 0x00};
  static const unsigned char flac_header2[5]= {'f', 'L', 'a', 'C', 0x80};
  register_header_check(0, flac_header,sizeof(flac_header), &header_check_flac, file_stat);
#ifndef DISABLED_FOR_FRAMAC
  register_header_check(0, flac_header2,sizeof(flac_header2), &header_check_flac, file_stat);
#endif
}
#endif
