/*

    File: file_evt.c

    Copyright (C) 2007-2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_evt)
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
#include "log.h"

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_evt(file_stat_t *file_stat);

const file_hint_t file_hint_evt= {
  .extension="evt",
  .description="Windows Event Log",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_evt
};

struct evt_chunk {
  uint32_t size;
  uint32_t id;
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires file_recovery->data_check==&data_check_evt;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ terminates \true;
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ assigns file_recovery->calculated_file_size;
  @*/
static data_check_t data_check_evt(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@
    @ loop assigns file_recovery->calculated_file_size;
    @ loop variant file_recovery->file_size + buffer_size/2 - (file_recovery->calculated_file_size + 8);
    @*/
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 8 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size + buffer_size/2 - file_recovery->file_size;
    /*@ assert 0 <= i < buffer_size - 8; */
    const struct evt_chunk *chunk=(const struct evt_chunk *)&buffer[i];
    if((buffer[i+4]=='L' && buffer[i+5]=='f' && buffer[i+6]=='L' && buffer[i+7]=='e') ||
	(buffer[i+4]==0x11 && buffer[i+5]==0x11 && buffer[i+6]==0x11 && buffer[i+7]==0x11) ||
	(buffer[i+4]==0x22 && buffer[i+5]==0x22 && buffer[i+6]==0x22 && buffer[i+7]==0x22) ||
	(buffer[i+4]==0x33 && buffer[i+5]==0x33 && buffer[i+6]==0x33 && buffer[i+7]==0x33) ||
	(buffer[i+4]==0x44 && buffer[i+5]==0x44 && buffer[i+6]==0x44 && buffer[i+7]==0x44))
    {
      const unsigned int length=le32(chunk->size);
      if(length<8)
      {
	return DC_STOP;
      }
      file_recovery->calculated_file_size+=length;
    }
    else
    {
      return DC_STOP;
    }
  }
  /*
  log_trace("data_check_evt record_offset=0x%x\n\n",record_offset);
  */
  return DC_CONTINUE;
}

/*@
  @ requires buffer_size >= 8;
  @ requires separation: \separated(&file_hint_evt, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_evt(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct evt_chunk *chunk=(const struct evt_chunk *)buffer;
  const struct evt_chunk *chunk2;
  if(le32(chunk->size) != 0x30)
    return 0;
  chunk2=(const struct evt_chunk *)&buffer[le32(chunk->size)];
  if(le32(chunk2->size) < 8)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_evt.extension;
  if(file_recovery_new->blocksize >= 8)
  {
    file_recovery_new->calculated_file_size=le32(chunk->size);
    file_recovery_new->data_check=&data_check_evt;
    file_recovery_new->file_check=&file_check_size;
  }
  return 1;
}

static void register_header_check_evt(file_stat_t *file_stat)
{
  static const unsigned char evt_header[8]= {0x30, 0x00, 0x00, 0x00, 'L', 'f', 'L', 'e'};
  register_header_check(0, evt_header,sizeof(evt_header), &header_check_evt, file_stat);
}
#endif
