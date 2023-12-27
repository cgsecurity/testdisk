/*

    File: file_amr.c

    Copyright (C) 2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_amr)
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

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_amr(file_stat_t *file_stat);

const file_hint_t file_hint_amr= {
  .extension="amr",
  .description="Adaptive Multi-Rate",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_amr
};

/*@
  @ requires file_recovery->data_check==&data_check_amr;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ terminates \true;
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ assigns file_recovery->calculated_file_size;
  @*/
static data_check_t data_check_amr(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@
    @ loop assigns file_recovery->calculated_file_size;
    @ loop variant file_recovery->file_size + buffer_size/2 - (file_recovery->calculated_file_size + 4);
    @*/
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 4 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size + buffer_size/2 - file_recovery->file_size;
    /*@ assert 0 <= i < buffer_size - 4; */
#ifdef DEBUG_AMR
    log_info("data_check_amr %04x %02x %u\n", file_recovery->calculated_file_size, buffer[i], (buffer[i]>>1)&7);
#endif
    if((buffer[i]&0x83)!=0)
      return DC_STOP;
    if(buffer[i]==0 && buffer[i+1]==0 && buffer[i+2]==0 && buffer[i+3]==0)
      return DC_STOP;
    switch((buffer[i]>>3)&0x7)
    {
      case 0: file_recovery->calculated_file_size+=13; break;
      case 1: file_recovery->calculated_file_size+=14; break;
      case 2: file_recovery->calculated_file_size+=16; break;
      case 3: file_recovery->calculated_file_size+=18; break;
      case 4: file_recovery->calculated_file_size+=20; break;
      case 5: file_recovery->calculated_file_size+=21; break;
      case 6: file_recovery->calculated_file_size+=27; break;
      default: file_recovery->calculated_file_size+=32; break;
    }
  }
  return DC_CONTINUE;
}

/*@
  @ requires buffer_size >= 10;
  @ requires separation: \separated(&file_hint_amr, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_amr(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if((buffer[6]&0x83)!=0)
    return 0;
  if(buffer[6]==0 && buffer[6+1]==0 && buffer[6+2]==0 && buffer[6+3]==0)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->calculated_file_size=6;
  file_recovery_new->data_check=&data_check_amr;
  file_recovery_new->file_check=&file_check_size;
  file_recovery_new->extension=file_hint_amr.extension;
  return 1;
}

/* AMR file format is described in https://tools.ietf.org/html/rfc3267 */
static void register_header_check_amr(file_stat_t *file_stat)
{
  static const unsigned char amr_header[6]= {'#','!','A','M','R','\n'};
  register_header_check(0, amr_header,sizeof(amr_header), &header_check_amr, file_stat);
}
#endif
