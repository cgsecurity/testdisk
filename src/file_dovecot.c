/*

    File: file_dovecot.c

    Copyright (C) 2021 Christophe GRENIER <grenier@cgsecurity.org>

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dovecot)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "filegen.h"

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_dovecot(file_stat_t *file_stat);

const file_hint_t file_hint_dovecot= {
  .extension="dovecot",
  .description="dovecot encrypted files",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=0,
  .register_header_check=&register_header_check_dovecot
};

/*@
  @ requires file_recovery->data_check==&data_check_dovecot2;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ terminates \true;
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ ensures \result == DC_CONTINUE || \result == DC_ERROR;
  @ assigns file_recovery->data_check;
  @*/
static data_check_t data_check_dovecot2(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  if(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 2 <= file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size + buffer_size/2 - file_recovery->file_size;
    /*@ assert 0 <= i <= buffer_size - 2; */
    if(buffer[i] == 0 && buffer[i+1] == 0)
    {
      return DC_ERROR;
    }
    file_recovery->data_check=NULL;
  }
  return DC_CONTINUE;
}
/*@
  @ requires file_recovery->data_check==&data_check_dovecot;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ terminates \true;
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ ensures \result == DC_CONTINUE || \result == DC_ERROR;
  @ assigns file_recovery->calculated_file_size, file_recovery->data_check;
  @*/
static data_check_t data_check_dovecot(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  unsigned int i;
  /*@
    @ loop assigns i;
    @ loop variant buffer_size - i;
    @*/
  for(i=buffer_size/2;
      i<buffer_size && file_recovery->calculated_file_size+i <= 0x14000;
      i++)
  {
    if(buffer[i]!='\0')
      return DC_ERROR;
  }
  if(file_recovery->calculated_file_size+buffer_size/2 < 0x14000)
  {
    file_recovery->calculated_file_size+=buffer_size/2;
    return DC_CONTINUE;
  }
  file_recovery->calculated_file_size=0x14000;
  file_recovery->data_check=data_check_dovecot2;
  return data_check_dovecot2(buffer, buffer_size, file_recovery);
}

/*@
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @*/
static int header_check_dovecot(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(file_recovery->data_check==&data_check_dovecot)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_dovecot.extension;
  file_recovery_new->data_check=&data_check_dovecot;
  file_recovery_new->min_filesize=0x14000;
  return 1;
}

static void register_header_check_dovecot(file_stat_t *file_stat)
{
  static const unsigned char dovecot_header[0x30]=  {
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0
  };
  register_header_check(0, dovecot_header, sizeof(dovecot_header), &header_check_dovecot, file_stat);
}
#endif
