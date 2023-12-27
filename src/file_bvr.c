/*

    File: file_bvr.c

    Copyright (C) 2018 Christophe GRENIER <grenier@cgsecurity.org>

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_bvr)
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
static void register_header_check_bvr(file_stat_t *file_stat);

const file_hint_t file_hint_bvr= {
  .extension="bvr",
  .description="Blue Iris DVR",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_bvr
};

/*@
  @ requires file_recovery->data_check==&data_check_bvr;
  @ requires \separated(buffer, file_recovery);
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ assigns file_recovery->calculated_file_size;
  @*/
static data_check_t data_check_bvr(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@
    @ loop assigns file_recovery->calculated_file_size;
    @ loop variant file_recovery->file_size + buffer_size/2 - (file_recovery->calculated_file_size + 16);
    @*/
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 16 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size + buffer_size/2 - file_recovery->file_size;
    /*@ assert 0 <= i < buffer_size - 16; */
    const uint32_t *valp=(const uint32_t *)&buffer[i+12];
    if(memcmp(&buffer[i], "BLUE", 4) != 0)
      return DC_STOP;
    file_recovery->calculated_file_size+=(uint64_t)0x20 + *valp;
    if(*valp == 0)
      return DC_STOP;
  }
  return DC_CONTINUE;
}

/*@
  @ requires separation: \separated(&file_hint_bvr, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @*/
static int header_check_bvr(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(file_recovery->file_stat!=NULL &&
    file_recovery->file_check!=NULL &&
    file_recovery->file_stat->file_hint==&file_hint_bvr)
  {
    /*@ assert \valid_function(file_recovery->file_check); */
    header_ignored(file_recovery_new);
    return 0;
  }
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_bvr.extension;
  file_recovery_new->data_check=&data_check_bvr;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static void register_header_check_bvr(file_stat_t *file_stat)
{
  static const unsigned char bvrheader[8]= { 'B', 'L', 'U', 'E', 0x20, 0x00, 0x10, 0x00};
  register_header_check(0, bvrheader, sizeof(bvrheader), &header_check_bvr, file_stat);
}
#endif
