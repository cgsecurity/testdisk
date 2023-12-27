/*

    File: file_icc.c

    Copyright (C) 2009 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_icc)
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
static void register_header_check_icc(file_stat_t *file_stat);

const file_hint_t file_hint_icc= {
  .extension="icc",
  .description="Color profiles",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_icc
};

/*@
  @ requires buffer_size >= 128;
  @ requires separation: \separated(&file_hint_icc, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_icc(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const uint64_t file_size=(((uint64_t)buffer[0])<<24) +
    (((uint64_t)buffer[1])<<16) + (((uint64_t)buffer[2])<<8) + (uint64_t)buffer[3];
  unsigned int i;
  if(file_size<128 || buffer[10]!=0 || buffer[11]!=0)
    return 0;
  /*@
    @ loop assigns i;
    @ loop variant 128 - i;
    @*/
  for(i=100; i<128; i++)
    if(buffer[i]!=0)
      return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_icc.extension;
  file_recovery_new->calculated_file_size=file_size;
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

/* http://www.npes.org/ICC/ICC1-V41_ForPublicReview.pdf */

static void register_header_check_icc(file_stat_t *file_stat)
{
  static const unsigned char icc_header[4]= { 'a', 'c', 's', 'p' };
  register_header_check(36, icc_header,sizeof(icc_header), &header_check_icc, file_stat);
}
#endif
