/*

    File: file_stl.c

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_stl)
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

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_stl(file_stat_t *file_stat);

const file_hint_t file_hint_stl= {
  .extension="stl",
  .description="Stereolithography CAD (Binary format)",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_stl
};

/*@
  @ requires buffer_size >= 84;
  @ requires separation: \separated(&file_hint_stl, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_stl(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /* STL Binary format
   * http://www.ennex.com/~fabbers/StL.asp	*/
  unsigned int i;
  const uint32_t *fs_ptr=(const uint32_t *)&buffer[80];
  const uint64_t filesize=80+4+(uint64_t)le32(*fs_ptr)*50;
  /*@ assert filesize < PHOTOREC_MAX_FILE_SIZE; */
  /*@
    @ loop assigns i;
    @ loop variant 80 - i;
    @*/
  for(i=0; i<80 && buffer[i]!='\0'; i++);
  if(i>64)
    return 0;
  /*@
    @ loop assigns i;
    @ loop variant 80 - i;
    @*/
  for(i++; i<80 && buffer[i]==' '; i++);
  if(i!=80)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_stl.extension;
  file_recovery_new->calculated_file_size=filesize;
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static void register_header_check_stl(file_stat_t *file_stat)
{
  /* Note: STL Ascii format is recovered in file_txt.c */
  register_header_check(0, "solid ", 6, &header_check_stl, file_stat);
}
#endif
