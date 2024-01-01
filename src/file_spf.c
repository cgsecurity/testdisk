/*

    File: file_spf.c

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_spf)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include "types.h"
#include "filegen.h"
#include "common.h"

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_spf(file_stat_t *file_stat);

const file_hint_t file_hint_spf= {
  .extension="spf",
  .description="ShadowProtect",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_spf
};

enum { READ_SIZE=32*512 };

/*@
  @ requires file_recovery->file_check == &file_check_spf;
  @ requires valid_file_check_param(file_recovery);
  @ ensures  valid_file_check_result(file_recovery);
  @ assigns  *file_recovery->handle, file_recovery->file_size, Frama_C_entropy_source, errno;
  @*/
static void file_check_spf(file_recovery_t *file_recovery)
{
  file_recovery->file_size=0;
  if(my_fseek(file_recovery->handle, 0, SEEK_SET)<0)
  {
    return;
  }
  /*@
    @ loop invariant valid_file_check_param(file_recovery);
    @ loop assigns *file_recovery->handle, file_recovery->file_size;
    @ loop assigns Frama_C_entropy_source, errno;
    @*/
  while(1)
  {
    int i;
    char buffer[READ_SIZE];
    const int taille=fread(buffer,1,READ_SIZE,file_recovery->handle);
    if(taille<512 || taille%512!=0)
    {
      file_recovery->file_size=0;
      return ;
    }
#ifdef __FRAMAC__
    Frama_C_make_unknown(buffer, READ_SIZE);
#endif
    /*@
      @ loop invariant valid_file_check_param(file_recovery);
      @ loop assigns i, file_recovery->file_size;
      @ loop variant PHOTOREC_MAX_FILE_SIZE - file_recovery->file_size;
      @*/
    for(i=0; i<taille; i+=512)
    {
      int j;
      int is_valid=0;
      file_recovery->file_size+=512;
      if(file_recovery->file_size >= PHOTOREC_MAX_FILE_SIZE)
      {
	return;
      }
      /*@
        @ loop assigns j, is_valid;
	@ loop variant 8 - j;
	@*/
      for(j=0; j<8; j++)
	if(buffer[i+j]!=0)
	  is_valid=1;
      /*@
        @ loop assigns j;
	@ loop variant 512 - j;
	@*/
      for(j=8; j<512 && buffer[i+j]==0; j++);
      if(is_valid > 0 && j==512)
      {
	return;
      }
    }
  }
}

/*@
  @ requires separation: \separated(&file_hint_spf, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_spf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_spf.extension;
  file_recovery_new->file_check=&file_check_spf;
  return 1;
}

static void register_header_check_spf(file_stat_t *file_stat)
{
  static const unsigned char spf_header[12]= {
    'S', 'P', 'F', 'I', 0x00, 0x02, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00
  };
  register_header_check(0, spf_header,sizeof(spf_header), &header_check_spf, file_stat);
}
#endif
