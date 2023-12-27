/*

    File: file_dxf.c

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dxf)
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

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_dxf(file_stat_t *file_stat);

const file_hint_t file_hint_dxf= {
  .extension="dxf",
  .description="Drawing Interchange File",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_dxf
};

/*@
  @ requires buffer_size >= 6;
  @ requires file_recovery->data_check==&data_check_dxf;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ terminates \true;
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ assigns file_recovery->calculated_file_size;
  @*/
static data_check_t data_check_dxf(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  unsigned int i;
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@
    @ loop assigns i, file_recovery->calculated_file_size;
    @ loop variant buffer_size - (i+4);
    @*/
  for(i=(buffer_size/2)-3;i+4<buffer_size;i++)
  {
    if(buffer[i]=='\n' && buffer[i+1]=='E' && buffer[i+2]=='O' && buffer[i+3]=='F')
    {
      file_recovery->calculated_file_size=file_recovery->file_size+i+4-(buffer_size/2);
      return DC_STOP;
    }
  }
  file_recovery->calculated_file_size=file_recovery->file_size+(buffer_size/2);
  return DC_CONTINUE;
}

/*@
  @ requires file_recovery->file_check == &file_check_dxf;
  @ requires valid_file_check_param(file_recovery);
  @ ensures  valid_file_check_result(file_recovery);
  @ assigns *file_recovery->handle, errno, Frama_C_entropy_source, file_recovery->file_size;
  @*/
static void file_check_dxf(file_recovery_t *file_recovery)
{
  const unsigned char dxf_footer[4]= {'\n', 'E', 'O', 'F'};
  file_search_footer(file_recovery, dxf_footer, sizeof(dxf_footer), 0);
  file_allow_nl(file_recovery, NL_BARENL|NL_CRLF);
}

/*@
  @ requires separation: \separated(&file_hint_dxf, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns *file_recovery_new;
  @*/
static int header_check_dxf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_dxf.extension;
  file_recovery_new->file_check=&file_check_dxf;
  if(file_recovery_new->blocksize >= 3)
  {
    file_recovery_new->data_check=&data_check_dxf;
  }
  return 1;
}

static void register_header_check_dxf(file_stat_t *file_stat)
{
  static const unsigned char header_dxflib[10]= 	{'9', '9', '9', '\n',
    'd', 'x', 'f', 'l', 'i', 'b'};
  static const unsigned char header_dxflib_dos[11]= 	{'9', '9', '9', '\r', '\n',
    'd', 'x', 'f', 'l', 'i', 'b'};
  static const unsigned char header_dxf[11]= 	{' ', ' ', '0', '\n',
    'S', 'E', 'C', 'T', 'I', 'O', 'N'};
  static const unsigned char header_dxf_dos[12]= 	{' ', ' ', '0', '\r', '\n',
    'S', 'E', 'C', 'T', 'I', 'O', 'N'};

  register_header_check(0, header_dxf, sizeof(header_dxf), &header_check_dxf, file_stat);
#ifndef DISABLED_FOR_FRAMAC
  register_header_check(0, header_dxf_dos, sizeof(header_dxf_dos), &header_check_dxf, file_stat);
  register_header_check(0, header_dxflib, sizeof(header_dxflib), &header_check_dxf, file_stat);
  register_header_check(0, header_dxflib_dos, sizeof(header_dxflib_dos), &header_check_dxf, file_stat);
#endif
}
#endif
