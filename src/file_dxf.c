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

static void register_header_check_dxf(file_stat_t *file_stat);
static data_check_t data_check_dxf(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery);
static void file_check_dxf(file_recovery_t *file_recovery);

const file_hint_t file_hint_dxf= {
  .extension="dxf",
  .description="Drawing Interchange File",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_dxf
};

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

static data_check_t data_check_dxf(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  unsigned int i;
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

static void file_check_dxf(file_recovery_t *file_recovery)
{
  const unsigned char dxf_footer[4]= {'\n', 'E', 'O', 'F'};
  file_search_footer(file_recovery, dxf_footer, sizeof(dxf_footer), 0);
  file_allow_nl(file_recovery, NL_BARENL|NL_CRLF);
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
  register_header_check(0, header_dxf_dos, sizeof(header_dxf_dos), &header_check_dxf, file_stat);
  register_header_check(0, header_dxflib, sizeof(header_dxflib), &header_check_dxf, file_stat);
  register_header_check(0, header_dxflib_dos, sizeof(header_dxflib_dos), &header_check_dxf, file_stat);
}
