/*

    File: file_vmg.c

    Copyright (C) 2011 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include "filegen.h"

static void register_header_check_vmg(file_stat_t *file_stat);

const file_hint_t file_hint_vmg= {
  .extension="vmg",
  .description="Nokia Text Message",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_vmg
};

static void file_check_vmg(file_recovery_t *file_recovery)
{
  const unsigned char vmg_footer[0x15]= {
    0x00, '\n', 0x00, 'E' , 0x00, 'N' , 0x00, 'D' ,
    0x00, ':' , 0x00, 'V' , 0x00, 'M' , 0x00, 'S' ,
    0x00, 'G' , 0x00, '\n', 0x00
  };
  file_search_footer(file_recovery, vmg_footer, sizeof(vmg_footer), 0);
}

static const unsigned char vmg_header[0x28]=  {
  'B' , 0x00, 'E' , 0x00, 'G' , 0x00, 'I' , 0x00,
  'N' , 0x00, ':' , 0x00, 'V' , 0x00, 'M' , 0x00,
  'S' , 0x00, 'G' , 0x00, '\n', 0x00, 'V' , 0x00,
  'E' , 0x00, 'R' , 0x00, 'S' , 0x00, 'I' , 0x00,
  'O' , 0x00, 'N' , 0x00, ':' , 0x00, '1' , 0x00
};

static int header_check_vmg(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(&buffer[0], vmg_header, sizeof(vmg_header))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_vmg.extension;
    file_recovery_new->file_check=&file_check_vmg;
    return 1;
  }
  return 0;
}

static void register_header_check_vmg(file_stat_t *file_stat)
{
  register_header_check(0, vmg_header, sizeof(vmg_header), &header_check_vmg, file_stat);
}
