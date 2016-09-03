/*

    File: file_ysfc100.c

    Copyright (C) 2016 Christophe GRENIER <grenier@cgsecurity.org>

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
#include "common.h"

static void register_header_check_ysfc100(file_stat_t *file_stat);

const file_hint_t file_hint_x4a= {
  .extension="x4a",
  .description="Yamaha-YSFC",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_ysfc100
};

struct x4a_catalog
{
  char type[4];
  uint32_t size;
} __attribute__ ((gcc_struct, __packed__));

static void file_check_x4a(file_recovery_t *fr)
{
  unsigned char buffer[0x200];
  unsigned int i;
  unsigned int fs=0x80;
  fr->file_size = 0;
  fr->offset_error=0;
  fr->offset_ok=0;
  if(my_fseek(fr->handle, 0, SEEK_SET) < 0 ||
      fread(&buffer, sizeof(buffer), 1, fr->handle)!=1)
    return;
  for(i=0x80; i<0x200; i+=8)
  {
    const struct x4a_catalog *p=(const struct x4a_catalog *)&buffer[i];
    if(be32(p->size) > fs)
      fs=be32(p->size);
  }
  if(my_fseek(fr->handle, 0, SEEK_SET) < 0 ||
      fread(&buffer, 8, 1, fr->handle)!=1)
    return;
  {
    const struct x4a_catalog *p=(const struct x4a_catalog *)buffer;
    fr->file_size=fs+be32(p->size);
  }
}

static int header_check_ysfc100(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(&buffer[0x10], "Ver 01.00", 8)!=0 ||
      memcmp(&buffer[0x30], "YSFC", 4)!=0)
    return 0;
  reset_file_recovery(file_recovery_new);
  if(memcmp(&buffer[6], "ALL", 3)==0)
    file_recovery_new->extension=file_hint_x4a.extension;
  else if(memcmp(&buffer[6], "SONG", 4)==0)
    file_recovery_new->extension="x4s";
  else if(memcmp(&buffer[6], "PATTERN", 7)==0)
    file_recovery_new->extension="x4p";
  else if(memcmp(&buffer[6], "ARPEGGIO", 8)==0)
    file_recovery_new->extension="x4g";
  else
    file_recovery_new->extension=file_hint_x4a.extension;
  file_recovery_new->min_filesize=0x200;
  file_recovery_new->file_check=&file_check_x4a;
  return 1;
}

static void register_header_check_ysfc100(file_stat_t *file_stat)
{
  static const unsigned char ysfc100_header[8]=  {
    'Y' , 'S' , 'F' , 'C' , 0xff, 0xff, 0xff, 0xff
  };
  register_header_check(0x30, ysfc100_header, sizeof(ysfc100_header), &header_check_ysfc100, file_stat);
}
