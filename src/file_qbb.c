/*

    File: file_qbb.c

    Copyright (C) 2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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


static void register_header_check_qbb(file_stat_t *file_stat);

const file_hint_t file_hint_qbb= {
  .extension="qbb",
  .description="Quickbooks (qbb/qbw)",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_qbb
};

static data_check_t data_check_qbb(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  if(file_recovery->file_size + buffer_size / 2 > file_recovery->calculated_file_size+512)
  {
    return DC_STOP;
  }
  return DC_CONTINUE;
}

static void file_check_qbb(file_recovery_t *file_recovery)
{
  if(file_recovery->file_size < file_recovery->calculated_file_size)
    file_recovery->file_size=0;
}

static int header_check_qbb(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  reset_file_recovery(file_recovery_new);
  /* The filesize is bigger */
  file_recovery_new->calculated_file_size=(uint64_t)buffer[0x37] + (((uint64_t)buffer[0x37+1])<<8)+
    (((uint64_t)buffer[0x37+2])<<16) + (((uint64_t)buffer[0x37+3])<<24);
  file_recovery_new->extension=file_hint_qbb.extension;
  file_recovery_new->data_check=&data_check_qbb;
  file_recovery_new->file_check=&file_check_qbb;
  return 1;
}

static int header_check_qbw(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(buffer[0x60]=='M' && buffer[0x61]=='A' && buffer[0x62]=='U' && buffer[0x63]=='I')
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension="qbw";
    file_recovery_new->calculated_file_size=(((uint64_t)buffer[0x34] + (((uint64_t)buffer[0x34+1])<<8)+
      (((uint64_t)buffer[0x34+2])<<16) + (((uint64_t)buffer[0x34+3])<<24))+1)*1024;
    file_recovery_new->data_check=&data_check_size;
    file_recovery_new->file_check=&file_check_size;
    return 1;
  }
  return 0;
}

static int header_check_qbw2(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(&buffer[0x87A], "Sybase", 6)==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension="qbw";
    return 1;
  }
  return 0;
}


static void register_header_check_qbb(file_stat_t *file_stat)
{
  static const unsigned char qbb_header[10]= {0x45, 0x86, 0x00, 0x00, 0x06, 0x00, 0x02, 0x00, 0x01, 0x00};
  static const unsigned char qbw2_header[4]= {0x5e, 0xba, 0x7a, 0xda};
  static const unsigned char qbw_header[4]= {0x56, 0x00, 0x00, 0x00};
  register_header_check(0, qbb_header,sizeof(qbb_header), &header_check_qbb, file_stat);
  register_header_check(4, qbw_header,sizeof(qbw_header), &header_check_qbw, file_stat);
  register_header_check(0x14, qbw2_header,sizeof(qbw2_header), &header_check_qbw2, file_stat);
}
