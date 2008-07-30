/*

    File: file_m2ts.c

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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "filegen.h"

static void register_header_check_m2ts(file_stat_t *file_stat);
/* M2TS */
static int header_check_m2ts(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);
static int data_check_m2ts(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery);
/* M2T */
static int header_check_m2t(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);
static int data_check_m2t(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery);

const file_hint_t file_hint_m2ts= {
  .extension="m2ts",
  .description="Blu-ray MPEG-2",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_m2ts
};

static const unsigned char m2ts_header[4]=  { 'H','D','M','V'};
static const unsigned char m2t_header[4] =  { 'T','S','H','V'};

static void register_header_check_m2ts(file_stat_t *file_stat)
{
  register_header_check(0xd7, m2ts_header, sizeof(m2ts_header), &header_check_m2ts, file_stat);
  register_header_check(0x18b, m2t_header, sizeof(m2t_header),  &header_check_m2t,  file_stat);
}

static int header_check_m2ts(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(file_recovery!=NULL && file_recovery->file_stat!=NULL &&
       file_recovery->file_stat->file_hint==&file_hint_m2ts)
    return 0;
  /* BDAV MPEG-2 transport stream */
  /* Each frame is 192 byte long and begins by a TS_SYNC_BYTE */
  if(buffer[4]==0x47 && buffer[4+192]==0x47 && buffer[4+2*192]==0x47 &&
      memcmp(&buffer[0xd7], m2ts_header, sizeof(m2ts_header))==0 &&
      memcmp(&buffer[0xe8], m2ts_header, sizeof(m2ts_header))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_m2ts.extension;
    file_recovery_new->min_filesize=192;
    file_recovery_new->calculated_file_size=192;
    file_recovery_new->data_check=&data_check_m2ts;
    file_recovery_new->file_check=&file_check_size;
    return 1;
  }
  return 0;
}

static int header_check_m2t(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(file_recovery!=NULL && file_recovery->file_stat!=NULL &&
      file_recovery->file_stat->file_hint==&file_hint_m2ts &&
      file_recovery->calculated_file_size == file_recovery->file_size)
    return 0;
  /* Each frame is 188 byte long and begins by a TS_SYNC_BYTE */
  if(buffer[0]==0x47 && buffer[188]==0x47 && buffer[2*188]==0x47 &&
      memcmp(&buffer[0x18b], m2t_header, sizeof(m2t_header))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension="m2t";
    file_recovery_new->min_filesize=188;
    file_recovery_new->calculated_file_size=188;
    file_recovery_new->data_check=&data_check_m2t;
    file_recovery_new->file_check=&file_check_size;
    return 1;
  }
  return 0;
}

static int data_check_m2ts(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 5 < file_recovery->file_size + buffer_size/2)
  {
    unsigned int i=file_recovery->calculated_file_size - file_recovery->file_size + buffer_size/2;
    if(buffer[i+4]!=0x47)	/* TS_SYNC_BYTE */
      return 2;
    file_recovery->calculated_file_size+=192;
  }
  return 1;
}

static int data_check_m2t(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  while(file_recovery->calculated_file_size + 1 < file_recovery->file_size + buffer_size/2)
  {
    unsigned int i=file_recovery->calculated_file_size - file_recovery->file_size + buffer_size/2;
    if(buffer[i]!=0x47)	/* TS_SYNC_BYTE */
      return 2;
    file_recovery->calculated_file_size+=188;
  }
  return 1;
}
