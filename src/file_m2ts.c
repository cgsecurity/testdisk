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
static void register_header_check_ts(file_stat_t *file_stat);

const file_hint_t file_hint_m2ts= {
  .extension="m2ts",
  .description="Blu-ray MPEG-2",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_m2ts
};

const file_hint_t file_hint_ts= {
  .extension="ts",
  .description="MPEG transport stream (TS)",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=0,
  .register_header_check=&register_header_check_ts
};

static const unsigned char hdmv_header[4] = { 'H','D','M','V'};
static const unsigned char hdpr_header[4] = { 'H','D','P','R'};
static const unsigned char tshv_header[4] = { 'T','S','H','V'};
static const unsigned char sdvs_header[4] = { 'S','D','V','S'};

static int data_check_ts_192(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 5 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size - file_recovery->file_size + buffer_size/2;
    if(buffer[i+4]!=0x47)	/* TS_SYNC_BYTE */
      return 2;
    file_recovery->calculated_file_size+=192;
  }
  return 1;
}

static int header_check_m2ts(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  unsigned int i;
  if(file_recovery!=NULL && file_recovery->file_stat!=NULL &&
      file_recovery->data_check==&data_check_ts_192)
    return 0;
  /* BDAV MPEG-2 transport stream */
  /* Each frame is 192 byte long and begins by a TS_SYNC_BYTE */
  for(i=4; i<buffer_size && buffer[i]==0x47; i+=192);
  if(i<buffer_size)
    return 0;
  reset_file_recovery(file_recovery_new);
  if( memcmp(&buffer[0xd7], &buffer[0xe8], 4)==0)
  {
    if( memcmp(&buffer[0xd7], hdmv_header, sizeof(hdmv_header))==0 ||
	memcmp(&buffer[0xd7], hdpr_header, sizeof(hdpr_header))==0)
    {
#ifdef DJGPP
      file_recovery_new->extension="m2t";
#else
      file_recovery_new->extension=file_hint_m2ts.extension;
#endif
    }
    else if( memcmp(&buffer[0xd7], sdvs_header, sizeof(sdvs_header))==0)
      file_recovery_new->extension="tod";
    else
      file_recovery_new->extension="ts";
  }
  else
    file_recovery_new->extension="ts";
  file_recovery_new->min_filesize=192;
  file_recovery_new->calculated_file_size=0;
  /* data_check_ts_192 is for a check at header_check_m2ts() beginning
   * so always define data_check even if it will only really work
   * for blocksize >= 3 */
  file_recovery_new->data_check=&data_check_ts_192;
  if(file_recovery_new->blocksize > 5/2)
  {
    file_recovery_new->file_check=&file_check_size_lax;
  }
  return 1;
}

static int data_check_ts_188(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  while(file_recovery->calculated_file_size + 1 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size - file_recovery->file_size + buffer_size/2;
    if(buffer[i]!=0x47)	/* TS_SYNC_BYTE */
      return 2;
    file_recovery->calculated_file_size+=188;
  }
  return 1;
}

static int header_check_m2t(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  unsigned int i;
  if(file_recovery!=NULL && file_recovery->file_stat!=NULL &&
      file_recovery->data_check==&data_check_ts_188 &&
      file_recovery->calculated_file_size == file_recovery->file_size)
    return 0;
  /* Each frame is 188 byte long and begins by a TS_SYNC_BYTE */
  for(i=0; i<buffer_size && buffer[i]==0x47; i+=188);
  if(i<buffer_size)
    return 0;
  reset_file_recovery(file_recovery_new);
  if(memcmp(&buffer[0x18b], tshv_header, sizeof(tshv_header))==0)
    file_recovery_new->extension="m2t";
  else
    file_recovery_new->extension="ts";
  file_recovery_new->min_filesize=188;
  file_recovery_new->calculated_file_size=0;
  file_recovery_new->data_check=&data_check_ts_188;
  file_recovery_new->file_check=&file_check_size_lax;
  return 1;
}

static void register_header_check_m2ts(file_stat_t *file_stat)
{
  register_header_check(0xd7, hdmv_header, sizeof(hdmv_header), &header_check_m2ts, file_stat);
  register_header_check(0xd7, hdpr_header, sizeof(hdpr_header), &header_check_m2ts, file_stat);
  register_header_check(0xd7, sdvs_header, sizeof(sdvs_header), &header_check_m2ts, file_stat);
  register_header_check(0x18b, tshv_header, sizeof(tshv_header), &header_check_m2t,  file_stat);
}

static void register_header_check_ts(file_stat_t *file_stat)
{
  register_header_check(0, "G", 1,  &header_check_m2t, file_stat);
  register_header_check(4, "G", 1,  &header_check_m2ts, file_stat);
}
