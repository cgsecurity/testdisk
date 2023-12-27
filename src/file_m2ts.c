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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_m2ts)
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
static void register_header_check_m2ts(file_stat_t *file_stat);
/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_ts(file_stat_t *file_stat);

const file_hint_t file_hint_m2ts= {
  .extension="m2ts",
  .description="Blu-ray MPEG-2",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_m2ts
};

const file_hint_t file_hint_ts= {
  .extension="ts",
  .description="MPEG transport stream (TS)",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=0,
  .register_header_check=&register_header_check_ts
};

static const unsigned char hdmv_header[4] = { 'H','D','M','V'};
static const unsigned char hdpr_header[4] = { 'H','D','P','R'};
static const unsigned char tshv_header[4] = { 'T','S','H','V'};
static const unsigned char sdvs_header[4] = { 'S','D','V','S'};

/*@
  @ requires file_recovery->data_check==&data_check_ts_192;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ terminates \true;
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ assigns file_recovery->calculated_file_size;
  @*/
static data_check_t data_check_ts_192(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@
    @ loop assigns file_recovery->calculated_file_size;
    @ loop variant file_recovery->file_size + buffer_size/2 - (file_recovery->calculated_file_size + 5);
    @*/
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 5 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size + buffer_size/2 - file_recovery->file_size;
    /*@ assert 0 <= i < buffer_size - 5; */
    if(buffer[i+4]!=0x47)	/* TS_SYNC_BYTE */
      return DC_STOP;
    file_recovery->calculated_file_size+=192;
  }
  return DC_CONTINUE;
}

/*@
  @ requires file_recovery->file_rename==&file_rename_ts_188;
  @ requires valid_file_rename_param(file_recovery);
  @ ensures  valid_file_rename_result(file_recovery);
  @*/
static void file_rename_ts_188(file_recovery_t *file_recovery)
{
  FILE *file;
  unsigned char buffer[188];
  char buffer_pid[32];
  unsigned int pid;
  if((file=fopen(file_recovery->filename, "rb"))==NULL)
    return;
  if(my_fseek(file, 0, SEEK_SET) < 0 ||
      fread(&buffer, sizeof(buffer), 1, file) != 1)
  {
    fclose(file);
    return ;
  }
  fclose(file);
#if defined(__FRAMAC__)
  Frama_C_make_unknown((char *)&buffer, sizeof(buffer));
#endif
  pid=((buffer[1]<<8)|buffer[2])&0x1fff;
  sprintf(buffer_pid, "pid_%u", pid);
#if defined(DISABLED_FOR_FRAMAC)
  buffer_pid[sizeof(buffer_pid)-1]='\0';
#endif
  file_rename(file_recovery, (const unsigned char*)buffer_pid, strlen(buffer_pid), 0, NULL, 1);
}

/*@
  @ requires file_recovery->file_rename==&file_rename_ts_192;
  @ requires valid_file_rename_param(file_recovery);
  @ ensures  valid_file_rename_result(file_recovery);
  @*/
static void file_rename_ts_192(file_recovery_t *file_recovery)
{
  FILE *file;
  unsigned char buffer[192];
  char buffer_pid[32];
  unsigned int pid;
  if((file=fopen(file_recovery->filename, "rb"))==NULL)
    return;
  if(my_fseek(file, 0, SEEK_SET) < 0 ||
      fread(&buffer, sizeof(buffer), 1, file) != 1)
  {
    fclose(file);
    return ;
  }
  fclose(file);
#if defined(__FRAMAC__)
  Frama_C_make_unknown((char *)&buffer, sizeof(buffer));
#endif
  pid=((buffer[5]<<8)|buffer[6])&0x1fff;
  sprintf(buffer_pid, "pid_%u", pid);
#if defined(DISABLED_FOR_FRAMAC)
  buffer_pid[sizeof(buffer_pid)-1]='\0';
#endif
  file_rename(file_recovery, (const unsigned char*)buffer_pid, strlen(buffer_pid), 0, NULL, 1);
}

/*@
  @ requires buffer_size >= 0xe8 + 4;
  @ requires separation: \separated(&file_hint_m2ts, &file_hint_ts, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @*/
static int header_check_m2ts(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  unsigned int i;
  /* BDAV MPEG-2 transport stream */
  /* Each frame is 192 byte long and begins by a TS_SYNC_BYTE */
  /*@
    @ loop assigns i;
    @ loop variant buffer_size - i;
    @*/
  for(i=4; i<buffer_size; i+=192)
    if(buffer[i]!=0x47)
      return 0;
  if(file_recovery->file_stat!=NULL &&
     file_recovery->file_check!=NULL &&
     file_recovery->file_stat->file_hint==&file_hint_m2ts &&
     file_recovery->data_check==&data_check_ts_192)
  {
    header_ignored(file_recovery_new);
    return 0;
  }
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
  file_recovery_new->file_rename=&file_rename_ts_192;
  file_recovery_new->min_filesize=192;
  if(file_recovery_new->blocksize < 5)
    return 1;
  file_recovery_new->calculated_file_size=0;
  file_recovery_new->data_check=&data_check_ts_192;
  file_recovery_new->file_check=&file_check_size_max;
  return 1;
}

/*@
  @ requires file_recovery->data_check==&data_check_ts_188;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ terminates \true;
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ assigns file_recovery->calculated_file_size;
  @*/
static data_check_t data_check_ts_188(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@
    @ loop assigns file_recovery->calculated_file_size;
    @ loop variant file_recovery->file_size + buffer_size/2 - file_recovery->calculated_file_size;
    @*/
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size + buffer_size/2 - file_recovery->file_size;
    /*@ assert 0 <= i < buffer_size; */
    if(buffer[i]!=0x47)	/* TS_SYNC_BYTE */
      return DC_STOP;
    file_recovery->calculated_file_size+=188;
  }
  return DC_CONTINUE;
}

/*@
  @ requires buffer_size >= 0x18b+sizeof(tshv_header);
  @ requires separation: \separated(&file_hint_m2ts, &file_hint_ts, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_m2t(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  unsigned int i;
  if(file_recovery->file_stat!=NULL &&
      file_recovery->data_check==&data_check_ts_188 &&
      file_recovery->calculated_file_size == file_recovery->file_size)
    return 0;
  /* Each frame is 188 byte long and begins by a TS_SYNC_BYTE */
  /*@
    @ loop assigns i;
    @ loop variant buffer_size - i;
    @*/
  for(i=0; i<buffer_size; i+=188)
    if(buffer[i]!=0x47)
      return 0;
  reset_file_recovery(file_recovery_new);
  if(memcmp(&buffer[0x18b], tshv_header, sizeof(tshv_header))==0)
    file_recovery_new->extension="m2t";
  else
    file_recovery_new->extension="ts";
  file_recovery_new->min_filesize=188;
  file_recovery_new->calculated_file_size=0;
  file_recovery_new->data_check=&data_check_ts_188;
  file_recovery_new->file_check=&file_check_size_max;
  file_recovery_new->file_rename=&file_rename_ts_188;
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
#endif
