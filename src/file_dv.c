/*

    File: file_dv.c

    Copyright (C) 2006-2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dv)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "filegen.h"
#if defined(__FRAMAC__)
#include "__fc_builtin.h"
#endif

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_dv(file_stat_t *file_stat);

const file_hint_t file_hint_dv= {
  .extension="dv",
  .description="DIF Digital Video",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_dv
};

/*@
  @ requires file_recovery->data_check==&data_check_NTSC;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ terminates \true;
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ assigns file_recovery->calculated_file_size;
  @*/
static data_check_t data_check_NTSC(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@
    @ loop assigns file_recovery->calculated_file_size;
    @ loop variant file_recovery->file_size + buffer_size/2 - (file_recovery->calculated_file_size + 8);
    @*/
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 8 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size + buffer_size/2 - file_recovery->file_size;
    /*@ assert 0 <= i < buffer_size - 8; */
    if(buffer[i]==0x1f && buffer[i+1]==0x07 && buffer[i+2]==0x00 &&
	buffer[i+5]==0x78 && buffer[i+6]==0x78 && buffer[i+7]==0x78)
      file_recovery->calculated_file_size+=120000;
    else
      return DC_STOP;
  }
  return DC_CONTINUE;
}

/*@
  @ requires fr->file_check == &file_check_dv_NTSC;
  @ requires valid_file_check_param(fr);
  @ ensures  valid_file_check_result(fr);
  @ assigns *fr->handle, errno, Frama_C_entropy_source, fr->file_size;
  @*/
static void file_check_dv_NTSC(file_recovery_t *fr)
{
  char buffer_header[512];
  uint64_t fs=fr->file_size/120000*120000;
  if(my_fseek(fr->handle, 0, SEEK_SET) < 0 ||
      fread(&buffer_header, sizeof(buffer_header), 1, fr->handle) != 1)
    return ;
#if defined(__FRAMAC__)
  Frama_C_make_unknown(&buffer_header, sizeof(buffer_header));
#endif
  if(fs > 0)
    fs-=120000;
  if(fs > 0)
    fs-=120000;
  /*@
    @ loop assigns fs, *fr->handle, errno, Frama_C_entropy_source, fr->file_size;
    @ loop variant fr->file_size - fs;
    @*/
  while(fs < fr->file_size &&
      my_fseek(fr->handle, fs, SEEK_SET) >= 0)
  {
    char buffer[120000];
    unsigned int i;
    if(fread(&buffer, sizeof(buffer), 1, fr->handle) != 1)
    {
      fr->file_size=fs;
      return;
    }
#if defined(__FRAMAC__)
    Frama_C_make_unknown(&buffer, sizeof(buffer));
#endif
    /*@
      @ loop assigns i;
      @ loop variant sizeof(buffer) - i;
      @*/
    for(i=1; i<sizeof(buffer); i+=0x50)
      if((buffer[i]&0x0f)!=(buffer_header[1]&0x0f))
      {
	fr->file_size=fs;
	return;
      }
    fs+=sizeof(buffer);
  }
  fr->file_size=fs;
}

/*@
  @ requires file_recovery->data_check==&data_check_PAL;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ terminates \true;
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ assigns file_recovery->calculated_file_size;
  @*/
static data_check_t data_check_PAL(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert buffer_size <= 2 * PHOTOREC_MAX_BLOCKSIZE; */
  /*@
    @ loop assigns file_recovery->calculated_file_size;
    @ loop variant file_recovery->file_size + buffer_size/2 - (file_recovery->calculated_file_size + 8);
    @*/
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 8 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size + buffer_size/2 - file_recovery->file_size;
    /*@ assert 0 <= i < buffer_size - 8; */
    if(buffer[i]==0x1f && buffer[i+1]==0x07 && buffer[i+2]==0x00 &&
	buffer[i+5]==0x78 && buffer[i+6]==0x78 && buffer[i+7]==0x78)
      file_recovery->calculated_file_size+=144000;
    else
      return DC_STOP;
  }
  return DC_CONTINUE;
}

/*@
  @ requires fr->file_check == &file_check_dv_PAL;
  @ requires valid_file_check_param(fr);
  @ ensures  valid_file_check_result(fr);
  @ assigns *fr->handle, errno, Frama_C_entropy_source, fr->file_size;
  @*/
static void file_check_dv_PAL(file_recovery_t *fr)
{
  char buffer_header[512];
  uint64_t fs=fr->file_size/144000*144000;
  if(my_fseek(fr->handle, 0, SEEK_SET) < 0 ||
      fread(&buffer_header, sizeof(buffer_header), 1, fr->handle) != 1)
    return ;
#if defined(__FRAMAC__)
  Frama_C_make_unknown(&buffer_header, sizeof(buffer_header));
#endif
  if(fs > 0)
    fs-=144000;
  if(fs > 0)
    fs-=144000;
  /*@
    @ loop assigns fs, *fr->handle, errno, Frama_C_entropy_source, fr->file_size;
    @ loop variant fr->file_size - fs;
    @*/
  while(fs < fr->file_size &&
      my_fseek(fr->handle, fs, SEEK_SET) >= 0)
  {
    unsigned int i;
    char buffer[144000];
    if(fread(&buffer, sizeof(buffer), 1, fr->handle) != 1)
    {
      fr->file_size=fs;
      return;
    }
#if defined(__FRAMAC__)
    Frama_C_make_unknown(&buffer, sizeof(buffer));
#endif
    /*@
      @ loop assigns i;
      @ loop variant sizeof(buffer) - i;
      @*/
    for(i=1; i<sizeof(buffer); i+=0x50)
      if((buffer[i]&0x0f)!=(buffer_header[1]&0x0f))
      {
	fr->file_size=fs;
	return;
      }
    fs+=sizeof(buffer);
  }
  fr->file_size=fs;
}


/*@
  @ requires buffer_size >= 8;
  @ requires separation: \separated(&file_hint_dv, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @*/
static int header_check_dv(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(buffer[0]!=0x1f || buffer[1]!=0x07 || buffer[2]!=0x00 || buffer[5]!=0x78 || buffer[6]!=0x78 || buffer[7]!=0x78)
    return 0;
  if(file_recovery->file_stat!=NULL &&
      file_recovery->file_check!=NULL &&
      file_recovery->file_stat->file_hint==&file_hint_dv)
  {
    /*@ assert \valid_function(file_recovery->file_check); */
    header_ignored(file_recovery_new);
    return 0;
  }
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_dv.extension;
  if((buffer[3]&0x80)==0)
    file_recovery_new->file_check=&file_check_dv_NTSC;
  else
    file_recovery_new->file_check=&file_check_dv_PAL;
  if(file_recovery_new->blocksize < 8)
    return 1;
  // Each frame contains exactly 120000 bytes in NTSC, 144000 in PAL.
  if((buffer[3]&0x80)==0)
    file_recovery_new->data_check=&data_check_NTSC;
  else
    file_recovery_new->data_check=&data_check_PAL;
  return 1;
}

static void register_header_check_dv(file_stat_t *file_stat)
{
  static const unsigned char dv_header[3]= {0x1f, 0x07, 0x00};
  register_header_check(0, dv_header,sizeof(dv_header), &header_check_dv, file_stat);
}
#endif
