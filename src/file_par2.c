/*

    File: file_par2.c

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_par2)
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
#include "log.h"

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_par2(file_stat_t *file_stat);

const file_hint_t file_hint_par2= {
  .extension="par2",
  .description="parchive",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_par2
};

static const unsigned char par2_header[8]=  {
  'P' , 'A' , 'R' , '2' , 0x00, 'P' , 'K' , 'T'
};

/*@
  @ requires file_recovery->data_check == &data_check_par2;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ assigns file_recovery->calculated_file_size;
  @*/
static data_check_t data_check_par2(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@
    @ loop assigns file_recovery->calculated_file_size;
    @ loop variant file_recovery->file_size + buffer_size/2 - (file_recovery->calculated_file_size + 16);
    @*/
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 16 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size + buffer_size/2 - file_recovery->file_size;
    /*@ assert 0 <= i < buffer_size - 16; */
    const uint64_t length=le64((*(const uint64_t *)(&buffer[i+8])));
    if(memcmp(&buffer[i], &par2_header, sizeof(par2_header))!=0)
      return DC_STOP;
    if(length % 4 !=0 || length < 16 || length > PHOTOREC_MAX_FILE_SIZE)
      return DC_STOP;
    file_recovery->calculated_file_size+=length;
  }
  return DC_CONTINUE;
}

/*@
  @ requires file_recovery->file_rename==&file_rename_par2;
  @ requires valid_file_rename_param(file_recovery);
  @ ensures  valid_file_rename_result(file_recovery);
  @*/
static void file_rename_par2(file_recovery_t *file_recovery)
{
  FILE *file;
  uint64_t offset=0;
  if((file=fopen(file_recovery->filename, "rb"))==NULL)
    return;
  /*@
    @ loop invariant valid_file_rename_param(file_recovery);
    @ loop variant PHOTOREC_MAX_FILE_SIZE - offset;
    @*/
  while(offset <= PHOTOREC_MAX_FILE_SIZE)
  {
    uint64_t length;
    size_t buffer_size;
    unsigned char buffer[4096];
    const uint64_t *lengthp=(const uint64_t *)&buffer[8];
    if(my_fseek(file, offset, SEEK_SET)<0)
    {
      fclose(file);
      return;
    }
    buffer_size=fread(buffer, 1, sizeof(buffer), file);
    if(buffer_size<0x78)
    {
      fclose(file);
      return;
    }
    length=le64(*lengthp);
    if(length % 4 !=0 || length < 16 || length >= PHOTOREC_MAX_FILE_SIZE ||
	memcmp(&buffer, &par2_header, sizeof(par2_header))!=0)
    {
      fclose(file);
      return;
    }
    /*@ assert length >= 16; */
    if(memcmp(&buffer[0x30], "PAR 2.0\0FileDesc", 16)==0)
    {
      fclose(file);
      file_rename(file_recovery, buffer,
	  (length < buffer_size ? length : buffer_size),
	  0x78, NULL, 1);
      return ;
    }
    offset+=length;
  }
  fclose(file);
  return;
}

/*@
  @ requires buffer_size >= 16;
  @ requires separation: \separated(&file_hint_par2, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @*/
static int header_check_par2(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const uint64_t length=le64((*(const uint64_t *)(&buffer[8])));
  if(length % 4 !=0 || length < 16 || length > PHOTOREC_MAX_FILE_SIZE)
    return 0;
  if(file_recovery->file_stat!=NULL &&
      file_recovery->file_stat->file_hint==&file_hint_par2)
  {
    if(header_ignored_adv(file_recovery, file_recovery_new)==0)
      return 0;
  }
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_par2.extension;
  file_recovery_new->file_rename=&file_rename_par2;
  file_recovery_new->min_filesize=64+length;
  if(file_recovery_new->blocksize < 16)
    return 1;
  file_recovery_new->data_check=&data_check_par2;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static void register_header_check_par2(file_stat_t *file_stat)
{
  register_header_check(0, par2_header, sizeof(par2_header), &header_check_par2, file_stat);
}
#endif
