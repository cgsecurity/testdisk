/*

    File: file_gif.c

    Copyright (C) 1998-2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_gif)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "filegen.h"
#include "log.h"

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_gif(file_stat_t *file_stat);
static data_check_t data_check_gif2(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery);

const file_hint_t file_hint_gif= {
  .extension="gif",
  .description="Graphic Interchange Format",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_gif
};

/*@
  @ requires file_recovery->file_check == &file_check_gif;
  @ requires valid_file_check_param(file_recovery);
  @ ensures  valid_file_check_result(file_recovery);
  @ assigns *file_recovery->handle, errno, file_recovery->file_size;
  @ assigns Frama_C_entropy_source;
  @*/
static void file_check_gif(file_recovery_t *file_recovery)
{
  const char gif_footer[2]= {0x00, 0x3b};
  char buffer[2];
  /* file_recovery->calculated_file_size is always >= */
  if(file_recovery->calculated_file_size < 2 ||
    file_recovery->calculated_file_size >= 0x8000000000000000 ||
      my_fseek(file_recovery->handle, file_recovery->calculated_file_size-2, SEEK_SET)<0 ||
      fread(buffer, 2, 1, file_recovery->handle)!=1)
  {
    file_recovery->file_size=0;
    return;
  }
#ifdef __FRAMAC__
  Frama_C_make_unknown(&buffer, sizeof(buffer));
#endif
  if(memcmp(buffer, gif_footer, sizeof(gif_footer))!=0)
  {
    file_recovery->file_size=0;
    return;
  }
  file_recovery->file_size=file_recovery->calculated_file_size;
}

/*@
  @ requires file_recovery->data_check==&data_check_gif;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ ensures file_recovery->data_check == &data_check_gif || file_recovery->data_check == &data_check_gif2;
  @ assigns file_recovery->calculated_file_size, file_recovery->data_check;
  @*/
static data_check_t data_check_gif(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  if(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 1 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size + buffer_size/2 - file_recovery->file_size;
    /*@ assert 0 <= i < buffer_size - 1; */
#ifdef DEBUG_GIF
    log_info("data_check_gif  calculated_file_size=0x%llx: 0x%02x\n",
	(long long unsigned)file_recovery->calculated_file_size, buffer[i]);
#endif
    switch(buffer[i])
    {
      case 0x21:
	/* Plain Text Extension 	21 01 ...		*/
	/* Graphic Control Extension 	21 f9 04 XX XX XX XX 00 */
	/* Comment Extension 		21 fe ... 		*/
	/* Application Extension 	21 ff 			*/
	file_recovery->calculated_file_size+=2;
	if(file_recovery->calculated_file_size >= PHOTOREC_MAX_FILE_SIZE)
	  return DC_STOP;
	/*@ assert file_recovery->calculated_file_size < PHOTOREC_MAX_FILE_SIZE; */
	file_recovery->data_check=&data_check_gif2;
	return data_check_gif2(buffer, buffer_size, file_recovery);
      case 0x2c:
	if(i + 20 < buffer_size)
	{
	  unsigned int j=10+1;
	  /* 1	Image Descriptor id=0x2c
	   * 4: NW corner
	   * 4: width, heigth,
	   * 1: is a local color table present ? */
	  if(((buffer[i+9]>>7)&0x1)>0)
	  {
	    /* local color table */
	    j+=3<<((buffer[i+9]&7)+1);
	  }
	  file_recovery->calculated_file_size+=j;
	  /* 1: Start of image - LZW minimum code size */
	  /* Table Based Image Data */
	  if(file_recovery->calculated_file_size >= PHOTOREC_MAX_FILE_SIZE)
	    return DC_STOP;
	  file_recovery->data_check=&data_check_gif2;
	  return data_check_gif2(buffer, buffer_size, file_recovery);
	}
	return DC_CONTINUE;
      case 0x3b:
	/* Trailer */
	file_recovery->calculated_file_size++;
	return DC_STOP;
      default:
	return DC_ERROR;
    }
  }
  return DC_CONTINUE;
}

/*@
  @ requires file_recovery->data_check==&data_check_gif2;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ ensures file_recovery->data_check == &data_check_gif || file_recovery->data_check == &data_check_gif2;
  @ assigns file_recovery->calculated_file_size, file_recovery->data_check;
  @*/
static data_check_t data_check_gif2(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@
    @ loop invariant file_recovery->data_check == &data_check_gif || file_recovery->data_check == &data_check_gif2;
    @ loop assigns file_recovery->calculated_file_size, file_recovery->data_check;
    @ loop variant file_recovery->file_size + buffer_size/2 - (file_recovery->calculated_file_size + 1);
    @*/
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 1 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size + buffer_size/2 - file_recovery->file_size;
    /*@ assert file_recovery->data_check==&data_check_gif2; */
    /*@ assert 0 <= i < buffer_size - 1; */
#ifdef DEBUG_GIF
    log_info("data_check_gif2 calculated_file_size=0x%llx\n",
	(long long unsigned)file_recovery->calculated_file_size);
#endif
    file_recovery->calculated_file_size+=(uint64_t)1+buffer[i];
    if(file_recovery->calculated_file_size >= PHOTOREC_MAX_FILE_SIZE)
      return DC_STOP;
    /*@ assert file_recovery->calculated_file_size < PHOTOREC_MAX_FILE_SIZE; */
    if(buffer[i]==0)
    {
      file_recovery->data_check=&data_check_gif;
      return data_check_gif(buffer, buffer_size, file_recovery);
    }
    /*@ assert file_recovery->data_check==&data_check_gif2; */
  }
  /*@ assert file_recovery->data_check==&data_check_gif2; */
  return DC_CONTINUE;
}

/*@
  @ requires buffer_size >= 6+7+(3<<8)+1;
  @ requires separation: \separated(&file_hint_gif, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ ensures (\result == 1) ==> file_recovery_new->file_size == 0;
  @ ensures (\result == 1) ==> (file_recovery_new->extension == file_hint_gif.extension);
  @ ensures (\result == 1) ==> (file_recovery_new->time == 0);
  @ ensures (\result == 1 && file_recovery_new->blocksize>=2) ==> (file_recovery_new->calculated_file_size >= 6+7);
  @ ensures (\result == 1 && file_recovery_new->blocksize>=2) ==> (file_recovery_new->data_check == &data_check_gif);
  @ ensures (\result == 1 && file_recovery_new->blocksize>=2) ==> (file_recovery_new->file_check == &file_check_gif);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_gif(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  uint64_t offset;
  offset=6;   /* Header */
  offset+=7;  /* Logical Screen Descriptor */
  if((buffer[10]>>7)&0x1)
  {
    /* Global Color Table */
    offset+=3<<((buffer[10]&7)+1);
  }
  if(offset < buffer_size && buffer[offset]!=0x21 && buffer[offset]!=0x2c)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_gif.extension;
  file_recovery_new->min_filesize=42;
  if(file_recovery_new->blocksize < 2)
    return 1;
  file_recovery_new->calculated_file_size=offset;
  file_recovery_new->file_check=&file_check_gif;
  file_recovery_new->data_check=&data_check_gif;
  return 1;
}

static void register_header_check_gif(file_stat_t *file_stat)
{
  static const unsigned char gif_header[6]=  { 'G','I','F','8','7','a'};
  static const unsigned char gif_header2[6]= { 'G','I','F','8','9','a'};
  register_header_check(0, gif_header,sizeof(gif_header), &header_check_gif, file_stat);
#ifndef DISABLED_FOR_FRAMAC
  register_header_check(0, gif_header2,sizeof(gif_header2), &header_check_gif, file_stat);
#endif
}
#endif
