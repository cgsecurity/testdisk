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
  @ assigns \nothing;
  @ behavior bit_set:
  @       assumes (buffer9 & 0x80) == 0x80;
  @       ensures \result == 11 + (6<<(buffer9 & 0x7));
  @ behavior bit_not_set:
  @       assumes (buffer9 & 0x80) != 0x80;
  @       ensures \result == 11;
  @ complete behaviors;
  @ disjoint behaviors;
  @*/
static unsigned int image_separator_size(const unsigned char buffer9)
{
  if((buffer9 & 0x80) == 0x80)
  {
    const unsigned int tmp=buffer9 & 0x7;
    /*@ assert 0 <= tmp <= 7; */
    /*@ assert tmp == (buffer9 & 7); */
    /* local color present */
    const unsigned int tmp2=11 + (6<<tmp);
    /*@ assert tmp2 == 11 + (6<<tmp); */
    return tmp2;
  }
  return 11;
}

/*@
  @ requires file_recovery->data_check==&data_check_gif;
  @ requires file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ decreases PHOTOREC_MAX_FILE_SIZE - file_recovery->calculated_file_size;
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ ensures file_recovery->data_check == &data_check_gif || file_recovery->data_check == &data_check_gif2;
  @ ensures \old(file_recovery->calculated_file_size) <= file_recovery->calculated_file_size;
  @ assigns file_recovery->calculated_file_size
      \from file_recovery->calculated_file_size,
            file_recovery->file_size,
            buffer_size,
            buffer[0 .. buffer_size-1];
  @ assigns file_recovery->data_check
      \from file_recovery->calculated_file_size,
            file_recovery->file_size,
            buffer_size,
            buffer[0 .. buffer_size-1];
  @*/
static data_check_t data_check_gif(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
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
	{
	  return DC_STOP;
	}
	file_recovery->data_check=&data_check_gif2;
	return data_check_gif2(buffer, buffer_size, file_recovery);
      case 0x2c:
	if(i + 20 < buffer_size)
	{
	  /*@ assert i < buffer_size - 20; */
	  /*@ assert \valid_read(buffer+(0..i+20-1)); */
	  /* 1	Image Descriptor id=0x2c
	   * 4: NW corner
	   * 4: width, heigth,
	   * 1: packed field */
	  const unsigned int j=image_separator_size(buffer[i+9]);
	  /*@ assert j >= 11; */
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
  @ requires \valid(file_recovery);
  @ requires \valid_read(buffer+(0..buffer_size-1));
  @ requires file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE;
  @ requires file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE;
  @ requires file_recovery->data_check==&data_check_gif2;
  @ requires buffer_size <= 2 * PHOTOREC_MAX_BLOCKSIZE;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ decreases PHOTOREC_MAX_FILE_SIZE - file_recovery->calculated_file_size;
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ ensures file_recovery->data_check == &data_check_gif || file_recovery->data_check == &data_check_gif2;
  @ ensures \old(file_recovery->calculated_file_size) <= file_recovery->calculated_file_size;
  @ assigns file_recovery->calculated_file_size
      \from file_recovery->calculated_file_size,
            file_recovery->file_size,
            buffer_size,
            buffer[0 .. buffer_size-1];
  @ assigns file_recovery->data_check
      \from file_recovery->calculated_file_size,
            file_recovery->file_size,
            buffer_size,
            buffer[0 .. buffer_size-1];
  @*/
static data_check_t data_check_gif2(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /*@
    @ loop invariant file_recovery->data_check == &data_check_gif2;
    @ loop invariant file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE;
    @ loop invariant \at(file_recovery->calculated_file_size, Pre) <= file_recovery->calculated_file_size;
    @ loop invariant file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE;
    @ loop assigns file_recovery->calculated_file_size, file_recovery->data_check;
    @ loop variant PHOTOREC_MAX_FILE_SIZE - file_recovery->calculated_file_size;
    @*/
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 1 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size + buffer_size/2 - file_recovery->file_size;
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
  }
  return DC_CONTINUE;
}

/*@
  @ assigns \nothing;
  @ ensures 13 <= \result <= 13 + (6<<7);
  @*/
static unsigned int gif_size_before_image(const unsigned char buffer10)
{
  unsigned int offset=6+7;   /* Header + Logical Screen Descriptor */
  if((buffer10 & 0x80) == 0x80)
  {
    /* Global Color Table */
    const unsigned int tmp=buffer10&7;
    offset+=6<<tmp;
  }
  /*@ assert 13 <= offset <= 13 + (6<<7); */
  return offset;
}

/*@
  @ requires buffer_size >= 6+7+(3<<8)+1;
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
  const uint64_t offset=gif_size_before_image(buffer[10]);
  if(offset < buffer_size && buffer[offset]!=0x21 && buffer[offset]!=0x2c)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_gif.extension;
  file_recovery_new->min_filesize=42;
  /*@ assert valid_read_string(file_recovery_new->extension); */
  /*@ assert valid_file_recovery(file_recovery_new); */
  if(file_recovery_new->blocksize < 2)
    return 1;
  file_recovery_new->calculated_file_size=offset;
  file_recovery_new->file_check=&file_check_gif;
  file_recovery_new->data_check=&data_check_gif;
  /*@ assert valid_file_recovery(file_recovery_new); */
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
