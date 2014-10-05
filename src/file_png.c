/*

    File: file_png.c

    Copyright (C) 1998-2009 Christophe GRENIER <grenier@cgsecurity.org>
    Thanks to Holger Klemm for JNG (JPEG Network Graphics) and
    MNG (Multiple-Image Network Graphics) support (2006)
  
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
/*
   MNG (Multiple-image Network Graphics) Format
   http://www.libpng.org/pub/mng/spec/
*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include <ctype.h>
#include "types.h"
#include "common.h"
#include "filegen.h"

extern const file_hint_t file_hint_doc;

static void register_header_check_png(file_stat_t *file_stat);
static data_check_t data_check_png(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery);
static data_check_t data_check_mng(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery);

const file_hint_t file_hint_png= {
  .extension="png",
  .description="Portable/JPEG/Multiple-Image Network Graphics",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_png
};

struct png_chunk
{
  uint32_t length;
  uint32_t type;
  char data[0];
  /* data is followed by uint32_t crc; */
} __attribute__ ((__packed__));

static int header_check_jng(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if( !((isupper(buffer[8+4]) || islower(buffer[8+4])) &&
	(isupper(buffer[8+5]) || islower(buffer[8+5])) &&
	(isupper(buffer[8+6]) || islower(buffer[8+6])) &&
	(isupper(buffer[8+7]) || islower(buffer[8+7]))))
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension="jng";
  file_recovery_new->min_filesize=16;
  if(file_recovery_new->blocksize < 8)
    return 1;
  file_recovery_new->calculated_file_size=8;
  file_recovery_new->data_check=&data_check_png;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static int header_check_mng(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if( !((isupper(buffer[8+4]) || islower(buffer[8+4])) &&
	(isupper(buffer[8+5]) || islower(buffer[8+5])) &&
	(isupper(buffer[8+6]) || islower(buffer[8+6])) &&
	(isupper(buffer[8+7]) || islower(buffer[8+7]))))
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension="mng";
  file_recovery_new->min_filesize=16;
  if(file_recovery_new->blocksize < 8)
    return 1;
  file_recovery_new->calculated_file_size=8;
  file_recovery_new->data_check=&data_check_mng;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static void file_check_png(file_recovery_t *fr)
{
  if(fr->file_size<fr->calculated_file_size)
  {
    fr->file_size=0;
    return ;
  }
  fr->file_size=8;
  while(1)
  {
    char buffer[8];
    const struct png_chunk *chunk=(const struct png_chunk *)&buffer;
    if(
#ifdef HAVE_FSEEKO
	fseeko(fr->handle, fr->file_size, SEEK_SET) < 0 ||
#else
	fseek(fr->handle, fr->file_size, SEEK_SET) < 0 ||
#endif
	fread(&buffer, sizeof(buffer), 1, fr->handle) != 1)
    {
      fr->file_size=0;
      return ;
    }
    fr->file_size+=12 + be32(chunk->length);
    if(memcmp(&buffer[4], "IEND", 4)==0)
      return ;
  }
}

static int header_check_png(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /* SolidWorks files contains a png */
  if(file_recovery->file_stat!=NULL &&
      file_recovery->file_stat->file_hint==&file_hint_doc &&
      (strcmp(file_recovery->extension,"sld")==0 ||
       strcmp(file_recovery->extension,"sldprt")==0))
    return 0;
  if( !((isupper(buffer[8+4]) || islower(buffer[8+4])) &&
	(isupper(buffer[8+5]) || islower(buffer[8+5])) &&
	(isupper(buffer[8+6]) || islower(buffer[8+6])) &&
	(isupper(buffer[8+7]) || islower(buffer[8+7]))))
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_png.extension;
  file_recovery_new->min_filesize=16;
  if(file_recovery_new->blocksize < 8)
    return 1;
  file_recovery_new->calculated_file_size=8;
  file_recovery_new->data_check=&data_check_png;
  file_recovery_new->file_check=&file_check_png;
  return 1;
}

static data_check_t data_check_mng(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  static const unsigned char mng_footer[4]= {'M','E','N','D'};
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 8 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size - file_recovery->file_size + buffer_size/2;
    const struct png_chunk *chunk=(const struct png_chunk *)&buffer[i];
    if(memcmp(&buffer[i+4], mng_footer, sizeof(mng_footer))==0)
    {
      file_recovery->calculated_file_size+=12 + be32(chunk->length);
      return DC_STOP;
    }
    if( !((isupper(buffer[i+4]) || islower(buffer[i+4])) &&
	  (isupper(buffer[i+5]) || islower(buffer[i+5])) &&
	  (isupper(buffer[i+6]) || islower(buffer[i+6])) &&
	  (isupper(buffer[i+7]) || islower(buffer[i+7]))))
    {
      file_recovery->offset_error=file_recovery->calculated_file_size+7;
      return DC_ERROR;
    }
    file_recovery->offset_ok=file_recovery->calculated_file_size+7;
    file_recovery->calculated_file_size+=12 + be32(chunk->length);
  }
  return DC_CONTINUE;
}

static data_check_t data_check_png(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 8 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size - file_recovery->file_size + buffer_size/2;
    const struct png_chunk *chunk=(const struct png_chunk *)&buffer[i];
    if(memcmp(&buffer[i+4], "IEND", 4)==0)
    {
      file_recovery->calculated_file_size+=12 + be32(chunk->length);
      return DC_STOP;
    }
// PNG chunk code
// IDAT IHDR PLTE bKGD cHRM fRAc gAMA gIFg gIFt gIFx hIST iCCP
// iTXt oFFs pCAL pHYs sBIT sCAL sPLT sRGB sTER tEXt tRNS zTXt
    if( !((isupper(buffer[i+4]) || islower(buffer[i+4])) &&
	  (isupper(buffer[i+5]) || islower(buffer[i+5])) &&
	  (isupper(buffer[i+6]) || islower(buffer[i+6])) &&
	  (isupper(buffer[i+7]) || islower(buffer[i+7]))))
    {
      file_recovery->offset_error=file_recovery->calculated_file_size+7;
      return DC_ERROR;
    }
    file_recovery->offset_ok=file_recovery->calculated_file_size+7;
    file_recovery->calculated_file_size+=12 + be32(chunk->length);
  }
  return DC_CONTINUE;
}

static void register_header_check_png(file_stat_t *file_stat)
{
  static const unsigned char png_header[8]= { 0x89, 'P', 'N','G', 0x0d, 0x0a, 0x1a, 0x0a};
  static const unsigned char mng_header[8]= { 0x8a, 'M', 'N','G', 0x0d, 0x0a, 0x1a, 0x0a};
  static const unsigned char jng_header[8]= { 0x8b, 'J', 'N','G', 0x0d, 0x0a, 0x1a, 0x0a};
  register_header_check(0, png_header, sizeof(png_header), &header_check_png, file_stat);
  register_header_check(0, mng_header, sizeof(mng_header), &header_check_mng, file_stat);
  register_header_check(0, jng_header, sizeof(jng_header), &header_check_jng, file_stat);
}
