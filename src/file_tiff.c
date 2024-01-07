/*

    File: file_tiff.c

    Copyright (C) 1998-2005,2007-2009 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_tiff) || defined(SINGLE_FORMAT_jpg) || defined(SINGLE_FORMAT_rw2) || defined(SINGLE_FORMAT_orf) || defined(SINGLE_FORMAT_wdp)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <stdio.h>
#include "types.h"
#include "filegen.h"
#include "common.h"
#include "file_tiff.h"
#include "log.h"
#if defined(__FRAMAC__)
#include "__fc_builtin.h"
#endif

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_tiff(file_stat_t *file_stat);

const file_hint_t file_hint_tiff= {
  .extension="tif",
  .description="Tag Image File Format and some raw file formats (pef/nef/dcr/sr2/cr2)",
  .max_filesize=1024*1024*1024,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_tiff
};

unsigned int tiff_type2size(const unsigned int type)
{
  switch(type)
  {
    case 1:	/* TIFF_BYTE	*/
    case 2:	/* TIFF_ASCII	*/
    case 6:	/* TIFF_SBYTE	*/
    case 7:	/* TIFF_UNDEFINED */
      return 1;
    case 3:	/* TIFF_SHORT	*/
    case 8:	/* TIFF_SSHORT	*/
      return 2;
    case 4:	/* TIFF_LONG	*/
    case 9:	/* TIFF_SLONG	*/
    case 11:	/* TIFF_FLOAT	*/
    case 13:	/* TIFF_IFD	*/
      return 4;
    case 5:	/* TIFF_RATIONAL */
    case 10:	/* TIFF_SRATIONAL */
    case 12:	/* TIFF_DOUBLE	*/
    case 16:	/* TIFF_LONG8	*/
    case 17:	/* TIFF_SLONG8	*/
    case 18:	/* TIFF_IFD8	*/
      return 8;
#if 0
    case 14:	/* TIFF_UNICODE	*/
    case 15:	/* TIFF_COMPLEX */
#endif
    default:
      return 1;
  }
}

#ifdef DEBUG_TIFF
const char *tag_name(unsigned int tag)
{
  switch(tag)
  {
    case TIFFTAG_IMAGEDESCRIPTION:
      return "IMAGEDESCRIPTION";
    case TIFFTAG_MAKE:
      return "MAKE";
    case TIFFTAG_MODEL:
      return "TIFFTAG_MODEL";
    case TIFFTAG_SUBIFD:
      return "SUBIFD";
    case TIFFTAG_EXIFIFD:
       return "EXIFIFD";
    case TIFFTAG_STRIPOFFSETS:
       return "STRIPOFFSETS";
    case TIFFTAG_STRIPBYTECOUNTS:
       return "STRIPBYTECOUNTS";
    case TIFFTAG_KODAKIFD:
       return "KODAKIFD";
    case TIFFTAG_JPEGIFOFFSET:
       return "JPEGIFOFFSET";
    case TIFFTAG_JPEGIFBYTECOUNT:
       return "JPEGIFBYTECOUNT";
    case TIFFTAG_DNGPRIVATEDATA:
       return "DNGPRIVATEDATA";
    case EXIFTAG_MAKERNOTE:
       return "EXIFTAG_MAKERNOTE";
    case TIFFTAG_PRINTIM:
       return "PrintIM";
    case TIFFTAG_IMAGEOFFSET:
       return "IMAGEOFFSET";
    case TIFFTAG_IMAGEBYTECOUNT:
       return "IMAGEBYTECOUNT";
    case TIFFTAG_ALPHAOFFSET:
       return "ALPHAOFFSET";
    case TIFFTAG_ALPHABYTECOUNT:
       return "ALPHABYTECOUNT";
    case TIFFTAG_TILEOFFSETS:
       return "TileOffsets";
    case TIFFTAG_TILEBYTECOUNTS:
       return "TileByteCounts";
    default:
      return "";
  }
}
#endif

unsigned int find_tag_from_tiff_header(const unsigned char*buffer, const unsigned int buffer_size, const unsigned int tag, const unsigned char **potential_error)
{
  const TIFFHeader *tiff=(const TIFFHeader *)buffer;
  /*@ assert sizeof(TIFFHeader) <= sizeof(struct ifd_header); */
  if(buffer_size < sizeof(struct ifd_header))
    return 0;
  /*@ assert buffer_size >= sizeof(TIFFHeader); */
  /*@ assert buffer_size >= sizeof(struct ifd_header); */
  /*@ assert \valid_read(tiff); */
#ifndef MAIN_tiff_le
  if(tiff->tiff_magic==TIFF_BIGENDIAN)
    return find_tag_from_tiff_header_be(buffer, buffer_size, tag, potential_error);
#endif
#ifndef MAIN_tiff_be
  if(tiff->tiff_magic==TIFF_LITTLEENDIAN)
    return find_tag_from_tiff_header_le(buffer, buffer_size, tag, potential_error);
#endif
  return 0;
}

time_t get_date_from_tiff_header(const unsigned char *buffer, const unsigned int buffer_size)
{
  const unsigned char *potential_error=NULL;
  unsigned int date_asc=0;
  time_t tmp;
  /*@ assert \valid_read(buffer+(0..buffer_size-1)); */
  /*@ assert sizeof(TIFFHeader) <= sizeof(struct ifd_header); */
  if(buffer_size < sizeof(struct ifd_header) || buffer_size < 19)
    return (time_t)0;
  /*@ assert buffer_size >= sizeof(TIFFHeader); */
  /*@ assert buffer_size >= sizeof(struct ifd_header); */
  /* DateTimeOriginal */
  date_asc=find_tag_from_tiff_header(buffer, buffer_size, 0x9003, &potential_error);
  /* DateTimeDigitalized*/
  if(date_asc==0 || date_asc >  buffer_size - 19)
    date_asc=find_tag_from_tiff_header(buffer, buffer_size, 0x9004, &potential_error);
  if(date_asc==0 || date_asc >  buffer_size - 19)
    date_asc=find_tag_from_tiff_header(buffer, buffer_size, 0x132, &potential_error);
  if(date_asc==0 || date_asc >  buffer_size - 19)
    return (time_t)0;
  tmp=get_time_from_YYYY_MM_DD_HH_MM_SS(&buffer[date_asc]);
  /*@ assert \valid_read(buffer+(0..buffer_size-1)); */
  return tmp;
}

static void register_header_check_tiff(file_stat_t *file_stat)
{
  static const unsigned char tiff_header_be[4]= { 'M','M',0x00, 0x2a};
  static const unsigned char tiff_header_le[4]= { 'I','I',0x2a, 0x00};
#if !defined(SINGLE_FORMAT_jpg) && !defined(SINGLE_FORMAT_rw2) && !defined(SINGLE_FORMAT_orf) && !defined(SINGLE_FORMAT_wdp)
#if !defined(MAIN_tiff_le) && !defined(MAIN_jpg)
  register_header_check(0, tiff_header_be, sizeof(tiff_header_be), &header_check_tiff_be, file_stat);
#endif
#if !defined(MAIN_tiff_be) && !defined(MAIN_jpg)
  register_header_check(0, tiff_header_le, sizeof(tiff_header_le), &header_check_tiff_le, file_stat);
#endif
#endif
}
#endif
