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

static void register_header_check_tiff(file_stat_t *file_stat);

const file_hint_t file_hint_tiff= {
  .extension="tif",
  .description="Tag Image File Format and some raw file formats (pef/nef/dcr/sr2/cr2)",
  .max_filesize=100*1024*1024,
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

const char *find_tag_from_tiff_header(const TIFFHeader *tiff, const unsigned int tiff_size, const unsigned int tag, const char **potential_error)
{
  if(tiff->tiff_magic==TIFF_BIGENDIAN)
    return find_tag_from_tiff_header_be(tiff, tiff_size, tag, potential_error);
  else if(tiff->tiff_magic==TIFF_LITTLEENDIAN)
    return find_tag_from_tiff_header_le(tiff, tiff_size, tag, potential_error);
  return NULL;
}

time_t get_date_from_tiff_header(const TIFFHeader *tiff, const unsigned int tiff_size)
{
  const char *potential_error=NULL;
  const char *date_asc;
  /* DateTimeOriginal */
  date_asc=find_tag_from_tiff_header(tiff, tiff_size, 0x9003, &potential_error);
  /* DateTimeDigitalized*/
  if(date_asc==NULL || date_asc < (const char *)tiff || &date_asc[18] >= (const char *)tiff + tiff_size)
    date_asc=find_tag_from_tiff_header(tiff, tiff_size, 0x9004, &potential_error);
  if(date_asc==NULL || date_asc < (const char *)tiff || &date_asc[18] >= (const char *)tiff + tiff_size)
    date_asc=find_tag_from_tiff_header(tiff, tiff_size, 0x132, &potential_error);
  if(date_asc==NULL || date_asc < (const char *)tiff || &date_asc[18] >= (const char *)tiff + tiff_size)
    return (time_t)0;
  return get_time_from_YYYY_MM_DD_HH_MM_SS(date_asc);
}

static void register_header_check_tiff(file_stat_t *file_stat)
{
  static const unsigned char tiff_header_be[4]= { 'M','M',0x00, 0x2a};
  static const unsigned char tiff_header_le[4]= { 'I','I',0x2a, 0x00};
  register_header_check(0, tiff_header_be, sizeof(tiff_header_be), &header_check_tiff_be_new, file_stat);
  register_header_check(0, tiff_header_le, sizeof(tiff_header_le), &header_check_tiff_le_new, file_stat);
}

void file_check_tiff(file_recovery_t *fr)
{
  static uint64_t calculated_file_size=0;
  TIFFHeader header;
  calculated_file_size = 0;
  if(fseek(fr->handle, 0, SEEK_SET) < 0 ||
      fread(&header, sizeof(TIFFHeader), 1, fr->handle) != 1)
  {
    fr->file_size=0;
    return;
  }
  if(header.tiff_magic==TIFF_LITTLEENDIAN)
    calculated_file_size=header_check_tiff_le(fr, le32(header.tiff_diroff), 0, 0);
  else if(header.tiff_magic==TIFF_BIGENDIAN)
    calculated_file_size=header_check_tiff_be(fr, be32(header.tiff_diroff), 0, 0);
#ifdef DEBUG_TIFF
  log_info("TIFF Current   %llu\n", (unsigned long long)fr->file_size);
  log_info("TIFF Estimated %llu %llx\n", (unsigned long long)calculated_file_size, (unsigned long long)calculated_file_size);
#endif
  if(fr->file_size < calculated_file_size || calculated_file_size==0)
    fr->file_size=0;
    /* PhotoRec isn't yet capable to find the correct filesize for
     * Sony arw and dng,
     * Panasonic raw/rw2,
     * Minolta tif
     * Sony sr2
     * so don't truncate them */
  else if(strcmp(fr->extension,"cr2")==0 ||
      strcmp(fr->extension,"dcr")==0 ||
      strcmp(fr->extension,"nef")==0 ||
      strcmp(fr->extension,"orf")==0 ||
      strcmp(fr->extension,"pef")==0 ||
      (strcmp(fr->extension,"tif")==0 && calculated_file_size>1024*1024*1024) ||
      strcmp(fr->extension,"wdp")==0)
    fr->file_size=calculated_file_size;
}
