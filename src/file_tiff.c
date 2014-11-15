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

extern const file_hint_t file_hint_raf;

static void register_header_check_tiff(file_stat_t *file_stat);
static uint64_t header_check_tiff_be(file_recovery_t *fr, const uint32_t tiff_diroff, const unsigned int depth, const unsigned int count, const char *tag_make);
static uint64_t header_check_tiff_le(file_recovery_t *fr, const uint32_t tiff_diroff, const unsigned int depth, const unsigned int count, const char *tag_make);

const file_hint_t file_hint_tiff= {
  .extension="tif",
  .description="Tag Image File Format and some raw file formats (pef/nef/dcr/sr2/cr2)",
  .min_header_distance=0,
  .max_filesize=100*1024*1024,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_tiff
};

static unsigned int type2size(const unsigned int type)
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
    default:
//    case 14:	/* TIFF_UNICODE	*/
//    case 15:	/* TIFF_COMPLEX */
      return 1;
  }
}

#ifdef DEBUG_TIFF
static const char *tag_name(unsigned int tag)
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

static const char *find_tag_from_tiff_header_be(const TIFFHeader *tiff, const unsigned int tiff_size, const unsigned int tag, const char**potential_error)
{
  const struct ifd_header *ifd0=(const struct ifd_header *)((const char*)tiff + be32(tiff->tiff_diroff));
  const struct ifd_header *exififd=NULL;
  const uint32_t *tiff_next_diroff;
  const TIFFDirEntry *ifd;
  unsigned int j;
  if(tiff_size < sizeof(TIFFHeader))
    return NULL;
  if(tiff_size < be32(tiff->tiff_diroff)+sizeof(TIFFDirEntry))
    return NULL;
  /* Bound checking */
  if((const char*)ifd0 < (const char*)tiff ||
      (const char*)(ifd0+1) > (const char*)tiff + tiff_size)
    return NULL;
  for(j=0, ifd=&ifd0->ifd;
      (const char*)(ifd+1) <= (const char*)tiff+tiff_size && j<(uint16_t)be16(ifd0->nbr_fields);
      j++, ifd++)
  {
    if(be16(ifd->tdir_type) > 18 && (*potential_error==NULL || *potential_error > (const char*)&ifd->tdir_type+1))
      *potential_error = (const char*)&ifd->tdir_type+1;
    if((uint16_t)be16(ifd->tdir_tag)==tag)
      return (const char*)tiff+be32(ifd->tdir_offset);
    else if(be16(ifd->tdir_tag)==TIFFTAG_EXIFIFD)	/* Exif IFD Pointer */
      exififd=(const struct ifd_header *)((const char*)tiff + be32(ifd->tdir_offset));
  }
  tiff_next_diroff=(const uint32_t *)ifd;
  if(exififd!=NULL &&
      (const char*)exififd > (const char*)tiff &&
      (const char*)(exififd+1) <= (const char*)tiff + tiff_size)
  {	/* Exif */
    const unsigned int nbr_fields=be16(exififd->nbr_fields);
    for(j=0, ifd=&exififd->ifd;
	(const char*)(ifd+1) <= (const char*)tiff+tiff_size && j<nbr_fields;
	j++, ifd++)
    {
      if(be16(ifd->tdir_type) > 18 && (*potential_error==NULL || *potential_error > (const char*)&ifd->tdir_type+1))
	*potential_error = (const char*)&ifd->tdir_type+1;
      if((uint16_t)be16(ifd->tdir_tag)==tag)
	return (const char*)tiff+be32(ifd->tdir_offset);
    }
  }
  /* IFD1 */
  if(be32(*tiff_next_diroff)>0)
  {
    const struct ifd_header *ifd1=(const struct ifd_header*)((const char *)tiff+be32(*tiff_next_diroff));
    const unsigned int nbr_fields=be16(ifd1->nbr_fields);
    if((const char*)ifd1 <= (const char*)tiff ||
	(const char*)(ifd1+1) > (const char*)tiff+tiff_size)
      return NULL;
    for(j=0, ifd=&ifd1->ifd;
	(const char*)(ifd+1) <= (const char*)tiff+tiff_size && j<nbr_fields;
	j++, ifd++)
    {
      if(be16(ifd->tdir_type) > 18 && (*potential_error==NULL || *potential_error > (const char*)&ifd->tdir_type+1))
	*potential_error = (const char*)&ifd->tdir_type+1;
      if((uint16_t)be16(ifd->tdir_tag)==tag)
	return (const char*)tiff+be32(ifd->tdir_offset);
    }
  }
  return NULL;
}

static const char *find_tag_from_tiff_header_le(const TIFFHeader *tiff, const unsigned int tiff_size, const unsigned int tag, const char**potential_error)
{
  const struct ifd_header *ifd0=(const struct ifd_header *)((const char*)tiff + le32(tiff->tiff_diroff));
  const struct ifd_header *exififd=NULL;
  const uint32_t *tiff_next_diroff;
  const TIFFDirEntry *ifd;
  unsigned int j;
  if(tiff_size < sizeof(TIFFHeader))
    return NULL;
  if(tiff_size < le32(tiff->tiff_diroff)+sizeof(TIFFDirEntry))
    return NULL;
  /* Bound checking */
  if((const char*)ifd0 < (const char*)tiff ||
      (const char*)(ifd0+1) > (const char*)tiff + tiff_size)
    return NULL;
  for(j=0, ifd=&ifd0->ifd;
      (const char*)(ifd+1) <= (const char*)tiff+tiff_size && j<le16(ifd0->nbr_fields);
      j++, ifd++)
  {
    if(le16(ifd->tdir_type) > 18 && (*potential_error==NULL || *potential_error > (const char*)&ifd->tdir_type+1))
      *potential_error = (const char*)&ifd->tdir_type+1;
    if(le16(ifd->tdir_tag)==tag)
      return (const char*)tiff+le32(ifd->tdir_offset);
    else if(le16(ifd->tdir_tag)==TIFFTAG_EXIFIFD)	/* Exif IFD Pointer */
      exififd=(const struct ifd_header *)((const char*)tiff + le32(ifd->tdir_offset));
  }
  tiff_next_diroff=(const uint32_t *)ifd;
  if(exififd!=NULL &&
      (const char*)exififd > (const char*)tiff &&
      (const char*)(exififd+1) <= (const char*)tiff + tiff_size)
  {	/* Exif */
    for(j=0, ifd=&exififd->ifd;
	(const char*)(ifd+1) <= (const char*)tiff+tiff_size && j<le16(exififd->nbr_fields);
	j++, ifd++)
    {
      if(le16(ifd->tdir_type) > 18 && (*potential_error==NULL || *potential_error > (const char*)&ifd->tdir_type+1))
	*potential_error = (const char*)&ifd->tdir_type+1;
      if(le16(ifd->tdir_tag)==tag)		/* DateTimeOriginal */
	return (const char*)tiff+le32(ifd->tdir_offset);
    }
  }
  /* IFD1 */
  if(le32(*tiff_next_diroff)>0)
  {
    const struct ifd_header *ifd1=(const struct ifd_header*)((const char *)tiff+le32(*tiff_next_diroff));
    /* Bound checking */
    if((const char*)(ifd1) <= (const char*)tiff ||
	(const char*)(ifd1+1) > (const char*)tiff+tiff_size)
      return NULL;
    for(j=0, ifd=&ifd1->ifd;
	(const char*)(ifd+1) <= (const char*)tiff+tiff_size && j<le16(ifd1->nbr_fields);
	j++, ifd++)
    {
      if(le16(ifd->tdir_type) > 18 && (*potential_error==NULL || *potential_error > (const char*)&ifd->tdir_type+1))
	*potential_error = (const char*)&ifd->tdir_type+1;
      if(le16(ifd->tdir_tag)==tag)
	return (const char*)tiff+le32(ifd->tdir_offset);
    }
  }
  return NULL;
}

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
  struct tm tm_time;
  /* DateTimeOriginal */
  date_asc=find_tag_from_tiff_header(tiff, tiff_size, 0x9003, &potential_error);
  /* DateTimeDigitalized*/
  if(date_asc==NULL || date_asc < (const char *)tiff || &date_asc[18] >= (const char *)tiff + tiff_size)
    date_asc=find_tag_from_tiff_header(tiff, tiff_size, 0x9004, &potential_error);
  if(date_asc==NULL || date_asc < (const char *)tiff || &date_asc[18] >= (const char *)tiff + tiff_size)
    date_asc=find_tag_from_tiff_header(tiff, tiff_size, 0x132, &potential_error);
  if(date_asc==NULL || date_asc < (const char *)tiff || &date_asc[18] >= (const char *)tiff + tiff_size)
    return (time_t)0;
  if(memcmp(date_asc, "0000", 4)==0)
    return (time_t)0;
  memset(&tm_time, 0, sizeof(tm_time));
  tm_time.tm_sec=(date_asc[17]-'0')*10+(date_asc[18]-'0');      /* seconds 0-59 */
  tm_time.tm_min=(date_asc[14]-'0')*10+(date_asc[15]-'0');      /* minutes 0-59 */
  tm_time.tm_hour=(date_asc[11]-'0')*10+(date_asc[12]-'0');     /* hours   0-23*/
  tm_time.tm_mday=(date_asc[8]-'0')*10+(date_asc[9]-'0');	/* day of the month 1-31 */
  tm_time.tm_mon=(date_asc[5]-'0')*10+(date_asc[6]-'0')-1;	/* month 0-11 */
  tm_time.tm_year=(date_asc[0]-'0')*1000+(date_asc[1]-'0')*100+
    (date_asc[2]-'0')*10+(date_asc[3]-'0')-1900;        	/* year */
  tm_time.tm_isdst = -1;		/* unknown daylight saving time */
  return mktime(&tm_time);
}

static int header_check_tiff_be_new(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const char *potential_error=NULL;
  const char *tag_make;
  const TIFFHeader *header=(const TIFFHeader *)buffer;
  if((uint32_t)be32(header->tiff_diroff) < sizeof(TIFFHeader))
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_tiff.extension;
  tag_make=find_tag_from_tiff_header_be(header, buffer_size, TIFFTAG_MAKE, &potential_error);
  if(tag_make!=NULL && tag_make >= (const char *)buffer && tag_make < (const char *)buffer + buffer_size - 20)
  {
    if(strcmp(tag_make, "PENTAX Corporation ")==0 ||
	strcmp(tag_make, "PENTAX             ")==0)
      file_recovery_new->extension="pef";
    else if(strcmp(tag_make, "NIKON CORPORATION")==0)
      file_recovery_new->extension="nef";
    else if(strcmp(tag_make, "Kodak")==0)
      file_recovery_new->extension="dcr";
  }
  file_recovery_new->time=get_date_from_tiff_header(header, buffer_size);
  file_recovery_new->file_check=&file_check_tiff;
  return 1;
}

static int header_check_tiff_le_new(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const char raf_fp[15]={0x49, 0x49, 0x2a, 0x00, 0x08, 0x00, 0x00, 0x00,  0x01, 0x00, 0x00, 0xf0, 0x0d, 0x00, 0x01};
  const char *potential_error=NULL;
  const TIFFHeader *header=(const TIFFHeader *)buffer;
  if((uint32_t)le32(header->tiff_diroff) < sizeof(TIFFHeader))
    return 0;
  /* Avoid a false positiv with some RAF files */
  if(file_recovery->file_stat!=NULL &&
    file_recovery->file_stat->file_hint==&file_hint_raf &&
    memcmp(buffer, raf_fp, 15)==0)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_tiff.extension;
  /* Canon RAW */
  if(buffer[8]=='C' && buffer[9]=='R' && buffer[10]==2)
    file_recovery_new->extension="cr2";
  else if(find_tag_from_tiff_header_le(header, buffer_size, TIFFTAG_DNGVERSION, &potential_error)!=NULL)
  {
    /* Adobe Digital Negative */
    file_recovery_new->extension="dng";
  }
  else
  {
    const char *tag_make;
    tag_make=find_tag_from_tiff_header_le(header, buffer_size, TIFFTAG_MAKE, &potential_error);
    if(tag_make!=NULL && tag_make >= (const char *)buffer && tag_make < (const char *)buffer + buffer_size - 20)
    {
      if(strcmp(tag_make, "SONY")==0)
	file_recovery_new->extension="sr2";
      else if(strncmp(tag_make, "SONY ",5)==0)
	file_recovery_new->extension="arw";
    }
  }
  file_recovery_new->time=get_date_from_tiff_header(header, buffer_size);
  file_recovery_new->file_check=&file_check_tiff;
  return 1;
}

static void register_header_check_tiff(file_stat_t *file_stat)
{
  static const unsigned char tiff_header_be[4]= { 'M','M',0x00, 0x2a};
  static const unsigned char tiff_header_le[4]= { 'I','I',0x2a, 0x00};
  register_header_check(0, tiff_header_be, sizeof(tiff_header_be), &header_check_tiff_be_new, file_stat);
  register_header_check(0, tiff_header_le, sizeof(tiff_header_le), &header_check_tiff_le_new, file_stat);
}

static unsigned int tiff_le_read(const void *val, const unsigned int type)
{
  switch(type)
  {
    case 1:
      return *((const uint8_t*)val);
    case 3:
      return le16(*((const uint16_t*)val));
    case 4:
      return le32(*((const uint32_t*)val));
    default:
      return 0;
  }
}

static unsigned int tiff_be_read(const void *val, const unsigned int type)
{
  switch(type)
  {
    case 1:
      return *((const uint8_t*)val);
    case 3:
      return be16(*((const uint16_t*)val));
    case 4:
      return be32(*((const uint32_t*)val));
    default:
      return 0;
  }
}

static uint64_t parse_strip_le(FILE *handle, const TIFFDirEntry *entry_strip_offsets, const TIFFDirEntry *entry_strip_bytecounts)
{
  const unsigned int nbr=(le32(entry_strip_offsets->tdir_count)<2048?
      le32(entry_strip_offsets->tdir_count):
      2048);
  unsigned int i;
  uint32_t *offsetp;
  uint32_t *sizep;
  uint64_t max_offset=0;
  if(le32(entry_strip_offsets->tdir_count) != le32(entry_strip_bytecounts->tdir_count))
    return -1;
  if(le32(entry_strip_offsets->tdir_count)==0 ||
      le16(entry_strip_offsets->tdir_type)!=4 ||
      le16(entry_strip_bytecounts->tdir_type)!=4)
    return -1;
  offsetp=(uint32_t *)MALLOC(nbr*sizeof(*offsetp));
  if(fseek(handle, le32(entry_strip_offsets->tdir_offset), SEEK_SET) < 0 ||
      fread(offsetp, sizeof(*offsetp), nbr, handle) != nbr)
  {
    free(offsetp);
    return -1;
  }
  sizep=(uint32_t *)MALLOC(nbr*sizeof(*sizep));
  if(fseek(handle, le32(entry_strip_bytecounts->tdir_offset), SEEK_SET) < 0 ||
      fread(sizep, sizeof(*sizep), nbr, handle) != nbr)
  {
    free(offsetp);
    free(sizep);
    return -1;
  }
  for(i=0; i<nbr; i++)
  {
    const uint64_t tmp=le32(offsetp[i]) + le32(sizep[i]);
    if(max_offset < tmp)
      max_offset=tmp;
  }
  free(offsetp);
  free(sizep);
  return max_offset;
}

static uint64_t parse_strip_be(FILE *handle, const TIFFDirEntry *entry_strip_offsets, const TIFFDirEntry *entry_strip_bytecounts)
{
  const unsigned int nbr=(be32(entry_strip_offsets->tdir_count)<2048?
      be32(entry_strip_offsets->tdir_count):
      2048);
  unsigned int i;
  uint32_t *offsetp;
  uint32_t *sizep;
  uint64_t max_offset=0;
  if(be32(entry_strip_offsets->tdir_count) != be32(entry_strip_bytecounts->tdir_count))
    return -1;
  if(be32(entry_strip_offsets->tdir_count)==0 ||
      be16(entry_strip_offsets->tdir_type)!=4 ||
      be16(entry_strip_bytecounts->tdir_type)!=4)
    return -1;
  offsetp=(uint32_t *)MALLOC(nbr*sizeof(*offsetp));
  if(fseek(handle, be32(entry_strip_offsets->tdir_offset), SEEK_SET) < 0 ||
      fread(offsetp, sizeof(*offsetp), nbr, handle) != nbr)
  {
    free(offsetp);
    return -1;
  }
  sizep=(uint32_t *)MALLOC(nbr*sizeof(*sizep));
  if(fseek(handle, be32(entry_strip_bytecounts->tdir_offset), SEEK_SET) < 0 ||
      fread(sizep, sizeof(*sizep), nbr, handle) != nbr)
  {
    free(offsetp);
    free(sizep);
    return -1;
  }
  for(i=0; i<nbr; i++)
  {
    const uint64_t tmp=be32(offsetp[i]) + be32(sizep[i]);
    if(max_offset < tmp)
      max_offset=tmp;
  }
  free(offsetp);
  free(sizep);
  return max_offset;
}

#ifdef ENABLE_TIFF_MAKERNOTE
static uint64_t tiff_le_makernote(FILE *in, const uint32_t tiff_diroff)
{
  const unsigned char sign_nikon1[7]={'N', 'i', 'k', 'o', 'n', 0x00, 0x01};
  const unsigned char sign_nikon2[7]={'N', 'i', 'k', 'o', 'n', 0x00, 0x02};
  const unsigned char sign_pentax[4]={'A', 'O', 'C', 0x00};
  unsigned char buffer[8192];
  unsigned int i,n;
  int data_read;
  uint64_t max_offset=0;
  uint64_t alphaoffset=0;
  uint64_t alphabytecount=0;
  uint64_t imageoffset=0;
  uint64_t imagebytecount=0;
  uint64_t jpegifoffset=0;
  uint64_t jpegifbytecount=0;
  uint64_t strip_offsets=0;
  uint64_t strip_bytecounts=0;
  uint64_t tile_offsets=0;
  uint64_t tile_bytecounts=0;
  const TIFFDirEntry *entry;
  if(tiff_diroff < sizeof(TIFFHeader))
    return -1;
  if(fseek(in, tiff_diroff, SEEK_SET) < 0)
    return -1;
  data_read=fread(buffer, 1, sizeof(buffer), in);
  if(data_read<2)
    return -1;
  if( memcmp(buffer, sign_nikon1, sizeof(sign_nikon1))==0 ||
      memcmp(buffer, sign_nikon2, sizeof(sign_nikon2))==0 ||
      memcmp(buffer, sign_pentax, sizeof(sign_pentax))==0 )
    return tiff_diroff;
  entry=(const TIFFDirEntry *)&buffer[2];
  n=buffer[0]+(buffer[1]<<8);
#ifdef DEBUG_TIFF
  log_info("tiff_le_makernote(%lu) => %u entries\n", (long unsigned)tiff_diroff, n);
#endif
  //sizeof(TIFFDirEntry)=12;
  if(n > (unsigned)(data_read-2)/12)
    n=(data_read-2)/12;
  if(n==0)
    return -1;
  for(i=0;i<n;i++)
  {
    const uint64_t val=(uint64_t)le32(entry->tdir_count)*type2size(le16(entry->tdir_type));
#ifdef DEBUG_TIFF
    log_info("%u tag=%u(0x%x) %s type=%u count=%lu offset=%lu(0x%lx)\n",
	i,
	le16(entry->tdir_tag),
	le16(entry->tdir_tag),
	tag_name(le16(entry->tdir_tag)),
	le16(entry->tdir_type),
	(long unsigned)le32(entry->tdir_count),
	(long unsigned)le32(entry->tdir_offset),
	(long unsigned)le32(entry->tdir_offset));
#endif
    if(val>4)
    {
      const uint64_t new_offset=le32(entry->tdir_offset)+val;
      if(new_offset==0)
	return -1;
      if(max_offset < new_offset)
	max_offset=new_offset;
    }
    if(le32(entry->tdir_count)==1)
    {
      const unsigned int tmp=tiff_le_read(&entry->tdir_offset, le16(entry->tdir_type));
      switch(le16(entry->tdir_tag))
      {
	case TIFFTAG_JPEGIFOFFSET: 	jpegifoffset=tmp;	break;
	case TIFFTAG_JPEGIFBYTECOUNT:	jpegifbytecount=tmp;	break;
	case TIFFTAG_ALPHAOFFSET:	alphaoffset=tmp;	break;
	case TIFFTAG_ALPHABYTECOUNT:	alphabytecount=tmp;	break;
	case TIFFTAG_IMAGEOFFSET:	imageoffset=tmp;	break;
	case TIFFTAG_IMAGEBYTECOUNT:	imagebytecount=tmp;	break;
	case TIFFTAG_STRIPOFFSETS:	strip_offsets=tmp;	break;
	case TIFFTAG_STRIPBYTECOUNTS:	strip_bytecounts=tmp;	break;
	case TIFFTAG_TILEBYTECOUNTS:	tile_bytecounts=tmp;	break;
	case TIFFTAG_TILEOFFSETS:	tile_offsets=tmp;	break;
      }
    }
    entry++;
  }
  if(alphabytecount > 0 && max_offset < alphaoffset + alphabytecount)
    max_offset = alphaoffset + alphabytecount;
  if(imagebytecount > 0 && max_offset < imageoffset + imagebytecount)
    max_offset = imageoffset + imagebytecount;
  if(jpegifbytecount > 0 && max_offset < jpegifoffset + jpegifbytecount)
    max_offset = jpegifoffset + jpegifbytecount;
  if(strip_bytecounts > 0 && strip_offsets!=0xffffffff &&
      max_offset < strip_offsets + strip_bytecounts)
    max_offset = strip_offsets + strip_bytecounts;
  if(tile_bytecounts > 0 && tile_offsets!=0xffffffff &&
      max_offset < tile_offsets + tile_bytecounts)
    max_offset = tile_offsets + tile_bytecounts;
  return max_offset;
}
#endif

static uint64_t header_check_tiff_le(file_recovery_t *fr, const uint32_t tiff_diroff, const unsigned int depth, const unsigned int count, const char *tag_make)
{
  unsigned char buffer[8192];
  unsigned int i,n;
  int data_read;
  const uint32_t *tiff_next_diroff;
  uint64_t max_offset=0;
  uint64_t alphaoffset=0;
  uint64_t alphabytecount=0;
  uint64_t imageoffset=0;
  uint64_t imagebytecount=0;
  uint64_t jpegifoffset=0;
  uint64_t jpegifbytecount=0;
  uint64_t strip_offsets=0;
  uint64_t strip_bytecounts=0;
  uint64_t tile_offsets=0;
  uint64_t tile_bytecounts=0;
  const TIFFDirEntry *entry=(const TIFFDirEntry *)&buffer[2];
  const TIFFDirEntry *entry_strip_offsets=NULL;
  const TIFFDirEntry *entry_strip_bytecounts=NULL;
  const TIFFDirEntry *entry_tile_offsets=NULL;
  const TIFFDirEntry *entry_tile_bytecounts=NULL;
#ifdef DEBUG_TIFF
  log_info("header_check_tiff_le(fr, %lu, %u, %u)\n", (long unsigned)tiff_diroff, depth, count);
#endif
  if(depth>4)
    return -1;
  if(count>16)
    return -1;
  if(tiff_diroff < sizeof(TIFFHeader))
    return -1;
  if(fseek(fr->handle, tiff_diroff, SEEK_SET) < 0)
    return -1;
  data_read=fread(buffer, 1, sizeof(buffer), fr->handle);
  if(data_read<2)
    return -1;
  n=buffer[0]+(buffer[1]<<8);
#ifdef DEBUG_TIFF
  log_info("header_check_tiff_le(fr, %lu, %u, %u) => %u entries\n", (long unsigned)tiff_diroff, depth, count, n);
#endif
  //sizeof(TIFFDirEntry)=12;
  if(n > (unsigned)(data_read-2)/12)
    n=(data_read-2)/12;
  if(n==0)
    return -1;
  for(i=0;i<n;i++)
  {
    const uint64_t val=(uint64_t)le32(entry->tdir_count)*type2size(le16(entry->tdir_type));
#ifdef DEBUG_TIFF
    log_info("%u tag=%u(0x%x) %s type=%u count=%lu offset=%lu(0x%lx) val=%lu\n",
	i,
	le16(entry->tdir_tag),
	le16(entry->tdir_tag),
	tag_name(le16(entry->tdir_tag)),
	le16(entry->tdir_type),
	(long unsigned)le32(entry->tdir_count),
	(long unsigned)le32(entry->tdir_offset),
	(long unsigned)le32(entry->tdir_offset),
	(long unsigned)val);
#endif
    if(val>4)
    {
      const uint64_t new_offset=le32(entry->tdir_offset)+val;
      if(new_offset==0)
	return -1;
      if(max_offset < new_offset)
	max_offset=new_offset;
    }
    if(le32(entry->tdir_count)==1 && val<=4)
    {
      const unsigned int tmp=tiff_le_read(&entry->tdir_offset, le16(entry->tdir_type));
      switch(le16(entry->tdir_tag))
      {
	case TIFFTAG_ALPHABYTECOUNT:	alphabytecount=tmp;	break;
	case TIFFTAG_ALPHAOFFSET:	alphaoffset=tmp;	break;
	case TIFFTAG_IMAGEBYTECOUNT:	imagebytecount=tmp;	break;
	case TIFFTAG_IMAGEOFFSET:	imageoffset=tmp;	break;
	case TIFFTAG_JPEGIFBYTECOUNT:	jpegifbytecount=tmp;	break;
	case TIFFTAG_JPEGIFOFFSET: 	jpegifoffset=tmp;	break;
	case TIFFTAG_STRIPBYTECOUNTS:	strip_bytecounts=tmp;	break;
	case TIFFTAG_STRIPOFFSETS:	strip_offsets=tmp;	break;
	case TIFFTAG_TILEBYTECOUNTS:	tile_bytecounts=tmp;	break;
	case TIFFTAG_TILEOFFSETS:	tile_offsets=tmp;	break;
	case TIFFTAG_EXIFIFD:
	case TIFFTAG_KODAKIFD:
	  {
	    const uint64_t new_offset=header_check_tiff_le(fr, tmp, depth+1, 0, tag_make);
	    if(new_offset==-1)
	      return -1;
	    if(max_offset < new_offset)
	      max_offset=new_offset;
	  }
	  break;
	case TIFFTAG_SUBIFD:
#if 1
	  if(fr->extension!=NULL && strcmp(fr->extension, "arw")==0)
	  {
	    /* DSLR-A100 is boggus, may be A100DataOffset */
	    const uint64_t new_offset=tmp;
	    if(max_offset < new_offset)
	      max_offset=new_offset;
	  }
	  else
#endif
	  {
	    const uint64_t new_offset=header_check_tiff_le(fr, tmp, depth+1, 0, tag_make);
	    if(new_offset==-1)
	      return -1;
	    if(max_offset < new_offset)
	      max_offset=new_offset;
	  }
	  break;
#ifdef ENABLE_TIFF_MAKERNOTE
	case EXIFTAG_MAKERNOTE:
	  {
	    const uint64_t new_offset=tiff_le_makernote(fr->handle, tmp);
	    if(new_offset==-1)
	      return -1;
	    if(max_offset < new_offset)
	      max_offset=new_offset;
	  }
	  break;
#endif
      }
    }
    else if(le32(entry->tdir_count) > 1)
    {
      switch(le16(entry->tdir_tag))
      {
	case TIFFTAG_EXIFIFD:
	case TIFFTAG_KODAKIFD:
	case TIFFTAG_SUBIFD:
	  if(le16(entry->tdir_type)==4)
	  {
	    const unsigned int nbr=(le32(entry->tdir_count)<32?le32(entry->tdir_count):32);
	    unsigned int j;
	    uint32_t *subifd_offsetp;
	    if(fseek(fr->handle, le32(entry->tdir_offset), SEEK_SET) < 0)
	    {
	      return -1;
	    }
	    subifd_offsetp=(uint32_t *)MALLOC(nbr*sizeof(*subifd_offsetp));
	    if(fread(subifd_offsetp, sizeof(*subifd_offsetp), nbr, fr->handle) != nbr)
	    {
	      free(subifd_offsetp);
	      return -1;
	    }
	    for(j=0; j<nbr; j++)
	    {
	      const uint64_t new_offset=header_check_tiff_le(fr, le32(subifd_offsetp[j]), depth+1, 0, tag_make);
	      if(new_offset==-1)
	      {
		free(subifd_offsetp);
		return -1;
	      }
	      if(max_offset < new_offset)
		max_offset = new_offset;
	    }
	    free(subifd_offsetp);
	  }
	  break;
	case TIFFTAG_STRIPOFFSETS:
	  entry_strip_offsets=entry;
	  break;
	case TIFFTAG_STRIPBYTECOUNTS:
	  entry_strip_bytecounts=entry;
	  break;
	case TIFFTAG_TILEBYTECOUNTS:
	  entry_tile_bytecounts=entry;
	  break;
	case TIFFTAG_TILEOFFSETS:
	  entry_tile_offsets=entry;
	  break;
      }
    }
    entry++;
  }
  if(alphabytecount > 0 && max_offset < alphaoffset + alphabytecount)
    max_offset = alphaoffset + alphabytecount;
  if(imagebytecount > 0 && max_offset < imageoffset + imagebytecount)
    max_offset = imageoffset + imagebytecount;
  if(jpegifbytecount > 0 && max_offset < jpegifoffset + jpegifbytecount)
    max_offset = jpegifoffset + jpegifbytecount;
  if(strip_bytecounts > 0 && strip_offsets!=0xffffffff &&
      max_offset < strip_offsets + strip_bytecounts)
    max_offset = strip_offsets + strip_bytecounts;
  if(tile_bytecounts > 0 && tile_offsets!=0xffffffff &&
      max_offset < tile_offsets + tile_bytecounts)
    max_offset = tile_offsets + tile_bytecounts;
  if(entry_strip_offsets != NULL && entry_strip_bytecounts != NULL)
  {
    const uint64_t tmp=parse_strip_le(fr->handle, entry_strip_offsets, entry_strip_bytecounts);
    if(tmp==-1)
      return -1;
    if(max_offset < tmp)
      max_offset=tmp;
  }
  if(entry_tile_offsets != NULL && entry_tile_bytecounts != NULL)
  {
    const uint64_t tmp=parse_strip_le(fr->handle, entry_tile_offsets, entry_tile_bytecounts);
    if(tmp==-1)
      return -1;
    if(max_offset < tmp)
      max_offset=tmp;
  }
  tiff_next_diroff=(const uint32_t *)entry;
  if(le32(*tiff_next_diroff) > 0)
  {
    const uint64_t new_offset=header_check_tiff_le(fr, le32(*tiff_next_diroff), depth, count+1, tag_make);
    if(new_offset != -1 && max_offset < new_offset)
      max_offset=new_offset;
  }
  return max_offset;
}

#ifdef ENABLE_TIFF_MAKERNOTE
static uint64_t tiff_be_makernote(FILE *in, const uint32_t tiff_diroff)
{
  const unsigned char sign_nikon1[7]={'N', 'i', 'k', 'o', 'n', 0x00, 0x01};
  const unsigned char sign_nikon2[7]={'N', 'i', 'k', 'o', 'n', 0x00, 0x02};
  const unsigned char sign_pentax[4]={'A', 'O', 'C', 0x00};
  unsigned char buffer[8192];
  unsigned int i,n;
  int data_read;
  uint64_t max_offset=0;
  uint64_t alphaoffset=0;
  uint64_t alphabytecount=0;
  uint64_t imageoffset=0;
  uint64_t imagebytecount=0;
  uint64_t jpegifoffset=0;
  uint64_t jpegifbytecount=0;
  uint64_t strip_offsets=0;
  uint64_t strip_bytecounts=0;
  uint64_t tile_offsets=0;
  uint64_t tile_bytecounts=0;
  const TIFFDirEntry *entry;
  if(tiff_diroff < sizeof(TIFFHeader))
    return -1;
  if(fseek(in, tiff_diroff, SEEK_SET) < 0)
    return -1;
  data_read=fread(buffer, 1, sizeof(buffer), in);
  if(data_read<2)
    return -1;
  if( memcmp(buffer, sign_nikon1, sizeof(sign_nikon1))==0 ||
      memcmp(buffer, sign_nikon2, sizeof(sign_nikon2))==0 ||
      memcmp(buffer, sign_pentax, sizeof(sign_pentax))==0 )
    return tiff_diroff;
  entry=(const TIFFDirEntry *)&buffer[2];
  n=(buffer[0]<<8)+buffer[1];
#ifdef DEBUG_TIFF
  log_info("tiff_be_makernote(%lu) => %u entries\n", (long unsigned)tiff_diroff, n);
#endif
  //sizeof(TIFFDirEntry)=12;
  if(n > (unsigned)(data_read-2)/12)
    n=(data_read-2)/12;
  if(n==0)
    return -1;
  for(i=0;i<n;i++)
  {
    const uint64_t val=(uint64_t)be32(entry->tdir_count)*type2size(be16(entry->tdir_type));
#ifdef DEBUG_TIFF
    log_info("%u tag=%u(0x%x) %s type=%u count=%lu offset=%lu(0x%lx)\n",
	i,
	be16(entry->tdir_tag),
	be16(entry->tdir_tag),
	tag_name(be16(entry->tdir_tag)),
	be16(entry->tdir_type),
	(long unsigned)be32(entry->tdir_count),
	(long unsigned)be32(entry->tdir_offset),
	(long unsigned)be32(entry->tdir_offset));
#endif
    if(val>4)
    {
      const uint64_t new_offset=be32(entry->tdir_offset)+val;
      if(new_offset==0)
	return -1;
      if(max_offset < new_offset)
	max_offset=new_offset;
    }
    if(be32(entry->tdir_count)==1)
    {
      const unsigned int tmp=tiff_be_read(&entry->tdir_offset, be16(entry->tdir_type));
      switch(be16(entry->tdir_tag))
      {
	case TIFFTAG_JPEGIFOFFSET: 	jpegifoffset=tmp;	break;
	case TIFFTAG_JPEGIFBYTECOUNT:	jpegifbytecount=tmp;	break;
	case TIFFTAG_ALPHAOFFSET:	alphaoffset=tmp;	break;
	case TIFFTAG_ALPHABYTECOUNT:	alphabytecount=tmp;	break;
	case TIFFTAG_IMAGEOFFSET:	imageoffset=tmp;	break;
	case TIFFTAG_IMAGEBYTECOUNT:	imagebytecount=tmp;	break;
	case TIFFTAG_STRIPOFFSETS:	strip_offsets=tmp;	break;
	case TIFFTAG_STRIPBYTECOUNTS:	strip_bytecounts=tmp;	break;
	case TIFFTAG_TILEBYTECOUNTS:	tile_bytecounts=tmp;	break;
	case TIFFTAG_TILEOFFSETS:	tile_offsets=tmp;	break;
      }
    }
    entry++;
  }
  if(alphabytecount > 0 && max_offset < alphaoffset + alphabytecount)
    max_offset = alphaoffset + alphabytecount;
  if(imagebytecount > 0 && max_offset < imageoffset + imagebytecount)
    max_offset = imageoffset + imagebytecount;
  if(jpegifbytecount > 0 && max_offset < jpegifoffset + jpegifbytecount)
    max_offset = jpegifoffset + jpegifbytecount;
  if(strip_bytecounts > 0 && strip_offsets!=0xffffffff &&
      max_offset < strip_offsets + strip_bytecounts)
    max_offset = strip_offsets + strip_bytecounts;
  if(tile_bytecounts > 0 && tile_offsets!=0xffffffff &&
      max_offset < tile_offsets + tile_bytecounts)
    max_offset = tile_offsets + tile_bytecounts;
  return max_offset;
}
#endif

static uint64_t header_check_tiff_be(file_recovery_t *fr, const uint32_t tiff_diroff, const unsigned int depth, const unsigned int count, const char *tag_make)
{
  unsigned char buffer[8192];
  unsigned int i,n;
  int data_read;
  const uint32_t *tiff_next_diroff;
  uint64_t max_offset=0;
  uint64_t alphaoffset=0;
  uint64_t alphabytecount=0;
  uint64_t imageoffset=0;
  uint64_t imagebytecount=0;
  uint64_t jpegifoffset=0;
  uint64_t jpegifbytecount=0;
  uint64_t strip_offsets=0;
  uint64_t strip_bytecounts=0;
  uint64_t tile_offsets=0;
  uint64_t tile_bytecounts=0;
  const TIFFDirEntry *entry=(const TIFFDirEntry *)&buffer[2];
  const TIFFDirEntry *entry_strip_offsets=NULL;
  const TIFFDirEntry *entry_strip_bytecounts=NULL;
  const TIFFDirEntry *entry_tile_offsets=NULL;
  const TIFFDirEntry *entry_tile_bytecounts=NULL;
  if(depth>4)
    return -1;
  if(count>16)
    return -1;
  if(tiff_diroff < sizeof(TIFFHeader))
    return -1;
  if(fseek(fr->handle, tiff_diroff, SEEK_SET) < 0)
    return -1;
  data_read=fread(buffer, 1, sizeof(buffer), fr->handle);
  if(data_read<2)
    return -1;
  n=(buffer[0]<<8)+buffer[1];
#ifdef DEBUG_TIFF
  log_info("header_check_tiff_be(fr, %lu, %u, %u) => %u entries\n", (long unsigned)tiff_diroff, depth, count, n);
#endif
  //sizeof(TIFFDirEntry)=12;
  if(n > (unsigned)(data_read-2)/12)
    n=(data_read-2)/12;
  if(n==0)
    return -1;
  for(i=0;i<n;i++)
  {
    const uint64_t val=(uint64_t)be32(entry->tdir_count)*type2size(be16(entry->tdir_type));
#ifdef DEBUG_TIFF
    log_info("%u tag=%u(0x%x) %s type=%u count=%lu offset=%lu(0x%lx)\n",
	i,
	be16(entry->tdir_tag),
	be16(entry->tdir_tag),
	tag_name(be16(entry->tdir_tag)),
	be16(entry->tdir_type),
	(long unsigned)be32(entry->tdir_count),
	(long unsigned)be32(entry->tdir_offset),
	(long unsigned)be32(entry->tdir_offset));
#endif
    if(val>4)
    {
      const uint64_t new_offset=be32(entry->tdir_offset)+val;
      if(new_offset==0)
	return -1;
      if(max_offset < new_offset)
	max_offset=new_offset;
    }
    if(be32(entry->tdir_count)==1 && val<=4)
    {
      const unsigned int tmp=tiff_be_read(&entry->tdir_offset, be16(entry->tdir_type));
      switch(be16(entry->tdir_tag))
      {
	case TIFFTAG_ALPHABYTECOUNT:	alphabytecount=tmp;	break;
	case TIFFTAG_ALPHAOFFSET:	alphaoffset=tmp;	break;
	case TIFFTAG_IMAGEBYTECOUNT:	imagebytecount=tmp;	break;
	case TIFFTAG_IMAGEOFFSET:	imageoffset=tmp;	break;
	case TIFFTAG_JPEGIFBYTECOUNT:	jpegifbytecount=tmp;	break;
	case TIFFTAG_JPEGIFOFFSET: 	jpegifoffset=tmp;	break;
	case TIFFTAG_STRIPBYTECOUNTS:	strip_bytecounts=tmp;	break;
	case TIFFTAG_STRIPOFFSETS:	strip_offsets=tmp;	break;
	case TIFFTAG_TILEBYTECOUNTS:	tile_bytecounts=tmp;	break;
	case TIFFTAG_TILEOFFSETS:	tile_offsets=tmp;	break;
	case TIFFTAG_EXIFIFD:
	case TIFFTAG_KODAKIFD:
	  {
	    const uint64_t new_offset=header_check_tiff_be(fr, tmp, depth+1, 0, tag_make);
	    if(new_offset==-1)
	      return -1;
	    if(max_offset < new_offset)
	      max_offset=new_offset;
	  }
	  break;
	case TIFFTAG_SUBIFD:
#if 0
	  if(fr->extension!=NULL && strcmp(fr->extension, "arw")==0)
	  {
	    /* DSLR-A100 is boggus */
	    const uint64_t new_offset=tmp;
	    if(max_offset < new_offset)
	      max_offset=new_offset;
	  }
	  else
#endif
	  {
	    const uint64_t new_offset=header_check_tiff_be(fr, tmp, depth+1, 0, tag_make);
	    if(new_offset==-1)
	      return -1;
	    if(max_offset < new_offset)
	      max_offset=new_offset;
	  }
	  break;
#ifdef ENABLE_TIFF_MAKERNOTE
	case EXIFTAG_MAKERNOTE:
	  {
	    const uint64_t new_offset=tiff_be_makernote(fr->handle, tmp);
	    if(new_offset==-1)
	      return -1;
	    if(max_offset < new_offset)
	      max_offset=new_offset;
	  }
	  break;
#endif
      }
    }
    else if(be32(entry->tdir_count) > 1)
    {
      switch(be16(entry->tdir_tag))
      {
	case TIFFTAG_EXIFIFD:
	case TIFFTAG_KODAKIFD:
	case TIFFTAG_SUBIFD:
	  if(be16(entry->tdir_type)==4)
	  {
	    const unsigned int nbr=(be32(entry->tdir_count)<32?be32(entry->tdir_count):32);
	    unsigned int j;
	    uint32_t *subifd_offsetp;
	    if(fseek(fr->handle, be32(entry->tdir_offset), SEEK_SET) < 0)
	    {
	      return -1;
	    }
	    subifd_offsetp=(uint32_t *)MALLOC(nbr*sizeof(*subifd_offsetp));
	    if(fread(subifd_offsetp, sizeof(*subifd_offsetp), nbr, fr->handle) != nbr)
	    {
	      free(subifd_offsetp);
	      return -1;
	    }
	    for(j=0; j<nbr; j++)
	    {
	      const uint64_t new_offset=header_check_tiff_be(fr, be32(subifd_offsetp[j]), depth+1, 0, tag_make);
	      if(new_offset==-1)
	      {
		free(subifd_offsetp);
		return -1;
	      }
	      if(max_offset < new_offset)
		max_offset = new_offset;
	    }
	    free(subifd_offsetp);
	  }
	  break;
	case TIFFTAG_STRIPOFFSETS:
	  entry_strip_offsets=entry;
	  break;
	case TIFFTAG_STRIPBYTECOUNTS:
	  entry_strip_bytecounts=entry;
	  break;
	case TIFFTAG_TILEBYTECOUNTS:
	  entry_tile_bytecounts=entry;
	  break;
	case TIFFTAG_TILEOFFSETS:
	  entry_tile_offsets=entry;
	  break;
      }
    }
    entry++;
  }
  if(alphabytecount > 0 && max_offset < alphaoffset + alphabytecount)
    max_offset = alphaoffset + alphabytecount;
  if(imagebytecount > 0 && max_offset < imageoffset + imagebytecount)
    max_offset = imageoffset + imagebytecount;
  if(jpegifbytecount > 0 && max_offset < jpegifoffset + jpegifbytecount)
    max_offset = jpegifoffset + jpegifbytecount;
  if(strip_bytecounts > 0 && strip_offsets!=0xffffffff &&
      max_offset < strip_offsets + strip_bytecounts)
    max_offset = strip_offsets + strip_bytecounts;
  if(tile_bytecounts > 0 && tile_offsets!=0xffffffff &&
      max_offset < tile_offsets + tile_bytecounts)
    max_offset = tile_offsets + tile_bytecounts;
  if(entry_strip_offsets != NULL && entry_strip_bytecounts != NULL)
  {
    const uint64_t tmp=parse_strip_be(fr->handle, entry_strip_offsets, entry_strip_bytecounts);
    if(max_offset < tmp)
      max_offset=tmp;
  }
  if(entry_tile_offsets != NULL && entry_tile_bytecounts != NULL)
  {
    const uint64_t tmp=parse_strip_be(fr->handle, entry_tile_offsets, entry_tile_bytecounts);
    if(max_offset < tmp)
      max_offset=tmp;
  }
  tiff_next_diroff=(const uint32_t *)entry;
  if(be32(*tiff_next_diroff) > 0)
  {
    const uint64_t new_offset=header_check_tiff_be(fr, be32(*tiff_next_diroff), depth, count+1, tag_make);
    if(max_offset!=-1 && max_offset < new_offset)
      max_offset=new_offset;
  }
  return max_offset;
}

void file_check_tiff(file_recovery_t *fr)
{
  static uint64_t calculated_file_size=0;
  unsigned char *buffer=(unsigned char *)MALLOC(8192);
  int data_read;
  calculated_file_size = 0;
  if(fseek(fr->handle, 0, SEEK_SET) < 0 ||
      (data_read=fread(buffer, 1, 8192, fr->handle)) < (int)sizeof(TIFFHeader))
  {
    free(buffer);
    fr->file_size=0;
    return;
  }
  {
    const TIFFHeader *header=(const TIFFHeader *)buffer;
    const char *tag_make;
    const char *potential_error=NULL;
    tag_make=find_tag_from_tiff_header(header, data_read, TIFFTAG_MAKE, &potential_error);
    if(tag_make < (const char *)buffer || tag_make >= (const char *)buffer + data_read - 20)
      tag_make=NULL;
    if(header->tiff_magic==TIFF_LITTLEENDIAN)
      calculated_file_size=header_check_tiff_le(fr, le32(header->tiff_diroff), 0, 0, tag_make);
    else if(header->tiff_magic==TIFF_BIGENDIAN)
      calculated_file_size=header_check_tiff_be(fr, be32(header->tiff_diroff), 0, 0, tag_make);
  }
#ifdef DEBUG_TIFF
  log_info("TIFF Current   %llu\n", (unsigned long long)fr->file_size);
  log_info("TIFF Estimated %llu\n", (unsigned long long)calculated_file_size);
#endif
  if(fr->file_size < calculated_file_size || calculated_file_size==0)
    fr->file_size=0;
    /* PhotoRec isn't yet capable to find the correct filesize for
     * Sony arw and dng,
     * Panasonic raw/rw2,
     * Minolta tif
     * so don't truncate them */
  else if(strcmp(fr->extension,"cr2")==0 ||
      strcmp(fr->extension,"dcr")==0 ||
      strcmp(fr->extension,"nef")==0 ||
      strcmp(fr->extension,"orf")==0 ||
      strcmp(fr->extension,"pef")==0 ||
      strcmp(fr->extension,"sr2")==0 ||
      (strcmp(fr->extension,"tif")==0 && calculated_file_size>1024*1024*1024) ||
      strcmp(fr->extension,"wdp")==0)
    fr->file_size=calculated_file_size;
  free(buffer);
}
