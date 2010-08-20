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
static int header_check_tiff(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);
static uint64_t header_check_tiff_be(file_recovery_t *fr, const uint32_t tiff_diroff, const unsigned int depth, const unsigned int count, const char *tag_make);
static uint64_t header_check_tiff_le(file_recovery_t *fr, const uint32_t tiff_diroff, const unsigned int depth, const unsigned int count, const char *tag_make);

const file_hint_t file_hint_tiff= {
  .extension="tif",
  .description="Tag Image File Format and some raw file formats (pef/nef/dcr/sr2/cr2)",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_tiff
};

static const unsigned char tiff_header_be[4]= { 'M','M',0x00, 0x2a};
static const unsigned char tiff_header_le[4]= { 'I','I',0x2a, 0x00};

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
  /* Bound checking */
  if((const char*)ifd0 < (const char*)tiff ||
      (const char*)(ifd0+1) > (const char*)tiff + tiff_size)
    return NULL;
  for(j=0, ifd=&ifd0->ifd;
      (const char*)(ifd+1) <= (const char*)tiff+tiff_size && j<be16(ifd0->nbr_fields);
      j++, ifd++)
  {
    if(be16(ifd->tdir_type) > 18 && (*potential_error==NULL || *potential_error > (const char*)&ifd->tdir_tag))
      *potential_error = (const char*)&ifd->tdir_tag;
    if(be16(ifd->tdir_tag)==tag)
      return (const char*)tiff+be32(ifd->tdir_offset);
    else if(be16(ifd->tdir_tag)==TIFFTAG_EXIFIFD)	/* Exif IFD Pointer */
      exififd=(const struct ifd_header *)((const char*)tiff + be32(ifd->tdir_offset));
  }
  tiff_next_diroff=(const uint32_t *)ifd;
  if(exififd!=NULL &&
      (const char*)exififd > (const char*)tiff &&
      (const char*)(exififd+1) <= (const char*)tiff + tiff_size)
  {	/* Exif */
    for(j=0, ifd=&exififd->ifd;
	(const char*)(ifd+1) <= (const char*)tiff+tiff_size && j<be16(exififd->nbr_fields);
	j++, ifd++)
    {
      if(be16(ifd->tdir_type) > 18 && (*potential_error==NULL || *potential_error > (const char*)&ifd->tdir_tag))
	*potential_error = (const char*)&ifd->tdir_tag;
      if(be16(ifd->tdir_tag)==tag)
	return (const char*)tiff+be32(ifd->tdir_offset);
    }
  }
  /* IFD1 */
  if(be32(*tiff_next_diroff)>0)
  {
    const struct ifd_header *ifd1=(const struct ifd_header*)((const char *)tiff+be32(*tiff_next_diroff));
    if((const char*)ifd1 <= (const char*)tiff ||
	(const char*)(ifd1+1) > (const char*)tiff+tiff_size)
      return NULL;
    for(j=0, ifd=&ifd1->ifd;
	(const char*)(ifd+1) <= (const char*)tiff+tiff_size && j<be16(ifd1->nbr_fields);
	j++, ifd++)
    {
      if(be16(ifd->tdir_type) > 18 && (*potential_error==NULL || *potential_error > (const char*)&ifd->tdir_tag))
	*potential_error = (const char*)&ifd->tdir_tag;
      if(be16(ifd->tdir_tag)==tag)
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
  /* Bound checking */
  if((const char*)ifd0 < (const char*)tiff ||
      (const char*)(ifd0+1) > (const char*)tiff + tiff_size)
    return NULL;
  for(j=0, ifd=&ifd0->ifd;
      (const char*)(ifd+1) <= (const char*)tiff+tiff_size && j<le16(ifd0->nbr_fields);
      j++, ifd++)
  {
    if(le16(ifd->tdir_type) > 18 && (*potential_error==NULL || *potential_error > (const char*)&ifd->tdir_tag))
      *potential_error = (const char*)&ifd->tdir_tag;
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
      if(le16(ifd->tdir_type) > 18 && (*potential_error==NULL || *potential_error > (const char*)&ifd->tdir_tag))
	*potential_error = (const char*)&ifd->tdir_tag;
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
      if(le16(ifd->tdir_type) > 18 && (*potential_error==NULL || *potential_error > (const char*)&ifd->tdir_tag))
	*potential_error = (const char*)&ifd->tdir_tag;
      if(le16(ifd->tdir_tag)==tag)
	return (const char*)tiff+le32(ifd->tdir_offset);
    }
  }
  return NULL;
}

const char *find_tag_from_tiff_header(const TIFFHeader *tiff, const unsigned int tiff_size, const unsigned int tag, const char **potential_error)
{
  if(tiff_size < sizeof(TIFFHeader))
    return NULL;
  if(tiff->tiff_magic==TIFF_BIGENDIAN)
  {
    if(tiff_size < be32(tiff->tiff_diroff)+sizeof(TIFFDirEntry))
      return NULL;
    return find_tag_from_tiff_header_be(tiff, tiff_size, tag, potential_error);
  }
  else if(tiff->tiff_magic==TIFF_LITTLEENDIAN)
  {
    if(tiff_size < le32(tiff->tiff_diroff)+sizeof(TIFFDirEntry))
      return NULL;
    return find_tag_from_tiff_header_le(tiff, tiff_size, tag, potential_error);
  }
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

static void register_header_check_tiff(file_stat_t *file_stat)
{
  register_header_check(0, tiff_header_be, sizeof(tiff_header_be), &header_check_tiff, file_stat);
  register_header_check(0, tiff_header_le, sizeof(tiff_header_le), &header_check_tiff, file_stat);
}

static int header_check_tiff(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(buffer,tiff_header_be,sizeof(tiff_header_be))==0 ||
      memcmp(buffer,tiff_header_le,sizeof(tiff_header_le))==0)
  {
    const char *potential_error=NULL;
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_tiff.extension;
    /* Canon RAW */
    if(buffer[8]=='C' && buffer[9]=='R' && buffer[10]==2)
      file_recovery_new->extension="cr2";
    else if(find_tag_from_tiff_header((const TIFFHeader *)buffer, buffer_size, TIFFTAG_DNGVERSION, &potential_error)!=NULL)
    {
      /* Adobe Digital Negative */
      file_recovery_new->extension="dng";
    }
    else
    {
      const char *tag_make;
      tag_make=find_tag_from_tiff_header((const TIFFHeader *)buffer, buffer_size, TIFFTAG_MAKE, &potential_error);
      if(tag_make!=NULL && tag_make >= (const char *)buffer && tag_make < (const char *)buffer + buffer_size - 20)
      {
	if(strcmp(tag_make, "PENTAX Corporation ")==0 ||
	    strcmp(tag_make, "PENTAX             ")==0)
	  file_recovery_new->extension="pef";
	else if(strcmp(tag_make, "NIKON CORPORATION")==0)
	  file_recovery_new->extension="nef";
	else if(strcmp(tag_make, "Kodak")==0)
	  file_recovery_new->extension="dcr";
	else if(strcmp(tag_make, "SONY")==0)
	  file_recovery_new->extension="sr2";
	else if(strncmp(tag_make, "SONY ",5)==0)
	  file_recovery_new->extension="arw";
      }
    }
    file_recovery_new->time=get_date_from_tiff_header((const TIFFHeader *)buffer, buffer_size);
    file_recovery_new->file_check=&file_check_tiff;
    return 1;
  }
  return 0;
}


#ifdef ENABLE_TIFF_MAKERNOTE
static uint64_t tiff_le_makernote(FILE *in, const uint32_t tiff_diroff, const char *tag_make)
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
  const TIFFDirEntry *entry;
  if(tiff_diroff == 0)
    return 0;
  if(fseek(in, tiff_diroff, SEEK_SET) < 0)
    return 0;
  data_read=fread(buffer, 1, sizeof(buffer), in);
  if(data_read<2)
    return 0;
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
    return 0;
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
	return 0;
      if(max_offset < new_offset)
	max_offset=new_offset;
    }
    switch(le16(entry->tdir_tag))
    {
      case TIFFTAG_JPEGIFOFFSET:
	jpegifoffset=le32(entry->tdir_offset);
	break;
      case TIFFTAG_JPEGIFBYTECOUNT:
	jpegifbytecount=le32(entry->tdir_offset);
	break;
      case TIFFTAG_STRIPOFFSETS:
        strip_offsets=le32(entry->tdir_offset);
	break;
      case TIFFTAG_STRIPBYTECOUNTS:
	strip_bytecounts=le32(entry->tdir_offset);
	break;
      case TIFFTAG_ALPHAOFFSET:
	alphaoffset=le32(entry->tdir_offset);
	break;
      case TIFFTAG_ALPHABYTECOUNT:
	alphabytecount=le32(entry->tdir_offset);
	break;
      case TIFFTAG_IMAGEOFFSET:
	imageoffset=le32(entry->tdir_offset);
	break;
      case TIFFTAG_IMAGEBYTECOUNT:
	imagebytecount=le32(entry->tdir_offset);
	break;
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
  return max_offset;
}
#endif

static uint64_t header_check_tiff_le(file_recovery_t *fr, const uint32_t tiff_diroff, const unsigned int depth, const unsigned int count, const char *tag_make)
{
  unsigned char buffer[8192];
  unsigned int i,n;
  int data_read;
  uint32_t *tiff_next_diroff;
  uint64_t max_offset=0;
  uint64_t alphaoffset=0;
  uint64_t alphabytecount=0;
  uint64_t imageoffset=0;
  uint64_t imagebytecount=0;
  uint64_t jpegifoffset=0;
  uint64_t jpegifbytecount=0;
  uint64_t strip_offsets=0;
  uint64_t strip_bytecounts=0;
  TIFFDirEntry *entry=(TIFFDirEntry *)&buffer[2];
#ifdef DEBUG_TIFF
  log_info("header_check_tiff_le(fr, %lu, %u, %u)\n", (long unsigned)tiff_diroff, depth, count);
#endif
  if(depth>4)
    return 0;
  if(count>16)
    return 0;
  if(tiff_diroff == 0)
    return 0;
  if(fseek(fr->handle, tiff_diroff, SEEK_SET) < 0)
    return 0;
  data_read=fread(buffer, 1, sizeof(buffer), fr->handle);
  if(data_read<2)
    return 0;
  n=buffer[0]+(buffer[1]<<8);
#ifdef DEBUG_TIFF
  log_info("header_check_tiff_le(fr, %lu, %u, %u) => %u entries\n", (long unsigned)tiff_diroff, depth, count, n);
#endif
  //sizeof(TIFFDirEntry)=12;
  if(n > (unsigned)(data_read-2)/12)
    n=(data_read-2)/12;
  if(n==0)
    return 0;
  for(i=0;i<n;i++)
  {
    uint64_t val=(uint64_t)le32(entry->tdir_count)*type2size(le16(entry->tdir_type));
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
	return 0;
      if(max_offset < new_offset)
	max_offset=new_offset;
    }
    switch(le16(entry->tdir_tag))
    {
      case TIFFTAG_JPEGIFOFFSET:
	jpegifoffset=le32(entry->tdir_offset);
	break;
      case TIFFTAG_JPEGIFBYTECOUNT:
	jpegifbytecount=le32(entry->tdir_offset);
	break;
      case TIFFTAG_STRIPOFFSETS:
        strip_offsets=le32(entry->tdir_offset);
	break;
      case TIFFTAG_STRIPBYTECOUNTS:
	strip_bytecounts=le32(entry->tdir_offset);
	break;
      case TIFFTAG_ALPHAOFFSET:
	alphaoffset=le32(entry->tdir_offset);
	break;
      case TIFFTAG_ALPHABYTECOUNT:
	alphabytecount=le32(entry->tdir_offset);
	break;
      case TIFFTAG_IMAGEOFFSET:
	imageoffset=le32(entry->tdir_offset);
	break;
      case TIFFTAG_IMAGEBYTECOUNT:
	imagebytecount=le32(entry->tdir_offset);
	break;
      case TIFFTAG_EXIFIFD:
      case TIFFTAG_KODAKIFD:
	if(val==4)
	{
	  uint64_t new_offset=header_check_tiff_le(fr, le32(entry->tdir_offset), depth+1, 0, tag_make);
	  if(new_offset==0)
	    return 0;
	  if(max_offset < new_offset)
	    max_offset=new_offset;
	}
	else if(val>4)
	{
	  const unsigned int nbr=(le32(entry->tdir_count)<32?le32(entry->tdir_count):32);
	  unsigned int j;
	  uint32_t *subifd_offsetp;
	  subifd_offsetp=(uint32_t *)MALLOC(nbr*sizeof(*subifd_offsetp));
	  if(fseek(fr->handle, le32(entry->tdir_offset), SEEK_SET) < 0)
	  {
	    free(subifd_offsetp);
	    return 0;
	  }
	  if(fread(subifd_offsetp, sizeof(*subifd_offsetp), nbr, fr->handle) != nbr)
	  {
	    free(subifd_offsetp);
	    return 0;
	  }
	  for(j=0; j<nbr; j++)
	  {
	    const uint64_t new_offset=header_check_tiff_le(fr, le32(subifd_offsetp[j]), depth+1, 0, tag_make);
	    if(new_offset==0)
	    {
	      free(subifd_offsetp);
	      return 0;
	    }
	    if(max_offset < new_offset)
	      max_offset = new_offset;
	  }
	  free(subifd_offsetp);
	}
	break;
      case TIFFTAG_SUBIFD:
	if(fr->extension!=NULL && strcmp(fr->extension, "arw")==0)
	{
	  /* DSLR-A100 is boggus */
	  if(val==4)
	  {
	    const uint64_t new_offset=le32(entry->tdir_offset);
	    if(max_offset < new_offset)
	      max_offset=new_offset;
	  }
	}
	else if(val==4)
	{
	  uint64_t new_offset=header_check_tiff_le(fr, le32(entry->tdir_offset), depth+1, 0, tag_make);
	  if(new_offset==0)
	    return 0;
	  if(max_offset < new_offset)
	    max_offset=new_offset;
	}
	else if(val>4)
	{
	  const unsigned int nbr=(le32(entry->tdir_count)<32?le32(entry->tdir_count):32);
	  unsigned int j;
	  uint32_t *subifd_offsetp;
	  subifd_offsetp=(uint32_t *)MALLOC(nbr*sizeof(*subifd_offsetp));
	  if(fseek(fr->handle, le32(entry->tdir_offset), SEEK_SET) < 0)
	  {
	    free(subifd_offsetp);
	    return 0;
	  }
	  if(fread(subifd_offsetp, sizeof(*subifd_offsetp), nbr, fr->handle) != nbr)
	  {
	    free(subifd_offsetp);
	    return 0;
	  }
	  for(j=0; j<nbr; j++)
	  {
	    const uint64_t new_offset=header_check_tiff_le(fr, le32(subifd_offsetp[j]), depth+1, 0, tag_make);
	    if(new_offset==0)
	    {
	      free(subifd_offsetp);
	      return 0;
	    }
	    if(max_offset < new_offset)
	      max_offset = new_offset;
	  }
	  free(subifd_offsetp);
	}
	break;
#ifdef ENABLE_TIFF_MAKERNOTE
      case EXIFTAG_MAKERNOTE:
	{
	  uint64_t new_offset=tiff_le_makernote(in, le32(entry->tdir_offset), tag_make);
	  if(new_offset==0)
	    return 0;
	  if(max_offset < new_offset)
	    max_offset=new_offset;
	}
	break;
#endif
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
  tiff_next_diroff=(uint32_t *)entry;
  {
    uint64_t new_offset=header_check_tiff_le(fr, le32(*tiff_next_diroff), depth, count+1, tag_make);
    if(max_offset < new_offset)
      max_offset=new_offset;
  }
  return max_offset;
}

#ifdef ENABLE_TIFF_MAKERNOTE
static uint64_t tiff_be_makernote(FILE *in, const uint32_t tiff_diroff, const char *tag_make)
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
  const TIFFDirEntry *entry;
  if(tiff_diroff == 0)
    return 0;
  if(fseek(in, tiff_diroff, SEEK_SET) < 0)
    return 0;
  data_read=fread(buffer, 1, sizeof(buffer), in);
  if(data_read<2)
    return 0;
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
    return 0;
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
	return 0;
      if(max_offset < new_offset)
	max_offset=new_offset;
    }
    switch(be16(entry->tdir_tag))
    {
      case TIFFTAG_JPEGIFOFFSET:
	jpegifoffset=be32(entry->tdir_offset);
	break;
      case TIFFTAG_JPEGIFBYTECOUNT:
	jpegifbytecount=be32(entry->tdir_offset);
	break;
      case TIFFTAG_STRIPOFFSETS:
        strip_offsets=be32(entry->tdir_offset);
	break;
      case TIFFTAG_STRIPBYTECOUNTS:
	strip_bytecounts=be32(entry->tdir_offset);
	break;
      case TIFFTAG_ALPHAOFFSET:
	alphaoffset=be32(entry->tdir_offset);
	break;
      case TIFFTAG_ALPHABYTECOUNT:
	alphabytecount=be32(entry->tdir_offset);
	break;
      case TIFFTAG_IMAGEOFFSET:
	imageoffset=be32(entry->tdir_offset);
	break;
      case TIFFTAG_IMAGEBYTECOUNT:
	imagebytecount=be32(entry->tdir_offset);
	break;
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
  return max_offset;
}
#endif

static uint64_t header_check_tiff_be(file_recovery_t *fr, const uint32_t tiff_diroff, const unsigned int depth, const unsigned int count, const char *tag_make)
{
  unsigned char buffer[8192];
  unsigned int i,n;
  int data_read;
  uint32_t *tiff_next_diroff;
  uint64_t max_offset=0;
  uint64_t alphaoffset=0;
  uint64_t alphabytecount=0;
  uint64_t imageoffset=0;
  uint64_t imagebytecount=0;
  uint64_t jpegifoffset=0;
  uint64_t jpegifbytecount=0;
  uint64_t strip_offsets=0;
  uint64_t strip_bytecounts=0;
  TIFFDirEntry *entry=(TIFFDirEntry *)&buffer[2];
  if(depth>4)
    return 0;
  if(count>16)
    return 0;
  if(tiff_diroff == 0)
    return 0;
  if(fseek(fr->handle, tiff_diroff, SEEK_SET) < 0)
    return 0;
  data_read=fread(buffer, 1, sizeof(buffer), fr->handle);
  if(data_read<2)
    return 0;
  n=(buffer[0]<<8)+buffer[1];
#ifdef DEBUG_TIFF
  log_info("header_check_tiff_be(fr, %lu, %u, %u) => %u entries\n", (long unsigned)tiff_diroff, depth, count, n);
#endif
  //sizeof(TIFFDirEntry)=12;
  if(n > (unsigned)(data_read-2)/12)
    n=(data_read-2)/12;
  if(n==0)
    return 0;
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
	return 0;
      if(max_offset < new_offset)
	max_offset=new_offset;
    }
    switch(be16(entry->tdir_tag))
    {
      case TIFFTAG_JPEGIFOFFSET:
	jpegifoffset=be32(entry->tdir_offset);
	break;
      case TIFFTAG_JPEGIFBYTECOUNT:
	jpegifbytecount=be32(entry->tdir_offset);
	break;
      case TIFFTAG_STRIPOFFSETS:
        strip_offsets=be32(entry->tdir_offset);
	break;
      case TIFFTAG_STRIPBYTECOUNTS:
	strip_bytecounts=be32(entry->tdir_offset);
	break;
      case TIFFTAG_ALPHAOFFSET:
	alphaoffset=be32(entry->tdir_offset);
	break;
      case TIFFTAG_ALPHABYTECOUNT:
	alphabytecount=be32(entry->tdir_offset);
	break;
      case TIFFTAG_IMAGEOFFSET:
	imageoffset=be32(entry->tdir_offset);
	break;
      case TIFFTAG_IMAGEBYTECOUNT:
	imagebytecount=be32(entry->tdir_offset);
	break;
      case TIFFTAG_EXIFIFD:
      case TIFFTAG_KODAKIFD:
      case TIFFTAG_SUBIFD:
	if(val==4)
	{
	  uint64_t new_offset=header_check_tiff_be(fr, be32(entry->tdir_offset), depth+1, 0, tag_make);
	  if(new_offset==0)
	    return 0;
	  if(max_offset < new_offset)
	    max_offset=new_offset;
	}
	else if(val>4)
	{
	  const unsigned int nbr=(be32(entry->tdir_count)<32?be32(entry->tdir_count):32);
	  unsigned int j;
	  uint32_t *subifd_offsetp;
	  subifd_offsetp=(uint32_t *)MALLOC(nbr*sizeof(*subifd_offsetp));
	  if(fseek(fr->handle, be32(entry->tdir_offset), SEEK_SET) < 0)
	  {
	    free(subifd_offsetp);
	    return 0;
	  }
	  if(fread(subifd_offsetp, sizeof(*subifd_offsetp), nbr, fr->handle) != nbr)
	  {
	    free(subifd_offsetp);
	    return 0;
	  }
	  for(j=0; j<nbr; j++)
	  {
	    const uint64_t new_offset=header_check_tiff_be(fr, be32(subifd_offsetp[j]), depth+1, 0, tag_make);
	    if(new_offset==0)
	    {
	      free(subifd_offsetp);
	      return 0;
	    }
	    if(max_offset < new_offset)
	      max_offset = new_offset;
	  }
	  free(subifd_offsetp);
	}
	break;
#ifdef ENABLE_TIFF_MAKERNOTE
      case EXIFTAG_MAKERNOTE:
	{
	  uint64_t new_offset=tiff_be_makernote(in, be32(entry->tdir_offset), tag_make);
	  if(new_offset==0)
	    return 0;
	  if(max_offset < new_offset)
	    max_offset=new_offset;
	}
	break;
#endif
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
  tiff_next_diroff=(uint32_t *)entry;
  {
    uint64_t new_offset=header_check_tiff_be(fr, be32(*tiff_next_diroff), depth, count+1, tag_make);
    if(max_offset < new_offset)
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
  fseek(fr->handle, 0, SEEK_SET);
  data_read=fread(buffer, 1, sizeof(buffer), fr->handle);
  if(data_read < (int)sizeof(TIFFHeader))
  {
    free(buffer);
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
  if(fr->file_size < calculated_file_size)
    fr->file_size=0;
    /* PhotoRec isn't yet capable to find the correct filesize for
     * Sony arw and dng,
     * Panasonic raw/rw2,
     * Minolta tif
     * so don't truncate them */
  else if(strcmp(fr->extension,"cr2")==0 ||
      strcmp(fr->extension,"dcr")==0 ||
      strcmp(fr->extension,"nef")==0 ||
      strcmp(fr->extension,"pef")==0 ||
      strcmp(fr->extension,"sr2")==0 ||
      (strcmp(fr->extension,"tif")==0 && calculated_file_size>1024*1024*1024) ||
      strcmp(fr->extension,"wdp")==0)
    fr->file_size=calculated_file_size;
  free(buffer);
}
