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
#include <stdio.h>
#include "types.h"
#include "filegen.h"
#include "common.h"
#include "file_tiff.h"

static void register_header_check_tiff(file_stat_t *file_stat);
static int header_check_tiff(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);
static void file_check_tiff(file_recovery_t *file_recovery);
static uint64_t header_check_tiff_be(FILE *in, const uint32_t tiff_diroff, const unsigned int depth, const unsigned int count);
static uint64_t header_check_tiff_le(FILE *in, const uint32_t tiff_diroff, const unsigned int depth, const unsigned int count);

const file_hint_t file_hint_tiff= {
  .extension="tif",
  .description="Tag Image File Format and some raw file formats (pef/nef/dcr/sr2/cr2)",
  .min_header_distance=0,
  .max_filesize=200*1024*1024,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_tiff
};

static const unsigned char tiff_header_be[4]= { 'M','M',0x00, 0x2a};
static const unsigned char tiff_header_le[4]= { 'I','I',0x2a, 0x00};
#define TIFFTAG_MAKE                    271     /* scanner manufacturer name */

static const char *find_tag_from_tiff_header(const TIFFHeader *tiff, const unsigned int tiff_size, const unsigned int tag)
{
  if(tiff_size < sizeof(TIFFHeader))
    return NULL;
  if(memcmp(&tiff->tiff_magic, tiff_header_be, sizeof(tiff_header_be))==0)
  {
    if(tiff_size < be32(tiff->tiff_diroff)+sizeof(TIFFDirEntry))
      return NULL;
    {
      const struct ifd_header *ifd0=(const struct ifd_header *)((const char*)tiff + be32(tiff->tiff_diroff));
      const struct ifd_header *ifd1=NULL;
      const TIFFDirEntry *ifd;
      unsigned int j;
      for(j=0, ifd=&ifd0->ifd;
	  (const char*)(ifd+1) <= (const char*)tiff+tiff_size && j<be16(ifd0->nbr_fields);
	  j++, ifd++)
      {
	if(be16(ifd->tdir_tag)==tag)
	{
	  if(be32(ifd->tdir_offset)+19 < tiff_size)
	    return (const char*)tiff+be32(ifd->tdir_offset);
	}
	else if(be16(ifd->tdir_tag)==TIFFTAG_EXIFIFD)	/* Exif IFD Pointer */
	{
	  ifd1=(const struct ifd_header *)((const char*)tiff + be32(ifd->tdir_offset));
	}
      }
      if(ifd1!=NULL)
      {	/* Exif */
	for(j=0, ifd=&ifd1->ifd;
	    (const char*)(ifd+1) <= (const char*)tiff+tiff_size && j<be16(ifd1->nbr_fields);
	    j++, ifd++)
	{
	  if(be16(ifd->tdir_tag)==tag)
	  {
	    if(be32(ifd->tdir_offset)+19 < tiff_size)
	      return (const char*)tiff+be32(ifd->tdir_offset);
	  }
	}
      }
    }
  }
  else if(memcmp(&tiff->tiff_magic, tiff_header_le, sizeof(tiff_header_le))==0)
  {
    if(tiff_size < le32(tiff->tiff_diroff)+sizeof(TIFFDirEntry))
      return NULL;
    {
      const struct ifd_header *ifd0=(const struct ifd_header *)((const char*)tiff + le32(tiff->tiff_diroff));
      const struct ifd_header *ifd1=NULL;
      const TIFFDirEntry *ifd;
      unsigned int j;
      for(j=0, ifd=&ifd0->ifd;
	   (const char*)(ifd+1) <= (const char*)tiff+tiff_size && j<le16(ifd0->nbr_fields);
	  j++, ifd++)
      {
	if(le16(ifd->tdir_tag)==tag)
	{
	  if(le32(ifd->tdir_offset)+19 < tiff_size)
	    return (const char*)tiff+le32(ifd->tdir_offset);
	}
	else if(le16(ifd->tdir_tag)==TIFFTAG_EXIFIFD)	/* Exif IFD Pointer */
	{
	  ifd1=(const struct ifd_header *)((const char*)tiff + le32(ifd->tdir_offset));
	}
      }
      if(ifd1!=NULL)
      {	/* Exif */
	for(j=0, ifd=&ifd1->ifd;
	    (const char*)(ifd+1) <= (const char*)tiff+tiff_size && j<le16(ifd1->nbr_fields);
	    j++, ifd++)
	{
	  if(le16(ifd->tdir_tag)==tag)		/* DateTimeOriginal */
	  {
	    if(le32(ifd->tdir_offset)+19 < tiff_size)
	      return (const char*)tiff+le32(ifd->tdir_offset);
	  }
	}
      }
    }
  }
  return NULL;
}

time_t get_date_from_tiff_header(const TIFFHeader *tiff, const unsigned int tiff_size)
{
  const char *date_asc;
  struct tm tm_time;
  /* DateTimeOriginal */
  date_asc=find_tag_from_tiff_header(tiff, tiff_size, 0x9003);
  /* DateTimeDigitalized*/
  if(date_asc==NULL)
    date_asc=find_tag_from_tiff_header(tiff, tiff_size, 0x9004);
  if(date_asc==NULL)
    date_asc=find_tag_from_tiff_header(tiff, tiff_size, 0x132);
  if(date_asc==NULL)
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
  register_header_check(0, tiff_header_be,sizeof(tiff_header_be), &header_check_tiff, file_stat);
  register_header_check(0, tiff_header_le,sizeof(tiff_header_le), &header_check_tiff, file_stat);
}

static int header_check_tiff(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(buffer,tiff_header_be,sizeof(tiff_header_be))==0 ||
      memcmp(buffer,tiff_header_le,sizeof(tiff_header_le))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_tiff.extension;
    /* Canon RAW */
    if(buffer[8]=='C' && buffer[9]=='R' && buffer[10]==2)
      file_recovery_new->extension="cr2";
    else
    {
      const char *tag_make;
      tag_make=find_tag_from_tiff_header((const TIFFHeader *)buffer, buffer_size, TIFFTAG_MAKE);
      if(tag_make!=NULL)
      {
	if(strcmp(tag_make, "PENTAX Corporation ")==0)
	  file_recovery_new->extension="pef";
	else if(strcmp(tag_make, "NIKON CORPORATION")==0)
	  file_recovery_new->extension="nef";
	else if(strcmp(tag_make, "Kodak")==0)
	  file_recovery_new->extension="dcr";
	else if(strcmp(tag_make, "Sony")==0)
	  file_recovery_new->extension="sr2";
	else if(strcmp(tag_make, "Sony ")==0)
	  file_recovery_new->extension="arw";
      }
    }
    file_recovery_new->time=get_date_from_tiff_header((const TIFFHeader *)buffer, buffer_size);
    file_recovery_new->file_check=&file_check_tiff;
    return 1;
  }
  return 0;
}

static unsigned int type2size(const unsigned int type)
{
  switch(type)
  {
    case 1:
    case 2:
    case 6:
    case 7:
      return 1;
    case 3:
    case 8:
      return 2;
    case 4:
    case 9:
    case 11:
      return 4;
    case 5:
    case 10:
    case 12:
      return 8;
    default:
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
    default:
      return "";
  }
}
#endif

static uint64_t header_check_tiff_le(FILE *in, const uint32_t tiff_diroff, const unsigned int depth, const unsigned int count)
{
  unsigned char buffer[8192];
  unsigned int i,n;
  int data_read;
  uint32_t *tiff_next_diroff;
  uint64_t max_offset=0;
  uint64_t strip_offsets=0;
  uint64_t strip_bytecounts=0;
  uint64_t jpegifoffset=0;
  uint64_t jpegifbytecount=0;
  TIFFDirEntry *entry=(TIFFDirEntry *)&buffer[2];
  if(depth>4)
    return 0;
  if(count>16)
    return 0;
  if(tiff_diroff == 0)
    return 0;
  if(tiff_diroff % 2 != 0)
    return -1;
  if(fseek(in, tiff_diroff, SEEK_SET) < 0)
    return -1;
  data_read=fread(buffer, 1, sizeof(buffer), in);
  if(data_read<2)
    return -1;
  n=buffer[0]+(buffer[1]<<8);
#ifdef DEBUG_TIFF
  log_info("header_check_tiff_le(in, %lu, %u, %u) => %u entries\n", (long unsigned)tiff_diroff, depth, count, n);
#endif
  //sizeof(TIFFDirEntry)=12;
  if(n > (data_read-2)/12)
    n=(data_read-2)/12;
  if(n==0)
    return 0;
  for(i=0;i<n;i++)
  {
    uint64_t val=(uint64_t)le32(entry->tdir_count)*type2size(le16(entry->tdir_type));
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
      if(new_offset==-1)
	return -1;
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
      case TIFFTAG_EXIFIFD:
      case TIFFTAG_KODAKIFD:
      case TIFFTAG_SUBIFD:
	if(val==4)
	{
	  uint64_t new_offset=header_check_tiff_le(in, le32(entry->tdir_offset), depth+1, 0);
	  if(new_offset==-1)
	    return -1;
	  if(max_offset < new_offset)
	    max_offset=new_offset;
	}
	else if(val>4)
	{
	  const unsigned int nbr=le32(entry->tdir_count);
	  if(nbr<25)
	  {
	    unsigned int j;
	    uint32_t *subifd_offsetp;
	    subifd_offsetp=(uint32_t *)malloc(nbr*sizeof(*subifd_offsetp));
	    if(fseek(in, le32(entry->tdir_offset), SEEK_SET) < 0)
	      return -1;
	    if(fread(subifd_offsetp, sizeof(*subifd_offsetp), nbr, in) != nbr)
	      return -1;
	    for(j=0; j<nbr; j++)
	    {
	      const uint64_t new_offset=header_check_tiff_le(in, le32(subifd_offsetp[j]), depth+1, 0);
	      if(new_offset==-1)
		return -1;
	      if(max_offset < new_offset)
		max_offset = new_offset;
	    }
	  }
	}
	break;
    }
    entry++;
  }
  if(strip_bytecounts > 0 && max_offset < strip_offsets + strip_bytecounts)
    max_offset = strip_offsets + strip_bytecounts;
  if(jpegifbytecount > 0 && max_offset < jpegifoffset + jpegifbytecount)
    max_offset = jpegifoffset + jpegifbytecount;
  tiff_next_diroff=(uint32_t *)entry;
  {
    uint64_t new_offset=header_check_tiff_le(in, le32(*tiff_next_diroff), depth, count+1);
    if(new_offset==-1)
      return -1;
    if(max_offset < new_offset)
      max_offset=new_offset;
  }
  return max_offset;
}

static uint64_t header_check_tiff_be(FILE *in, const uint32_t tiff_diroff, const unsigned int depth, const unsigned int count)
{
  unsigned char buffer[8192];
  unsigned int i,n;
  int data_read;
  uint32_t *tiff_next_diroff;
  uint64_t max_offset=0;
  uint64_t strip_offsets=0;
  uint64_t strip_bytecounts=0;
  uint64_t jpegifoffset=0;
  uint64_t jpegifbytecount=0;
  TIFFDirEntry *entry=(TIFFDirEntry *)&buffer[2];
  if(depth>4)
    return 0;
  if(count>16)
    return 0;
  if(tiff_diroff == 0)
    return 0;
  if(tiff_diroff % 2 != 0)
    return -1;
  if(fseek(in, tiff_diroff, SEEK_SET) < 0)
    return -1;
  data_read=fread(buffer, 1, sizeof(buffer), in);
  if(data_read<2)
    return -1;
  n=(buffer[0]<<8)+buffer[1];
#ifdef DEBUG_TIFF
  log_info("header_check_tiff_be(in, %lu, %u, %u) => %u entries\n", (long unsigned)tiff_diroff, depth, count, n);
#endif
  //sizeof(TIFFDirEntry)=12;
  if(n > (data_read-2)/12)
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
      if(new_offset==-1)
	return -1;
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
      case TIFFTAG_EXIFIFD:
      case TIFFTAG_KODAKIFD:
      case TIFFTAG_SUBIFD:
	if(val==4)
	{
	  uint64_t new_offset=header_check_tiff_be(in, be32(entry->tdir_offset), depth+1, 0);
	  if(new_offset==-1)
	    return -1;
	  if(max_offset < new_offset)
	    max_offset=new_offset;
	}
	else if(val>4)
	{
	  const unsigned int nbr=be32(entry->tdir_count);
	  if(nbr<25)
	  {
	    unsigned int j;
	    uint32_t *subifd_offsetp;
	    subifd_offsetp=(uint32_t *)malloc(nbr*sizeof(*subifd_offsetp));
	    if(fseek(in, be32(entry->tdir_offset), SEEK_SET) < 0)
	      return -1;
	    if(fread(subifd_offsetp, sizeof(*subifd_offsetp), nbr, in) != nbr)
	      return -1;
	    for(j=0; j<nbr; j++)
	    {
	      const uint64_t new_offset=header_check_tiff_be(in, be32(subifd_offsetp[j]), depth+1, 0);
	      if(new_offset==-1)
		return -1;
	      if(max_offset < new_offset)
		max_offset = new_offset;
	    }
	  }
	}
	break;
    }
    entry++;
  }
  if(strip_bytecounts > 0 && max_offset < strip_offsets + strip_bytecounts)
    max_offset = strip_offsets + strip_bytecounts;
  if(jpegifbytecount > 0 && max_offset < jpegifoffset + jpegifbytecount)
    max_offset = jpegifoffset + jpegifbytecount;
  tiff_next_diroff=(uint32_t *)entry;
  {
    uint64_t new_offset=header_check_tiff_be(in, be32(*tiff_next_diroff), depth, count+1);
    if(new_offset==-1)
      return -1;
    if(max_offset < new_offset)
      max_offset=new_offset;
  }
  return max_offset;
}

static void file_check_tiff(file_recovery_t *fr)
{
  static uint64_t calculated_file_size=0;
  TIFFHeader header;
  calculated_file_size = 0;
  fseek(fr->handle, 0, SEEK_SET);
  if(fread(&header, sizeof(header), 1, fr->handle) != 1)
    return;
  if(header.tiff_magic==TIFF_LITTLEENDIAN)
    calculated_file_size=header_check_tiff_le(fr->handle, le32(header.tiff_diroff), 0, 0);
  else if(header.tiff_magic==TIFF_BIGENDIAN)
    calculated_file_size=header_check_tiff_be(fr->handle, be32(header.tiff_diroff), 0, 0);
  if(fr->file_size < calculated_file_size)
    fr->file_size=0;
    /* PhotoRec isn't yet capable to find the correct Sony arw filesize,
     * so don't truncate them */
  else if(strcmp(fr->extension,"arw")!=0)
    fr->file_size=calculated_file_size;
}
