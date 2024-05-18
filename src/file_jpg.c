/*

    File: file_jpg.c

    Copyright (C) 1998-2009 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_jpg)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#if defined(DISABLED_FOR_FRAMAC)
#undef HAVE_LIBJPEG
#undef DEBUG_JPEG
#undef HAVE_JPEGLIB_H
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
#include <errno.h>
#include "types.h"
#ifdef HAVE_SETJMP_H
#include <setjmp.h>
#endif
#ifdef HAVE_JPEGLIB_H
#include <jpeglib.h>
#include "suspend.h"
#endif
#include <ctype.h>      /* isprint */
#include "filegen.h"
#include "common.h"
#include "log.h"
#include "file_jpg.h"
#if !defined(MAIN_jpg) && !defined(SINGLE_FORMAT)
#include "file_riff.h"
#endif
#include "file_tiff.h"
#include "setdate.h"
#if defined(__FRAMAC__)
#include "__fc_builtin.h"
#endif

#if !defined(MAIN_jpg) && !defined(SINGLE_FORMAT)
extern const file_hint_t file_hint_doc;
extern const file_hint_t file_hint_indd;
extern const file_hint_t file_hint_mov;
extern const file_hint_t file_hint_riff;
extern const file_hint_t file_hint_rw2;
#endif

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_jpg(file_stat_t *file_stat);
static void file_check_jpg(file_recovery_t *file_recovery);
static data_check_t data_check_jpg(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery);

/*@
  @ requires i < buffer_size;
  @ requires \valid_read(buffer+(0..buffer_size-1));
  @ assigns \nothing;
  @*/
static int jpg_check_dht(const unsigned char *buffer, const unsigned int buffer_size, const unsigned i, const unsigned int size);

const file_hint_t file_hint_jpg= {
  .extension="jpg",
  .description="JPG picture",
  .max_filesize=50*1024*1024,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_jpg
};

/*@
  @ requires PHOTOREC_MAX_BLOCKSIZE >= buffer_size;
  @ requires \valid_read(buffer + (0 .. buffer_size-1));
  @ requires \valid(height);
  @ requires \valid(width);
  @ requires \separated(buffer, height, width);
  @ terminates \true;
  @ assigns *height, *width;
  @*/
static void jpg_get_size(const unsigned char *buffer, const unsigned int buffer_size, unsigned int *height, unsigned int *width)
{
  unsigned int i=2;
  /*@
    @ loop invariant i< buffer_size + 2 + 0xffff;
    @ loop assigns i, *height, *width;
    @ loop variant buffer_size - i;
    @ */
  while(i+8<buffer_size)
  {
    if(buffer[i]==0xFF && buffer[i+1]==0xFF)
      i++;
    else if(buffer[i]==0xFF)
    {
      /*@ assert 0<= (buffer[i+2]<<8) <= 0xff00; */
      /*@ assert 0 <= ((buffer[i+2]<<8) | buffer[i+3]) <= 0xffff; */
      const unsigned int size=((unsigned int)buffer[i+2]<<8)|buffer[i+3];
      /*@ assert size <= 0xffff; */
      if(buffer[i+1]==0xc0)	/* SOF0 */
      {
	/*@ assert 0<= (buffer[i+5]<<8) <= 0xff00; */
	/*@ assert 0 <= ((buffer[i+5]<<8) | buffer[i+6]) <= 0xffff; */
	*height=((unsigned int)buffer[i+5]<<8)|buffer[i+6];
	/*@ assert 0<= (buffer[i+7]<<8) <= 0xff00; */
        /*@ assert 0 <= ((buffer[i+7]<<8) | buffer[i+8]) <= 0xffff; */
	*width=((unsigned int)buffer[i+7]<<8)|buffer[i+8];
	return;
      }
      i+=2+size;
    }
    else
    {
      return;
    }
  }
}

struct MP_IFD_Field
{
  uint16_t tag;
  uint16_t type;
  uint32_t count;
  char     value[4];
} __attribute__ ((gcc_struct, __packed__));

struct MP_Entry
{
  uint32_t attr;
  uint32_t size;
  uint32_t offset;
  uint16_t dep1;
  uint16_t dep2;
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires \valid(handle);
  @ requires size >= 8;
  @ requires \valid_read(mpo + ( 0 .. size-1));
  @ requires mpo_offset <= PHOTOREC_MAX_FILE_SIZE;
  @ requires separation: \separated(handle, &errno, &Frama_C_entropy_source, mpo + (..));
  @ assigns *handle, errno;
  @ assigns Frama_C_entropy_source;
  @*/
static uint64_t file_check_mpo_be(FILE *handle, const unsigned char *mpo, const uint64_t mpo_offset, const unsigned int size)
{
  const uint16_t *tmp16;
  const uint32_t *tmp32=(const uint32_t *)(&mpo[4]);
  unsigned int offset=be32(*tmp32);
  /*@ assert 0 <= offset <= 0xffffffff; */
  unsigned int i;
  unsigned int nbr;
  unsigned int NumberOfImages=0;
  unsigned int MPEntry_offset=0;
  uint64_t max_offset=0;
#ifdef DEBUG_JPEG
  log_info("file_check_mpo_be\n");
#endif
  if(offset >= size - 2)
    return 0;
  /*@ assert offset < size - 2; */
  tmp16=(const uint16_t*)(&mpo[offset]);
  nbr=be16(*tmp16);
  /*@ assert 0 <= nbr < 65536; */
  offset+=2;
  /* @offset: MP Index Fields*/
  if(offset + nbr * 12 > size)
    return 0;
  /*@ assert offset + nbr * 12 <= size; */
  /*@
    @ loop invariant 0 <= i <= nbr;
    @ loop assigns i, NumberOfImages, MPEntry_offset;
    @ loop variant nbr-i;
    @*/
  for(i=0; i< nbr; i++)
  {
    /*@ assert 0 <= i < nbr; */
    const unsigned char *field_ptr=&mpo[offset + i * 12];
    /*@ assert \valid_read(field_ptr + ( 0 .. sizeof(struct MP_IFD_Field)-1)); */
    const struct MP_IFD_Field *field=(const struct MP_IFD_Field *)field_ptr;
    const unsigned int count=be32(field->count);
    /*@ assert 0 <= count <= 0xffffffff; */
    const unsigned int type=be16(field->type);
    /*@ assert 0 <= type < 65536; */
    switch(be16(field->tag))
    {
      case 0xb000:
	/* MPFVersion, type must be undefined */
	if(type!=7 || count!=4)
	  return 0;
	break;
      case 0xb001:
	/* NumberOfImages, type must be long */
	if(type!=4 || count!=1)
	  return 0;
	{
	  const uint32_t *tmp=(const uint32_t *)&field->value[0];
	  NumberOfImages=be32(*tmp);
	  /*@ assert 0 <= NumberOfImages <= 0xffffffff; */
	  if(NumberOfImages >= 0x100000)
	    return 0;
	  /*@ assert NumberOfImages < 0x100000; */
	}
	break;
      case 0xb002:
	/* MPEntry, type must be undefined */
	if(type!=7 || count!=sizeof(struct MP_Entry)*NumberOfImages)
	  return 0;
	{
	  const uint32_t *tmp=(const uint32_t *)&field->value[0];
	  MPEntry_offset=be32(*tmp);
	  /*@ assert 0 <= MPEntry_offset <= 0xffffffff; */
	}
	break;
    }
  }
#ifdef DEBUG_JPEG
  log_info("MPEntry_offset=%u, NumberOfImages=%u\n", MPEntry_offset, NumberOfImages);
#endif
  /*@ assert NumberOfImages < 0x100000; */
  if(MPEntry_offset > size)
    return 0;
  if(MPEntry_offset + sizeof(struct MP_Entry)*NumberOfImages > size)
    return 0;
  /*@ assert MPEntry_offset + sizeof(struct MP_Entry)*NumberOfImages <= size; */
  /*@
    @ loop invariant 0 <= i <= NumberOfImages;
    @ loop assigns i, max_offset, *handle, errno;
    @ loop assigns Frama_C_entropy_source;
    @ loop variant NumberOfImages-i;
    @*/
  for(i=0; i<NumberOfImages; i++)
  {
    static const unsigned char jpg_header[3]= { 0xff,0xd8,0xff};
    char buffer[3];
    const unsigned char *MPEntry_ptr=&mpo[MPEntry_offset + i * sizeof(struct MP_Entry)];
    /*@ assert \valid_read(MPEntry_ptr+ ( 0 .. sizeof(struct MP_Entry)-1)); */
    const struct MP_Entry *MPEntry=(const struct MP_Entry*)MPEntry_ptr;
    /*@ assert \valid_read(MPEntry); */
    uint64_t tmp=be32(MPEntry->offset);
    /*@ assert 0 <= tmp <= 0xffffffff; */
#ifdef DEBUG_JPEG
    log_info("offset=%lu, size=%lu\n",
	(long unsigned)be32(MPEntry->offset),
	(long unsigned)be32(MPEntry->size));
#endif
    if(tmp>0)
      tmp+=mpo_offset;
    if(my_fseek(handle, tmp, SEEK_SET) < 0 ||
      fread(buffer, sizeof(buffer), 1, handle) != 1)
      return 0;
    tmp+=be32(MPEntry->size);
#ifdef __FRAMAC__
    Frama_C_make_unknown((char *)&buffer, sizeof(buffer));
#endif
    if(memcmp(buffer, jpg_header, sizeof(jpg_header))!=0)
      return 0;
    if(max_offset < tmp)
      max_offset = tmp;
  }
  return max_offset;
}

/*@
  @ requires \valid(handle);
  @ requires size >= 8;
  @ requires \valid_read(mpo + ( 0 .. size-1));
  @ requires mpo_offset <= PHOTOREC_MAX_FILE_SIZE;
  @ requires separation: \separated(handle, &errno, &Frama_C_entropy_source, mpo + (..));
  @ assigns *handle, errno;
  @ assigns Frama_C_entropy_source;
  @*/
static uint64_t file_check_mpo_le(FILE *handle, const unsigned char *mpo, const uint64_t mpo_offset, const unsigned int size)
{
  const uint16_t *tmp16;
  /* Offset to first IFD */
  const uint32_t *tmp32=(const uint32_t *)(&mpo[4]);
  unsigned int offset=le32(*tmp32);
  unsigned int i;
  unsigned int nbr;
  unsigned int NumberOfImages=0;
  unsigned int MPEntry_offset=0;
  uint64_t max_offset=0;
#ifdef DEBUG_JPEG
  log_info("file_check_mpo_le\n");
#endif
  if(offset >= size - 2)
    return 0;
  /*@ assert offset < size - 2; */
  tmp16=(const uint16_t*)(&mpo[offset]);
  nbr=le16(*tmp16);
  offset+=2;
  /* @offset: MP Index Fields*/
  if(offset + nbr * 12 > size)
    return 0;
  /*@ assert offset + nbr * 12 <= size; */
  /*@
    @ loop invariant 0 <= i <= nbr;
    @ loop assigns i, NumberOfImages, MPEntry_offset;
    @ loop variant nbr-i;
    @*/
  for(i=0; i< nbr; i++)
  {
    /*@ assert 0 <= i < nbr; */
    const unsigned char *field_ptr=&mpo[offset + i * 12];
    /*@ assert \valid_read(field_ptr + ( 0 .. sizeof(struct MP_IFD_Field)-1)); */
    const struct MP_IFD_Field *field=(const struct MP_IFD_Field *)field_ptr;
    /*@ assert \valid_read(field); */
    const unsigned int count=le32(field->count);
    const unsigned int type=le16(field->type);
    switch(le16(field->tag))
    {
      case 0xb000:
	/* MPFVersion, type must be undefined */
	if(type!=7 || count!=4)
	  return 0;
	break;
      case 0xb001:
	/* NumberOfImages, type must be long */
	if(type!=4 || count!=1)
	  return 0;
	{
	  const uint32_t *tmp=(const uint32_t *)&field->value[0];
	  NumberOfImages=le32(*tmp);
	  if(NumberOfImages >= 0x100000)
	    return 0;
	  /*@ assert NumberOfImages < 0x100000; */
	}
	break;
      case 0xb002:
	/* MPEntry, type must be undefined */
	if(type!=7 || count!=sizeof(struct MP_Entry)*NumberOfImages)
	  return 0;
	{
	  const uint32_t *tmp=(const uint32_t *)&field->value[0];
	  MPEntry_offset=le32(*tmp);
	}
	break;
    }
  }
#ifdef DEBUG_JPEG
  log_info("MPEntry_offset=%u, NumberOfImages=%u\n", MPEntry_offset, NumberOfImages);
#endif
  /*@ assert NumberOfImages < 0x100000; */
  if(NumberOfImages == 0)
    return 0;
  /*@ assert 0 < NumberOfImages < 0x100000; */
  if(MPEntry_offset >= size)
    return 0;
  /*@ assert size > MPEntry_offset; */
  if(MPEntry_offset + sizeof(struct MP_Entry)*NumberOfImages > size)
    return 0;
  /*@ assert MPEntry_offset + sizeof(struct MP_Entry)*NumberOfImages <= size; */
  /*@
    @ loop invariant 0 <= i <= NumberOfImages;
    @ loop assigns i, max_offset, *handle, errno;
    @ loop assigns Frama_C_entropy_source;
    @ loop variant NumberOfImages-i;
    @*/
  for(i=0; i<NumberOfImages; i++)
  {
    static const unsigned char jpg_header[3]= { 0xff,0xd8,0xff};
    char buffer[3];
    const unsigned char *MPEntry_ptr=&mpo[MPEntry_offset + i * sizeof(struct MP_Entry)];
    /*@ assert \valid_read(MPEntry_ptr+ ( 0 .. sizeof(struct MP_Entry)-1)); */
    const struct MP_Entry *MPEntry=(const struct MP_Entry*)MPEntry_ptr;
    /*@ assert \valid_read(MPEntry); */
    uint64_t tmp=le32(MPEntry->offset);
#ifdef DEBUG_JPEG
    log_info("mpo_offset=%lu offset=%lu, size=%lu\n",
        (long unsigned)mpo_offset,
	(long unsigned)le32(MPEntry->offset),
	(long unsigned)le32(MPEntry->size));
#endif
    if(tmp>0)
      tmp+=mpo_offset;
    if(my_fseek(handle, tmp, SEEK_SET) < 0 ||
      fread(buffer, sizeof(buffer), 1, handle) != 1)
      return 0;
    tmp+=le32(MPEntry->size);
#ifdef __FRAMAC__
    Frama_C_make_unknown((char *)&buffer, sizeof(buffer));
#endif
    if(memcmp(buffer, jpg_header, sizeof(jpg_header))!=0)
      return 0;
    if(max_offset < tmp)
      max_offset = tmp;
  }
  return max_offset;
}

/*@
  @ requires size >= 8;
  @ requires \valid_read(mpo + ( 0 .. size-1));
  @ assigns \nothing;
  @*/
static uint64_t check_mpo_be(const unsigned char *mpo, const uint64_t mpo_offset, const unsigned int size)
{
  const uint16_t *tmp16;
  const uint32_t *tmp32=(const uint32_t *)(&mpo[4]);
  unsigned int offset=be32(*tmp32);
  /*@ assert 0 <= offset <= 0xffffffff; */
  unsigned int i;
  unsigned int nbr;
  unsigned int NumberOfImages=0;
  unsigned int MPEntry_offset=0;
  uint64_t max_offset=0;
#ifdef DEBUG_JPEG
  log_info("check_mpo_be\n");
#endif
  if(offset >= size - 2)
    return 0;
  /*@ assert offset < size - 2; */
  tmp16=(const uint16_t*)(&mpo[offset]);
  nbr=be16(*tmp16);
  /*@ assert 0 <= nbr < 65536; */
  offset+=2;
  /* @offset: MP Index Fields*/
  if(offset + nbr * 12 > size)
    return 0;
  /*@ assert offset + nbr * 12 <= size; */
  /*@
    @ loop invariant 0 <= i <= nbr;
    @ loop assigns i, NumberOfImages, MPEntry_offset;
    @ loop variant nbr-i;
    @*/
  for(i=0; i< nbr; i++)
  {
    /*@ assert 0 <= i < nbr; */
    const unsigned char *field_ptr=&mpo[offset + i * 12];
    /*@ assert \valid_read(field_ptr + ( 0 .. sizeof(struct MP_IFD_Field)-1)); */
    const struct MP_IFD_Field *field=(const struct MP_IFD_Field *)field_ptr;
    const unsigned int count=be32(field->count);
    /*@ assert 0 <= count <= 0xffffffff; */
    const unsigned int type=be16(field->type);
    /*@ assert 0 <= type < 65536; */
    switch(be16(field->tag))
    {
      case 0xb000:
	/* MPFVersion, type must be undefined */
	if(type!=7 || count!=4)
	  return 0;
	break;
      case 0xb001:
	/* NumberOfImages, type must be long */
	if(type!=4 || count!=1)
	  return 0;
	{
	  const uint32_t *tmp=(const uint32_t *)&field->value[0];
	  NumberOfImages=be32(*tmp);
	  /*@ assert 0 <= NumberOfImages <= 0xffffffff; */
	  if(NumberOfImages >= 0x100000)
	    return 0;
	  /*@ assert NumberOfImages < 0x100000; */
	}
	break;
      case 0xb002:
	/* MPEntry, type must be undefined */
	if(type!=7 || count!=sizeof(struct MP_Entry)*NumberOfImages)
	  return 0;
	{
	  const uint32_t *tmp=(const uint32_t *)&field->value[0];
	  MPEntry_offset=be32(*tmp);
	  /*@ assert 0 <= MPEntry_offset <= 0xffffffff; */
	}
	break;
    }
  }
#ifdef DEBUG_JPEG
  log_info("MPEntry_offset=%u, NumberOfImages=%u\n", MPEntry_offset, NumberOfImages);
#endif
  /*@ assert NumberOfImages < 0x100000; */
  if(NumberOfImages == 0)
    return 0;
  if(MPEntry_offset > size)
    return 0;
  if(MPEntry_offset + sizeof(struct MP_Entry)*NumberOfImages > size)
    return 0;
  /*@
    @ loop invariant 0 <= i <= NumberOfImages;
    @ loop assigns i, max_offset;
    @ loop variant NumberOfImages-i;
    @*/
  for(i=0; i<NumberOfImages; i++)
  {
    /*@ assert 0 <= i < NumberOfImages; */
    const unsigned char *MPEntry_ptr=&mpo[MPEntry_offset + i * sizeof(struct MP_Entry)];
    /*@ assert \valid_read(MPEntry_ptr+ ( 0 .. sizeof(struct MP_Entry)-1)); */
    const struct MP_Entry *MPEntry=(const struct MP_Entry*)MPEntry_ptr;
    uint64_t tmp=be32(MPEntry->size);
    /*@ assert 0 <= tmp <= 0xffffffff; */
#ifdef DEBUG_JPEG
    log_info("offset=%lu, size=%lu\n",
	(long unsigned)be32(MPEntry->offset),
	(long unsigned)be32(MPEntry->size));
#endif
    if(be32(MPEntry->offset)>0)
      tmp+=(uint64_t)be32(MPEntry->offset)+mpo_offset;
    if(max_offset < tmp)
      max_offset = tmp;
  }
  return max_offset;
}

/*@
  @ requires size >= 8;
  @ requires \valid_read(mpo + ( 0 .. size-1));
  @ assigns \nothing;
  @*/
static uint64_t check_mpo_le(const unsigned char *mpo, const uint64_t mpo_offset, const unsigned int size)
{
  const uint16_t *tmp16;
  /* Offset to first IFD */
  const uint32_t *tmp32=(const uint32_t *)(&mpo[4]);
  unsigned int offset=le32(*tmp32);
  unsigned int i;
  unsigned int nbr;
  unsigned int NumberOfImages=0;
  unsigned int MPEntry_offset=0;
  uint64_t max_offset=0;
#ifdef DEBUG_JPEG
  log_info("check_mpo_le\n");
#endif
  if(offset >= size - 2)
    return 0;
  /*@ assert offset < size - 2; */
  tmp16=(const uint16_t*)(&mpo[offset]);
  nbr=le16(*tmp16);
  offset+=2;
  /* @offset: MP Index Fields*/
  if(offset + nbr * 12 > size)
    return 0;
  /*@ assert offset + nbr * 12 <= size; */
  /*@
    @ loop invariant 0 <= i <= nbr;
    @ loop assigns i, NumberOfImages, MPEntry_offset;
    @ loop variant nbr-i;
    @*/
  for(i=0; i< nbr; i++)
  {
    /*@ assert 0 <= i < nbr; */
    const unsigned char *field_ptr=&mpo[offset + i * 12];
    /*@ assert \valid_read(field_ptr + ( 0 .. sizeof(struct MP_IFD_Field)-1)); */
    const struct MP_IFD_Field *field=(const struct MP_IFD_Field *)field_ptr;
    /*@ assert \valid_read(field); */
    const unsigned int count=le32(field->count);
    const unsigned int type=le16(field->type);
    switch(le16(field->tag))
    {
      case 0xb000:
	/* MPFVersion, type must be undefined */
	if(type!=7 || count!=4)
	  return 0;
	break;
      case 0xb001:
	/* NumberOfImages, type must be long */
	if(type!=4 || count!=1)
	  return 0;
	{
	  const uint32_t *tmp=(const uint32_t *)&field->value[0];
	  NumberOfImages=le32(*tmp);
	  if(NumberOfImages >= 0x100000)
	    return 0;
	  /*@ assert NumberOfImages < 0x100000; */
	}
	break;
      case 0xb002:
	/* MPEntry, type must be undefined */
	if(type!=7 || count!=sizeof(struct MP_Entry)*NumberOfImages)
	  return 0;
	{
	  const uint32_t *tmp=(const uint32_t *)&field->value[0];
	  MPEntry_offset=le32(*tmp);
	}
	break;
    }
  }
#ifdef DEBUG_JPEG
  log_info("MPEntry_offset=%u, NumberOfImages=%u\n", MPEntry_offset, NumberOfImages);
#endif
  /*@ assert NumberOfImages < 0x100000; */
  if(MPEntry_offset > size)
    return 0;
  if(MPEntry_offset + sizeof(struct MP_Entry)*NumberOfImages > size)
    return 0;
  /*@
    @ loop invariant 0 <= i <= NumberOfImages;
    @ loop assigns i, max_offset;
    @ loop variant NumberOfImages-i;
    @*/
  for(i=0; i<NumberOfImages; i++)
  {
    /*@ assert 0 <= i < NumberOfImages; */
    const unsigned char *MPEntry_ptr=&mpo[MPEntry_offset + i * sizeof(struct MP_Entry)];
    /*@ assert \valid_read(MPEntry_ptr+ ( 0 .. sizeof(struct MP_Entry)-1)); */
    const struct MP_Entry *MPEntry=(const struct MP_Entry*)MPEntry_ptr;
    uint64_t tmp=le32(MPEntry->size);
#ifdef DEBUG_JPEG
    log_info("mpo_offset=%lu offset=%lu, size=%lu\n",
        (long unsigned)mpo_offset,
	(long unsigned)le32(MPEntry->offset),
	(long unsigned)le32(MPEntry->size));
#endif
    if(le32(MPEntry->offset)>0)
      tmp+=(uint64_t)le32(MPEntry->offset) + mpo_offset;
    if(max_offset < tmp)
      max_offset = tmp;
  }
  return max_offset;
}

/*@
  @ requires size >= 8;
  @ requires \valid_read(mpo + ( 0 .. size-1));
  @ assigns \nothing;
  @*/
static uint64_t check_mpo(const unsigned char *mpo, const uint64_t offset, const unsigned int size)
{
  /* MP header:
   * - MP Endian (4Byte)
   * - Offset to First IFD (4Byte)
   */
  if(mpo[0]=='I' && mpo[1]=='I' && mpo[2]=='*' && mpo[3]==0)
  {
    return check_mpo_le(mpo, offset, size);
  }
  else if(mpo[0]=='M' && mpo[1]=='M' && mpo[2]==0 && mpo[3]=='*')
  {
    return check_mpo_be(mpo, offset, size);
  }
  return 0;
}

/*@
  @ requires \valid(handle);
  @ requires size >= 8;
  @ requires \valid_read(mpo + ( 0 .. size-1));
  @ requires separation: \separated(handle, &errno, &Frama_C_entropy_source, mpo + (..));
  @ assigns *handle, errno;
  @ assigns Frama_C_entropy_source;
  @*/
static uint64_t file_check_mpo_aux(FILE *handle, const unsigned char *mpo, const uint64_t offset, const unsigned int size)
{
  /* MP header:
   * - MP Endian (4Byte)
   * - Offset to First IFD (4Byte)
   */
  if(offset > PHOTOREC_MAX_FILE_SIZE)
    return 0;
  /*@ assert offset <= PHOTOREC_MAX_FILE_SIZE; */
  if(mpo[0]=='I' && mpo[1]=='I' && mpo[2]=='*' && mpo[3]==0)
  {
    return file_check_mpo_le(handle, mpo, offset, size);
  }
  else if(mpo[0]=='M' && mpo[1]=='M' && mpo[2]==0 && mpo[3]=='*')
  {
    return file_check_mpo_be(handle, mpo, offset, size);
  }
  return 0;
}

/*@
  @ requires fr->file_check==&file_check_mpo;
  @ requires separation: \separated(fr, fr->handle, &errno, &Frama_C_entropy_source);
  @ requires valid_file_check_param(fr);
  @ ensures  valid_file_check_result(fr);
  @ assigns  errno;
  @ assigns  Frama_C_entropy_source;
  @ assigns  fr->calculated_file_size;
  @ assigns  fr->extra;
  @ assigns  fr->file_size;
  @ assigns  fr->flags;
  @ assigns  *fr->handle;
  @ assigns  fr->offset_error;
  @ assigns  fr->offset_ok;
  @ assigns  fr->time;
  @*/
static void file_check_mpo(file_recovery_t *fr)
{
  char sbuffer[512];
  const unsigned char *buffer=(const unsigned char *)&sbuffer;
  uint64_t offset=0;
  unsigned int size=0;
  size_t nbytes;
  uint64_t jpg_fs;
#ifdef DEBUG_JPEG
  log_info("file_check_mpo  %s calculated_file_size=%llu, error at %llu\n", fr->filename,
      (long long unsigned)fr->calculated_file_size,
      (long long unsigned)fr->offset_error);
#endif
  {
    /* Check the first jpg */
    const uint64_t fs=fr->file_size;
#if defined(HAVE_LIBJPEG) && defined(HAVE_JPEGLIB_H)
    fr->calculated_file_size=0;
#endif
    file_check_jpg(fr);
    if(fr->file_size==0)
      return ;
    jpg_fs=fr->file_size;
    fr->file_size=fs;
  }
  /*@
    @ loop assigns *fr->handle, Frama_C_entropy_source, errno;
    @ loop assigns sbuffer[0 .. 511], fr->file_size, offset, nbytes, size;
    @ loop variant 0x8000000000000000 - offset;
    @*/
  do
  {
    offset+=(uint64_t)2+size;
    if(offset >= 0x8000000000000000)
    {
      fr->file_size=0;
      return ;
    }
    /*@ assert offset < 0x8000000000000000; */
    if(my_fseek(fr->handle, offset, SEEK_SET) < 0)
    {
      fr->file_size=0;
      return ;
    }
    nbytes=fread(&sbuffer, 1, sizeof(sbuffer), fr->handle);
#if defined(__FRAMAC__)
    Frama_C_make_unknown(sbuffer, sizeof(sbuffer));
#endif
//    log_info("file_check_mpo offset=%llu => nbytes=%d, buffer=%02x %02x\n",
//    (long long unsigned)offset, nbytes, buffer[0], buffer[1]);
    /* 0xda SOS Start Of Scan */
    if(nbytes<8 || buffer[0]!=0xff || buffer[1]==0xda)
    {
      fr->file_size=0;
      return ;
    }
    /*@ assert nbytes >= 8; */
    size=((unsigned int)buffer[2]<<8)+buffer[3];
  } while(!(buffer[1]==0xe2 &&
	  buffer[4]=='M' && buffer[5]=='P' && buffer[6]=='F' && buffer[7]==0));
#ifdef DEBUG_JPEG
  log_info("Found at %lu\n", (long unsigned)offset);
#endif
  if(8+size > nbytes)
  {
    size=nbytes-8;
    /*@ assert size == nbytes - 8; */
  }
  /*@ assert 8 + size <= nbytes; */
  if(size<16)
  {
    fr->file_size=0;
    return ;
  }
  /*@ assert 16 <= size <= 65535; */
  {
    const uint64_t max_offset=check_mpo(buffer+8, offset+8, size-8);
    if(max_offset > fr->file_size)
    {
      fr->file_size=0;
      return ;
    }
    fr->file_size=max_offset;
  }
  if(file_check_mpo_aux(fr->handle, buffer+8, offset+8, size-8) == 0)
  {
#ifndef DISABLED_FOR_FRAMAC
    log_info("file_check_mpo  %s failed, limiting to first jpeg: %llu\n", fr->filename, (long long unsigned)jpg_fs);
#endif
    fr->file_size=jpg_fs;
  }
}

/*@
  @ terminates \true;
  @ assigns \nothing;
  @*/
static int is_marker_valid(const unsigned int marker)
{
  switch(marker)
  {
    case 0xc0:		/* SOF0 Start of Frame */
    case 0xc1:		/* SOF1 Extended sequential */
    case 0xc2:		/* SOF2 Progressive */
    case 0xc3:		/* SOF3 Lossless */
    case 0xc4:		/* Define Huffman table */
    case 0xc5:		/* SOF5 Differential sequential */
    case 0xc6:		/* SOF6 Differential progressive */
    case 0xc7:		/* SOF7 Differential lossless */
    case 0xc8:		/* Start of Frame (JPG) (Reserved for JPEG extensions) */
    case 0xc9:		/* SOF9 Extended sequential, arithmetic coding */
    case 0xca:		/* SOF10 Progressive, arithmetic coding */
    case 0xcb:		/* SOF11 Lossless, arithmetic coding */
    case 0xcc:		/* DAC arithmetic-coding conditioning*/
    case 0xcd:		/* SOF13 Differential sequential, arithmetic coding */
    case 0xce:		/* SOF14 Differential progressive, arithmetic coding */
    case 0xcf:		/* SOF15 Differential lossless, arithmetic coding */
    case 0xdb:		/* DQT: Define Quantization Table */
    case 0xdd:		/* DRI: define restart interval */
    case 0xe0 ... 0xef:	/* APP0 - APP15 */
    case 0xfe:		/* COM */
    case 0xff:
      return 1;
#if 0
    case 0x02 ... 0xbf:	/* Reserved */
    case 0xd0 ... 0xd7:	/* JPEG_RST0 .. JPEG_RST7 markers */
    case 0xd8:	/* SOI Start of Image */
    case 0xd9:	/* EOI End of Image */
    case 0xda:	/* SOS: Start Of Scan */
    case 0xdc:		/* DNL: Define Number of Lines */
    case 0xde:		/* DHP: define hierarchical progression */
    case 0xf0 ... 0xfd:	/* Reserved for JPEG extensions */
#endif
    default:
      return 0;
  }
}

/*@
  @ requires \valid_read(buffer + (0 .. buffer_size-1));
  @ assigns  \nothing;
  @*/
static time_t jpg_get_date(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int i, const unsigned int size)
{ /* APP1 Exif information */
  const unsigned int tiff_offset=i+2+8;
  if(tiff_offset < buffer_size && size > 8)
  {
    /*@ assert tiff_offset < buffer_size; */
    /*@ assert size > 8; */
    unsigned int tiff_size=size-0x08;
    if(buffer_size - tiff_offset < tiff_size)
    {
      tiff_size=buffer_size - tiff_offset;
      /*@ assert tiff_offset + tiff_size == buffer_size; */
    }
    else
    {
      /*@ assert tiff_offset + tiff_size <= buffer_size; */
    }
    /*@ assert tiff_offset + tiff_size <= buffer_size; */
    return get_date_from_tiff_header(&buffer[tiff_offset], tiff_size);
  }
  return 0;
}


/*@
  @ requires PHOTOREC_MAX_BLOCKSIZE >= buffer_size >= 10;
  @ requires separation: \separated(&file_hint_jpg, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ ensures \result == 1 ==> file_recovery_new->file_size == 0;
  @ ensures (\result == 1) ==> (file_recovery_new->extension != \null);
  @ ensures \result == 1 ==> file_recovery_new->calculated_file_size == 0;
  @ ensures \result == 1 && buffer_size >= 4 ==> file_recovery_new->data_check == data_check_jpg;
  @ ensures \result == 1 ==> file_recovery_new->file_check == file_check_jpg;
  @ ensures \result == 1 ==> file_recovery_new->file_rename == \null;
  @ ensures \result == 1 ==> file_recovery_new->extension == file_hint_jpg.extension;
  @ ensures \result == 1 ==> file_recovery_new->min_filesize > 0;
  @ ensures \result == 1 ==> file_recovery_new->offset_ok == 0;
  @*/
static int header_check_jpg(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /*@ assert valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new); */
  unsigned int i=2;
  time_t jpg_time=0;
  /*@
    @ loop invariant \valid_read(buffer+(0..buffer_size-1));
    @ loop invariant \initialized(buffer+(0..buffer_size-1));
    @ loop assigns i, jpg_time;
    @ loop variant buffer_size - (i+4);
    @*/
  while(i+4<buffer_size && buffer[i]==0xff && is_marker_valid(buffer[i+1]))
  {
    const unsigned int size=((unsigned int)buffer[i+2]<<8)+buffer[i+3];
    if(buffer[i+1]==0xff)
      i++;
    else
    {
      if(buffer[i+1]==0xe1)
      { /* APP1 Exif information */
	jpg_time=jpg_get_date(buffer, buffer_size, i, size);
      }
      else if(buffer[i+1]==0xc4)
      {
	/* DHT */
	if(jpg_check_dht(buffer, buffer_size, i, 2+((unsigned int)buffer[i+2]<<8)+buffer[i+3])!=0)
	  return 0;
      }
      i+=2+size;
    }
  }
  if(i < file_recovery_new->blocksize && buffer[i]!=0xff)
    return 0;
  if(i+1 < file_recovery_new->blocksize && buffer[i+1]!=0xda)
    return 0;
  if(i < 512 && buffer[i]!=0xff)
    return 0;
  if(i+1 < 512 && buffer[i+1]!=0xda)
    return 0;
  if(file_recovery->file_stat==NULL)
  {
    if(i < buffer_size && buffer[i]!=0xff)
      return 0;
    if(i+1 < buffer_size && buffer[i+1]!=0xda)
      return 0;
  }
  if(file_recovery->file_stat!=NULL &&
     file_recovery->file_check!=NULL)
  {
    static const unsigned char jpg_header_app0_avi[0x0c]= {
      0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 'A', 'V', 'I', '1', 0x00, 0x00
    };
    static const unsigned char jpg_header_app0_jfif11_null[0x14]= {
      0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00, 0x01,
      0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    static const unsigned char jpg_header_app0_jfif11_com[0x17]= {
      0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00, 0x01, 0x01, 0x01, 0x00, 0x48,
      0x00, 0x48, 0x00, 0x00, 0xff, 0xfe, 0x00
    };

    unsigned int width=0;
    unsigned int height=0;
    jpg_get_size(buffer, buffer_size, &height, &width);
#if !defined(MAIN_jpg) && !defined(SINGLE_FORMAT)
    if(file_recovery->file_stat->file_hint==&file_hint_indd)
    {
      if(header_ignored_adv(file_recovery, file_recovery_new)==0)
	return 0;
    }
    if(file_recovery->file_stat->file_hint==&file_hint_doc &&
	strstr(file_recovery->filename, ".albm")!=NULL)
    {
      if(header_ignored_adv(file_recovery, file_recovery_new)==0)
	return 0;
    }
#endif
    if( file_recovery->file_stat->file_hint==&file_hint_jpg)
    {
      /* Don't recover the thumb instead of the jpg itself */
      if( file_recovery->file_size <= 1024 &&
	buffer[3]==0xec)		/* APP12 */
      {
#ifndef DISABLED_FOR_FRAMAC
	log_info("jpg %llu %llu\n",
	    (long long unsigned)file_recovery->calculated_file_size,
	    (long long unsigned)file_recovery->file_size);
#endif
	if(header_ignored_adv(file_recovery, file_recovery_new)==0)
	  return 0;
      }
      /* Don't recover the thumb instead of the jpg itself */
      if(file_recovery->file_size <= 16384 &&
	  buffer[3]==0xe0 &&
	  width>0 && width<200 && height>0 && height<200)
      {
	if(header_ignored_adv(file_recovery, file_recovery_new)==0)
	  return 0;
      }
      /* Some JPG have two APP1 markers, avoid to dicard the first one */
      if( buffer[3]==0xe1	&&
	  memcmp(&buffer[6], "http://ns.adobe.com/xap/", 24)==0)
      {
	if(header_ignored_adv(file_recovery, file_recovery_new)==0)
	  return 0;
      }
      if(file_recovery->file_check==&file_check_mpo)
      {
	if(header_ignored_adv(file_recovery, file_recovery_new)==0)
	  return 0;
      }
    }
#if !defined(MAIN_jpg) && !defined(SINGLE_FORMAT)
    /* Don't extract jpg inside AVI */
    if( file_recovery->file_stat->file_hint==&file_hint_riff &&
	(memcmp(buffer,  jpg_header_app0_avi, sizeof(jpg_header_app0_avi))==0 ||
	 file_recovery->data_check == &data_check_avi_stream))
    {
      header_ignored(file_recovery_new);
      return 0;
    }
    /* Don't extract jpg inside MOV */
    if( file_recovery->file_stat->file_hint==&file_hint_mov &&
	(memcmp(buffer,  jpg_header_app0_jfif11_null, sizeof(jpg_header_app0_jfif11_null))==0 ||
	memcmp(buffer,  jpg_header_app0_jfif11_com, sizeof(jpg_header_app0_jfif11_com))==0))
    {
      header_ignored(file_recovery_new);
      return 0;
    }
    /* Don't extract jpg inside rw2 */
    if( file_recovery->file_stat->file_hint==&file_hint_rw2 &&
      file_recovery->file_size <= 8192)
    {
      if(header_ignored_adv(file_recovery, file_recovery_new)==0)
	return 0;
    }
#endif
    switch(buffer[3])
    {
      case 0xe0:	/* APP0 */
	if(buffer[6]!='J' || buffer[7]!='F')	/* Should be JFIF/JFXX */
	{
	  header_ignored(file_recovery_new);
	  return 0;
	}
	break;
    case 0xe1:		/* APP1 */
	if(buffer[6]!='E' || buffer[7]!='x' || buffer[8]!='i'|| buffer[9]!='f')	/* Should be Exif */
	{
	  header_ignored(file_recovery_new);
	  return 0;
	}
	break;
    case 0xfe:		/* COM */
	if(!isprint(buffer[6]) || !isprint(buffer[7]))
	{
	  header_ignored(file_recovery_new);
	  return 0;
	}
	break;
    default:
	header_ignored(file_recovery_new);
	return 0;
    }
  }
  reset_file_recovery(file_recovery_new);
  file_recovery_new->min_filesize=i;
  file_recovery_new->calculated_file_size=0;
  file_recovery_new->time=jpg_time;
  file_recovery_new->extension=file_hint_jpg.extension;
  file_recovery_new->file_check=&file_check_jpg;
  if(buffer_size >= 4)
    file_recovery_new->data_check=&data_check_jpg;
  /*@ assert valid_read_string(file_recovery_new->extension); */
  return 1;
}

#if defined(HAVE_LIBJPEG) && defined(HAVE_JPEGLIB_H)
struct my_error_mgr {
  struct jpeg_error_mgr pub;	/* "public" fields, must be the first field */

  jmp_buf setjmp_buffer;	/* for return to caller */
};

typedef struct {
  struct jpeg_source_mgr pub;	/* public fields */

  FILE * infile;		/* source stream */
  JOCTET * buffer;		/* start of buffer */
  int start_of_file;	/* have we gotten any data yet? */
  unsigned long int offset;
  unsigned long int file_size;
  unsigned long int file_size_max;
  unsigned long int offset_ok;
  unsigned int blocksize;
} my_source_mgr;

static void my_output_message (j_common_ptr cinfo);
static void my_error_exit (j_common_ptr cinfo);
static void my_emit_message (j_common_ptr cinfo, int msg_level);

static void my_output_message (j_common_ptr cinfo)
{
#ifdef DEBUG_JPEG
  struct my_error_mgr *myerr = (struct my_error_mgr *) cinfo->err;
  char buffermsg[JMSG_LENGTH_MAX];
  /* Create the message */
  (*cinfo->err->format_message) (cinfo, buffermsg);
  log_info("jpeg: %s\n", buffermsg);
#endif
}

static void my_error_exit (j_common_ptr cinfo)
{
  struct my_error_mgr *myerr = (struct my_error_mgr *) cinfo->err;
  (*cinfo->err->output_message) (cinfo);
  /* Return control to the setjmp point */
  longjmp(myerr->setjmp_buffer, 1);
}

static void my_emit_message (j_common_ptr cinfo, int msg_level)
{
  struct my_error_mgr *myerr = (struct my_error_mgr *) cinfo->err;
  struct jpeg_error_mgr *err = &myerr->pub;

  if (msg_level < 0) {
    /* It's a warning message.  Since corrupt files may generate many warnings,
     * the policy implemented here is to show only the first warning,
     * unless trace_level >= 3.
     */
    if (err->num_warnings == 0 || err->trace_level >= 3)
      (*err->output_message) (cinfo);
    /* Always count warnings in num_warnings. */
    err->num_warnings++;
    /* Return control to the setjmp point */
    longjmp(myerr->setjmp_buffer, 1);
  } else {
    /* It's a trace message.  Show it if trace_level >= msg_level. */
    if (err->trace_level >= msg_level)
      (*err->output_message) (cinfo);
  }
}

/*
 * Initialize source --- called by jpeg_read_header
 * before any data is actually read.
 */

static void jpg_init_source (j_decompress_ptr cinfo)
{
  my_source_mgr * src = (my_source_mgr *) cinfo->src;

  /* We reset the empty-input-file flag for each image,
   * but we don't clear the input buffer.
   * This is correct behavior for reading a series of images from one source.
   */
  src->start_of_file = TRUE;
  src->offset= 0;
  src->file_size = 0;
  src->file_size_max = 0;
//  src->offset_ok = 0;
}


/*
 * Fill the input buffer --- called whenever buffer is emptied.
 *
 * In typical applications, this should read fresh data into the buffer
 * (ignoring the current state of next_input_byte & bytes_in_buffer),
 * reset the pointer & count to the start of the buffer, and return TRUE
 * indicating that the buffer has been reloaded.  It is not necessary to
 * fill the buffer entirely, only to obtain at least one more byte.
 *
 * There is no such thing as an EOF return.  If the end of the file has been
 * reached, the routine has a choice of ERREXIT() or inserting fake data into
 * the buffer.  In most cases, generating a warning message and inserting a
 * fake EOI marker is the best course of action --- this will allow the
 * decompressor to output however much of the image is there.  However,
 * the resulting error message is misleading if the real problem is an empty
 * input file, so we handle that case specially.
 *
 * In applications that need to be able to suspend compression due to input
 * not being available yet, a FALSE return indicates that no more data can be
 * obtained right now, but more may be forthcoming later.  In this situation,
 * the decompressor will return to its caller (with an indication of the
 * number of scanlines it has read, if any).  The application should resume
 * decompression after it has loaded more data into the input buffer.  Note
 * that there are substantial restrictions on the use of suspension --- see
 * the documentation.
 *
 * When suspending, the decompressor will back up to a convenient restart point
 * (typically the start of the current MCU). next_input_byte & bytes_in_buffer
 * indicate where the restart point will be if the current call returns FALSE.
 * Data beyond this point must be rescanned after resumption, so move it to
 * the front of the buffer rather than discarding it.
 */

static boolean jpg_fill_input_buffer (j_decompress_ptr cinfo)
{
  my_source_mgr * src = (my_source_mgr *) cinfo->src;
  size_t nbytes;
#if 0
  log_info("jpg_fill_input_buffer file_size=%llu -> %llu (offset=%llu, blocksize=%u)\n",
      (long long unsigned)src->file_size,
      (long long unsigned)src->file_size+src->blocksize - (src->offset + src->file_size)%src->blocksize,
      (long long unsigned)src->offset,
      src->blocksize);
#endif
  nbytes = fread(src->buffer, 1,
      src->blocksize - (src->offset + src->file_size)%src->blocksize,
      src->infile);
  if (nbytes <= 0) {
    if (src->start_of_file)	/* Treat empty input file as fatal error */
    {
      // (cinfo)->err->msg_code = JERR_INPUT_EMPTY;
      (*(cinfo)->err->error_exit) ((j_common_ptr)cinfo);;
    }
    // cinfo->err->msg_code = JWRN_JPEG_EOF;
    (*(cinfo)->err->emit_message) ((j_common_ptr)cinfo, -1);
    /* Insert a fake EOI marker */
    src->buffer[0] = (JOCTET) 0xFF;
    src->buffer[1] = (JOCTET) JPEG_EOI;
    nbytes = 2;
  }
  src->pub.next_input_byte = src->buffer;
  if(src->file_size_max!=0 && src->file_size + nbytes > src->file_size_max)
  {
    const uint64_t off_end=(src->file_size_max > src->file_size ? src->file_size_max - src->file_size: 0);
//    memset(&src->buffer[off_end], 0, nbytes);
    src->buffer[off_end] = (JOCTET) 0xFF;
    src->buffer[off_end+1] = (JOCTET) JPEG_EOI;
    nbytes=off_end+2;
  }
  src->pub.bytes_in_buffer = nbytes;
  src->start_of_file = FALSE;
  src->file_size += nbytes;
  return TRUE;
}


/*
 * Skip data --- used to skip over a potentially large amount of
 * uninteresting data (such as an APPn marker).
 *
 * Writers of suspendable-input applications must note that skip_input_data
 * is not granted the right to give a suspension return.  If the skip extends
 * beyond the data currently in the buffer, the buffer can be marked empty so
 * that the next read will cause a fill_input_buffer call that can suspend.
 * Arranging for additional bytes to be discarded before reloading the input
 * buffer is the application writer's problem.
 */

static void jpg_skip_input_data (j_decompress_ptr cinfo, long num_bytes)
{
  my_source_mgr * src = (my_source_mgr *) cinfo->src;

  /* Just a dumb implementation for now.  Could use fseek() except
   * it doesn't work on pipes.  Not clear that being smart is worth
   * any trouble anyway --- large skips are infrequent.
   */
  if (num_bytes > 0) {
    src->offset_ok=src->file_size - src->pub.bytes_in_buffer;
    while (num_bytes > (long) src->pub.bytes_in_buffer) {
      num_bytes -= (long) src->pub.bytes_in_buffer;
      (void) jpg_fill_input_buffer(cinfo);
      /* note we assume that fill_input_buffer will never return FALSE,
       * so suspension need not be handled.
       */
    }
    src->pub.next_input_byte += (size_t) num_bytes;
    src->pub.bytes_in_buffer -= (size_t) num_bytes;
  }
}

/*
 * An additional method that can be provided by data source modules is the
 * resync_to_restart method for error recovery in the presence of RST markers.
 * For the moment, this source module just uses the default resync method
 * provided by the JPEG library.  That method assumes that no backtracking
 * is possible.
 */


/*
 * Terminate source --- called by jpeg_finish_decompress
 * after all data has been read.  Often a no-op.
 *
 * NB: *not* called by jpeg_abort or jpeg_destroy; surrounding
 * application must deal with any cleanup that should happen even
 * for error exit.
 */

static void jpg_term_source (j_decompress_ptr cinfo)
{
  /* no work necessary here */
}


/* WARNING: This function must be listed in clang Control Flow Integrity (CFI) function blacklist, section cfi-icall */
static void jpeg_testdisk_alloc_src (j_decompress_ptr cinfo, const unsigned int blocksize)
{
  my_source_mgr *src= (my_source_mgr *)
    (*cinfo->mem->alloc_small) ((j_common_ptr) cinfo, JPOOL_PERMANENT,
	sizeof(my_source_mgr));
  cinfo->src = (struct jpeg_source_mgr *) src;
  src->buffer = (JOCTET *)
    (*cinfo->mem->alloc_small) ((j_common_ptr) cinfo, JPOOL_PERMANENT,
	blocksize * sizeof(JOCTET));
}

/*
 * Prepare for input from a stdio stream.
 * The caller must have already opened the stream, and is responsible
 * for closing it after finishing decompression.
 */

static void jpeg_testdisk_src (j_decompress_ptr cinfo, FILE * infile, const uint64_t offset, const unsigned int blocksize)
{
  my_source_mgr * src;

  /* The source object and input buffer are made permanent so that a series
   * of JPEG images can be read from the same file by calling jpeg_testdisk_src
   * only before the first one.  (If we discarded the buffer at the end of
   * one image, we'd likely lose the start of the next one.)
   * This makes it unsafe to use this manager and a different source
   * manager serially with the same JPEG object.  Caveat programmer.
   */
  if (cinfo->src == NULL) {	/* first time for this JPEG object? */
    jpeg_testdisk_alloc_src(cinfo, blocksize);
  }

  src = (my_source_mgr *) cinfo->src;
  src->pub.init_source = &jpg_init_source;
  src->pub.fill_input_buffer = &jpg_fill_input_buffer;
  src->pub.skip_input_data = &jpg_skip_input_data;
  src->pub.resync_to_restart = &jpeg_resync_to_restart; /* use default method */
  src->pub.term_source = &jpg_term_source;
  src->pub.bytes_in_buffer = 0; /* forces fill_input_buffer on first read */
  src->pub.next_input_byte = NULL; /* until buffer loaded */
  src->infile = infile;
  src->offset = offset;
  src->blocksize=blocksize;
}

struct jpeg_session_struct
{
  struct jpeg_decompress_struct cinfo;
  struct jpeg_decompress_struct cinfo_backup;
  unsigned char *frame;
  unsigned int row_stride;
  unsigned int output_components;
  unsigned int output_width;
  unsigned int output_height;
  uint64_t offset;
  FILE *handle;
  unsigned int flags;
  unsigned int blocksize;
};

static void jpeg_init_session(struct jpeg_session_struct *jpeg_session)
{
  jpeg_session->frame=NULL;
  jpeg_session->row_stride=0;
  jpeg_session->output_components=0;
  jpeg_session->output_width=0;
  jpeg_session->output_height=0;
  jpeg_session->offset=0;
  jpeg_session->handle=NULL;
  jpeg_session->flags=0;
}

static void jpeg_session_delete(struct jpeg_session_struct *jpeg_session)
{
  jpeg_destroy_decompress(&jpeg_session->cinfo);
  free(jpeg_session->frame);
  jpeg_session->frame=NULL;
  jpeg_session->row_stride=0;
}

static inline int jpeg_session_resume(struct jpeg_session_struct *jpeg_session)
{
  my_source_mgr * src;
  memcpy(&jpeg_session->cinfo, &jpeg_session->cinfo_backup, sizeof(jpeg_session->cinfo));
  if(resume_memory((j_common_ptr)&jpeg_session->cinfo))
    return -1;
  src = (my_source_mgr *) jpeg_session->cinfo.src;
  if(my_fseek(jpeg_session->handle, jpeg_session->offset + src->file_size, SEEK_SET) < 0)
    return -1;
  return 0;
}

static inline void jpeg_session_suspend(struct jpeg_session_struct *jpeg_session)
{
  suspend_memory((j_common_ptr)&jpeg_session->cinfo);
  memcpy(&jpeg_session->cinfo_backup, &jpeg_session->cinfo, sizeof(jpeg_session->cinfo));
}

static void jpeg_session_start(struct jpeg_session_struct *jpeg_session)
{
  if(my_fseek(jpeg_session->handle, jpeg_session->offset, SEEK_SET) < 0)
  {
    log_critical("jpeg_session_start: fseek failed.\n");
  }
  jpeg_create_decompress(&jpeg_session->cinfo);
  jpeg_testdisk_src(&jpeg_session->cinfo, jpeg_session->handle, jpeg_session->offset, jpeg_session->blocksize);
  (void) jpeg_read_header(&jpeg_session->cinfo, TRUE);
  jpeg_session->cinfo.two_pass_quantize = FALSE;
  jpeg_session->cinfo.dither_mode = JDITHER_NONE;
  jpeg_session->cinfo.dct_method = JDCT_FASTEST;
  jpeg_session->cinfo.do_block_smoothing = FALSE;
  jpeg_session->cinfo.do_fancy_upsampling = FALSE;
  (void) jpeg_start_decompress(&jpeg_session->cinfo);
  jpeg_session->output_width=jpeg_session->cinfo.output_width;
  jpeg_session->output_height=jpeg_session->cinfo.output_height;
  jpeg_session->output_components=jpeg_session->cinfo.output_components;
  jpeg_session->row_stride = jpeg_session->cinfo.output_width * jpeg_session->cinfo.output_components;
  jpeg_session->frame=NULL;
}

static uint64_t jpg_xy_to_offset(FILE *infile, const unsigned int x, const unsigned y,
    const uint64_t offset_rel1, const uint64_t offset_rel2, const uint64_t offset, const unsigned int blocksize)
{
  static struct my_error_mgr jerr;
  static uint64_t file_size_max;
  static struct jpeg_session_struct jpeg_session;
  unsigned int checkpoint_status;
  int avoid_leak;
  jpeg_init_session(&jpeg_session);
  jpeg_session.handle=infile;
  jpeg_session.offset=offset;
  jpeg_session.blocksize=blocksize;
  file_size_max=(offset_rel1 + blocksize - (offset % blocksize) -1) / blocksize * blocksize;
#ifdef DEBUG_JPEG
  log_info("jpg_xy_to_offset(infile, x=%u, y=%u, offset_rel1=%lu, offset_rel2=%lu)\n",
      x, y, (long unsigned)offset_rel1, (long unsigned)offset_rel2);
#endif
  jpeg_session.cinfo.err = jpeg_std_error(&jerr.pub);
  jerr.pub.output_message = &my_output_message;
  jerr.pub.error_exit = &my_error_exit;
  /* Establish the setjmp return context for my_error_exit to use. */
  if (setjmp(jerr.setjmp_buffer))
  {
    if(jpeg_session.frame!=NULL && jpeg_session.cinfo.output_scanline >= y)
    {
      int data=0;
      unsigned int i;
      for(i=0; i< (jpeg_session.output_width-x) * jpeg_session.output_components; i++)
      {
	if(jpeg_session.frame[x*jpeg_session.output_components+i]!=0x80)
	  data=1;
      }
      if(data==1)
      {
	jpeg_session_delete(&jpeg_session);
	return offset + file_size_max;
      }
    }
    file_size_max+=blocksize;
  }
  checkpoint_status=0;
  avoid_leak=0;
  while(file_size_max<offset_rel2)
  {
    if(checkpoint_status==0 || jpeg_session_resume(&jpeg_session)<0)
    {
      if(avoid_leak)
	jpeg_session_delete(&jpeg_session);
      jpeg_session_start(&jpeg_session);
      jpeg_session.frame = (unsigned char *)MALLOC(jpeg_session.row_stride);
      avoid_leak=1;
    }
    {
      my_source_mgr * src;
      src = (my_source_mgr *) jpeg_session.cinfo.src;
      src->file_size_max=file_size_max;
    }
    {
      my_source_mgr * src;
      src = (my_source_mgr *) jpeg_session.cinfo.src;
      while (jpeg_session.cinfo.output_scanline < jpeg_session.cinfo.output_height &&
	  jpeg_session.cinfo.output_scanline < y)
      {
	JSAMPROW row_pointer[1];
	row_pointer[0] = (unsigned char *)jpeg_session.frame;
	(void)jpeg_read_scanlines(&jpeg_session.cinfo, row_pointer, 1);
      }
      if(src->file_size < src->file_size_max)
      {
	jpeg_session_suspend(&jpeg_session);
	checkpoint_status=1;
      }
      if(jpeg_session.cinfo.output_scanline < jpeg_session.cinfo.output_height)
      {
	JSAMPROW row_pointer[1];
	unsigned int i;
	row_pointer[0] = (unsigned char *)jpeg_session.frame;
	/* 0x100/2=0x80, medium value */
	memset(jpeg_session.frame, 0x80, jpeg_session.row_stride);
	(void)jpeg_read_scanlines(&jpeg_session.cinfo, row_pointer, 1);
	for(i=(x+1)*jpeg_session.output_components; i < jpeg_session.output_width * jpeg_session.output_components; i++)
	{
	  if(jpeg_session.frame[i]!=0x80)
	  {
	    (void) jpeg_finish_decompress(&jpeg_session.cinfo);
	    jpeg_session_delete(&jpeg_session);
	    return offset + file_size_max;
	  }
	}
      }
    }
    file_size_max+=blocksize;
  }
/*  Do not call jpeg_finish_decompress(&cinfo); to avoid an endless loop */
  jpeg_session_delete(&jpeg_session);
  return offset + offset_rel2;
}

static unsigned int is_line_cut(const unsigned int output_scanline, const unsigned int output_width, const unsigned int output_components, const unsigned char *frame, const unsigned int y)
{
  unsigned int result_x=0;
  if(y+8 < output_scanline)
  {
    unsigned int result_max=0;
    unsigned int x;
    for(x=8 - 1; x < output_width; x+=8)
    {
      unsigned int result=0;
      unsigned int j;
      for(j=0;
	  j<8 && y+j < output_scanline;
	  j++)
      {
	unsigned int c;
	unsigned int pos;
	for(c=0, pos= ((y+j) * output_width + x ) * output_components;
	    c<output_components;
	    c++, pos++)
	  result += abs(2 * frame[pos] - frame[pos - output_components] - frame[pos + output_components]);
      }
#ifdef DEBUG_JPEG2
      log_info("y=%u x=%u result=%u\n", y, x, result);
#endif
      if(result_max <= result)
      {
	result_max=result;
	result_x=x;
      }
    }
  }
  else
  {
    const unsigned int end = output_width * output_components * output_scanline;
    unsigned int result_max=0;
    unsigned int x;
    for(x=8 - 1; x < output_width; x+=8)
    {
      unsigned int result=0;
      unsigned int j;
      for(j=0;
	  j<8 && y+j < output_scanline;
	  j++)
      {
	unsigned int c;
	unsigned int pos;
	for(c=0, pos= ((y+j) * output_width + x ) * output_components;
	    c<output_components;
	    c++, pos++)
	  result += abs(2 * frame[pos] - frame[pos - output_components]
	      - (pos + output_components <  end ?
		frame[pos + output_components]:
		frame[pos - output_components]));
      }
#ifdef DEBUG_JPEG2
      log_info("y=%u x=%u result=%u\n", y, x, result);
#endif
      if(result_max <= result)
      {
	result_max=result;
	result_x=x;
      }
    }
  }
#ifdef DEBUG_JPEG2
  log_info("y=%u result_x=%u\n", y, result_x);
#endif
  return (output_width - result_x - 1);
}

static unsigned int jpg_find_border(const unsigned int output_scanline, const unsigned int output_width, const unsigned int output_components, const unsigned char *frame)
{
  unsigned int y;
  unsigned int val=0;
#ifdef DEBUG_JPEG
  log_info("jpg_find_border output_scanline=%u output_width=%u output_components=%u\n",
      output_scanline, output_width, output_components);
#endif
  /* TODO handle output_width%8!=0 */
  if(output_width%8!=0)
    return output_scanline;
  for(y=output_scanline-8; y>=8; y-=8)
  {
    const unsigned int old_val=val;
    val=is_line_cut(output_scanline, output_width, output_components, frame, y);
    if(val==0)
    {
      return y+8;
    }
    if(old_val!=0 && val!=old_val)
    {
      return y;
    }
  }
  return output_scanline;
}

#define JPG_MAX_OFFSETS	10240

/* FIXME: it doesn handle correctly when there is a few extra sectors */
static uint64_t jpg_find_error(struct jpeg_session_struct *jpeg_session, const unsigned int *offsets, const uint64_t checkpoint_offset)
{
  FILE *handle                         = jpeg_session->handle;
  const unsigned int output_scanline   = jpeg_session->cinfo.output_scanline;
  const unsigned int output_width      = jpeg_session->output_width;
  const unsigned int output_components = jpeg_session->output_components;
  //const unsigned int blocksize         = jpeg_session->blocksize;
  const unsigned char *frame           = jpeg_session->frame;
  const uint64_t offset                = jpeg_session->offset;
  const unsigned int row_stride = output_width * output_components;
  unsigned int result=0;
  unsigned int result_max=0;
  unsigned int result_x;
  unsigned int result_y;
  unsigned int y;
  unsigned int i;
  unsigned int pos_new;
  unsigned int output_scanline_max;
  if(output_scanline/8 >= JPG_MAX_OFFSETS)
    return 0;
  if(jpeg_session->output_height < 10)
    return 0;
  output_scanline_max=jpg_find_border(output_scanline, output_width, output_components, frame);
  for(i = 0, pos_new= 8 * row_stride;
      i < row_stride;
      i++, pos_new++)
  {
    result += abs(2 * frame[pos_new] - frame[pos_new - row_stride] - frame[pos_new + row_stride]);
  }
  result_x=0;
  result_y=8;
  result_max=result;

  for(y=8; y+8 < output_scanline; y+=8)
  {
    unsigned int pos;
    for(i = 0,
	pos = y * row_stride,
	pos_new = (y + 8) * row_stride;
	i < row_stride;
	i++, pos++, pos_new++)
    {
      if(i % (8 * output_components)==0)
      {
	int stop=0;
//	log_info("x %4u, y %4u: %6u\n", i/output_components, y, result);
	if(result_max < result)
	{
	  // FIXME
#if 1
	  if(2 * result_max < result) // && offset + offsets[result_x / 8] >= checkpoint_offset)
	    stop=1;
#endif
	  result_max=result;
	  result_x=i/output_components;
	  result_y=y;
	}
	/* 12 is a magic value */
#if 1
	else if(2 * result < result_max && result_max > 12 * row_stride) // && offset + offsets[result_x / 8] >= checkpoint_offset)
	  stop=1;
#endif
#if 1
	else if(y > output_scanline_max)
	{
	  stop=1;
	}
#endif
	if(stop==1
	    && is_line_cut(output_scanline, output_width, output_components, frame, y))
	{
	  const uint64_t offset_rel1=offsets[result_y / 8];
	  const uint64_t offset_rel2=offsets[result_y / 8 + 1];
#ifdef DEBUG_JPEG
	  log_info("x %4u, y %4u: %6u, result=%u, output_scanline_max=%u\n",
	      result_x, result_y, result_max, result, output_scanline_max);
#endif
	  if(offset_rel1 < offset_rel2)
	    return jpg_xy_to_offset(handle, result_x, result_y,
//		offset_rel1, offset_rel2, offset, blocksize);
		offset_rel1, offset_rel2, offset, 512);
	  return offset + offset_rel2;
	}
      }
      result -= abs(2 * frame[pos] - frame[pos - row_stride] - frame[pos + row_stride]);
      result += abs(2 * frame[pos_new] - frame[pos_new - row_stride] - frame[pos_new + row_stride]);
    }
  }
  return 0;
}

static uint64_t jpg_check_thumb(FILE *infile, const uint64_t offset, const unsigned int blocksize, const uint64_t checkpoint_offset, const unsigned int flags)
{
  static struct my_error_mgr jerr;
  static unsigned int offsets[JPG_MAX_OFFSETS];
  static struct jpeg_session_struct jpeg_session;
  jpeg_init_session(&jpeg_session);
  jpeg_session.flags=flags;
  jpeg_session.handle=infile;
  jpeg_session.offset=offset;
  jpeg_session.blocksize=blocksize;
  jpeg_session.cinfo.err = jpeg_std_error(&jerr.pub);
  jerr.pub.output_message = &my_output_message;
  jerr.pub.error_exit = &my_error_exit;
  jerr.pub.emit_message= &my_emit_message;
#ifdef DEBUG_JPEG
  jerr.pub.trace_level= 3;
#endif
  /* Establish the setjmp return context for my_error_exit to use. */
  if (setjmp(jerr.setjmp_buffer))
  {
    /* If we get here, the JPEG code has signaled an error.
     * We need to clean up the JPEG object and return.
     */
    uint64_t offset_error;
    my_source_mgr * src;
    src = (my_source_mgr *) jpeg_session.cinfo.src;
    offset_error=jpeg_session.offset + src->file_size - src->pub.bytes_in_buffer;
    if(jpeg_session.frame!=NULL && jpeg_session.flags!=0)
    {
      const uint64_t tmp=jpg_find_error(&jpeg_session, &offsets[0], checkpoint_offset);
//      log_info("jpg_check_thumb jpeg corrupted near   %llu\n", (long long unsigned)offset_error);
      if(tmp !=0 && offset_error > tmp)
	offset_error=tmp;
//      log_info("jpg_check_thumb find_error estimation %llu\n", (long long unsigned)offset_error);
    }
    jpeg_session_delete(&jpeg_session);
    return offset_error;
  }
  memset(offsets, 0, sizeof(offsets));
  jpeg_session_start(&jpeg_session);
  jpeg_session.frame = (unsigned char*)MALLOC((jpeg_session.output_height+1) * jpeg_session.row_stride);
  /* 0x100/2=0x80, medium value */
  memset(jpeg_session.frame, 0x80, jpeg_session.row_stride * (jpeg_session.cinfo.output_height+1));
  while (jpeg_session.cinfo.output_scanline < jpeg_session.cinfo.output_height)
  {
    JSAMPROW row_pointer[1];
    my_source_mgr * src;
    src = (my_source_mgr *) jpeg_session.cinfo.src;
    src->offset_ok=src->file_size - src->pub.bytes_in_buffer;
    if(jpeg_session.cinfo.output_scanline/8 < JPG_MAX_OFFSETS && offsets[jpeg_session.cinfo.output_scanline/8]==0)
      offsets[jpeg_session.cinfo.output_scanline/8]=src->file_size - src->pub.bytes_in_buffer;
    // Calculate where this line needs to go.
    row_pointer[0] = (unsigned char *)jpeg_session.frame + jpeg_session.cinfo.output_scanline * jpeg_session.row_stride;
    (void)jpeg_read_scanlines(&jpeg_session.cinfo, row_pointer, 1);
  }
  (void) jpeg_finish_decompress(&jpeg_session.cinfo);
  jpeg_session_delete(&jpeg_session);
  return 0;
}

static void jpg_check_picture(file_recovery_t *file_recovery)
{
  static struct my_error_mgr jerr;
  static unsigned int offsets[JPG_MAX_OFFSETS];
  uint64_t jpeg_size=0;
  static struct jpeg_session_struct jpeg_session;
  static int jpeg_session_initialised=0;
  if(file_recovery->checkpoint_status==0)
  {
    if(jpeg_session_initialised==1)
      jpeg_session_delete(&jpeg_session);
    jpeg_init_session(&jpeg_session);
    jpeg_session.flags=file_recovery->flags;
    jpeg_session_initialised=1;
    jpeg_session.blocksize=file_recovery->blocksize;
  }
  jpeg_session.handle=file_recovery->handle;
  jpeg_session.cinfo.err = jpeg_std_error(&jerr.pub);
  jerr.pub.output_message = &my_output_message;
  jerr.pub.error_exit = &my_error_exit;
  jerr.pub.emit_message= &my_emit_message;
#ifdef DEBUG_JPEG
  jerr.pub.trace_level= 3;
#endif
  /* Establish the setjmp return context for my_error_exit to use. */
  if (setjmp(jerr.setjmp_buffer))
  {
    /* If we get here, the JPEG code has signaled an error.
     * We need to clean up the JPEG object and return.
     */
    my_source_mgr * src;
    src = (my_source_mgr *) jpeg_session.cinfo.src;
    jpeg_size=src->file_size;
    if(src->pub.bytes_in_buffer >= 4)
      jpeg_size-=src->pub.bytes_in_buffer;
    if(jpeg_size>0)
      file_recovery->offset_error=jpeg_size;
    if(file_recovery->offset_ok < src->offset_ok)
      file_recovery->offset_ok=src->offset_ok;
#ifdef DEBUG_JPEG
    log_error("JPG error, ok at %llu - bad at %llu\n",
	(long long unsigned)file_recovery->offset_ok,
	(long long unsigned)file_recovery->offset_error);
#endif
    if(jpeg_session.frame!=NULL && jpeg_session.flags!=0)
    {
      const uint64_t offset_error=jpg_find_error(&jpeg_session, &offsets[0], file_recovery->checkpoint_offset);
      if(offset_error !=0 && file_recovery->offset_error > offset_error)
	file_recovery->offset_error=offset_error;
#ifdef DEBUG_JPEG
      log_error("JPG error, ok at %llu - bad at %llu (jpg_find_error)\n",
	  (long long unsigned)file_recovery->offset_ok,
	  (long long unsigned)file_recovery->offset_error);
#endif
    }
    jpeg_session_delete(&jpeg_session);
    return;
  }
  memset(offsets, 0, sizeof(offsets));
  jpeg_session_start(&jpeg_session);
  {
    my_source_mgr * src;
    src = (my_source_mgr *) jpeg_session.cinfo.src;
    src->file_size_max=file_recovery->file_size;
  }
  /* Image is very big, skip some tests */
  if((uint64_t)jpeg_session.output_height * jpeg_session.row_stride > 500 * 1024 * 1024 ||
      jpeg_session.output_height<9)
    jpeg_session.flags=0;
  /* 0x100/2=0x80, medium value */
  if(jpeg_session.flags==0)
  {
    jpeg_session.frame = (unsigned char *)MALLOC(jpeg_session.row_stride);
    memset(jpeg_session.frame, 0x80, jpeg_session.row_stride);
  }
  else
  {
    /* FIXME out of bound read access in libjpeg-turbo */
    jpeg_session.frame = (unsigned char *)MALLOC((jpeg_session.output_height+1) * jpeg_session.row_stride);
    memset(jpeg_session.frame, 0x80, (jpeg_session.cinfo.output_height+1) * jpeg_session.row_stride);
  }
  while (jpeg_session.cinfo.output_scanline < jpeg_session.cinfo.output_height)
  {
    JSAMPROW row_pointer[1];
    my_source_mgr * src;
    src = (my_source_mgr *) jpeg_session.cinfo.src;
    src->offset_ok=src->file_size - src->pub.bytes_in_buffer;
    if(jpeg_session.cinfo.output_scanline/8 < JPG_MAX_OFFSETS && offsets[jpeg_session.cinfo.output_scanline/8]==0)
    {
      offsets[jpeg_session.cinfo.output_scanline/8]=src->file_size - src->pub.bytes_in_buffer;
    }
  // Calculate where this line needs to go.
    if(jpeg_session.flags==0)
      row_pointer[0] = jpeg_session.frame;
    else
      row_pointer[0] = (unsigned char *)jpeg_session.frame + jpeg_session.cinfo.output_scanline * jpeg_session.row_stride;
    (void)jpeg_read_scanlines(&jpeg_session.cinfo, row_pointer, 1);
  }
  {
    my_source_mgr * src;
    src = (my_source_mgr *) jpeg_session.cinfo.src;
    jpeg_size=src->file_size - src->pub.bytes_in_buffer;
  }
  (void) jpeg_finish_decompress(&jpeg_session.cinfo);
  jpeg_session_delete(&jpeg_session);
  jpeg_session_initialised=0;
  file_recovery->checkpoint_status=0;
  if(jpeg_size<=0)
    return;
  if(file_recovery->calculated_file_size>0)
    file_recovery->file_size=file_recovery->calculated_file_size;
  else
  {
    static const unsigned char jpg_footer[2]= { 0xff,0xd9};
    file_recovery->file_size=jpeg_size;
    file_search_footer(file_recovery, jpg_footer, sizeof(jpg_footer), 0);
  }
}
#endif

static int jpg_check_dht(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int i, const unsigned int size)
{
  unsigned int j=i+4;
  /* DHT must not be shorter than 18 bytes, 1+16+1 */
  /* DHT should not be longer than 1088 bytes, 4*(1+16+255) */
  if(size<18)
    return 2;
  /*@
    @ loop assigns j;
    @ loop variant buffer_size - j;
    @*/
  while(j < buffer_size && j < i+size)
  {
    const unsigned int tc=buffer[j]>>4;
    const unsigned int n=buffer[j] & 0x0f;
    unsigned int l;
    unsigned int sum=0;
    /* Table class: 0 = DC table or lossless table, 1 = AC table */
    if(tc > 1)
      return 2;
    /* Must be between 0 and 3 Huffman table */
    if(n > 3)
      return 2;
    j++;
    /*@
      @ loop invariant 0 <= l <= 16;
      @ loop invariant sum <= l*255;
      @ loop assigns l,sum;
      @ loop variant 16-l;
      @*/
    for(l=0; l < 16; l++)
      if(j+l < buffer_size)
	sum+=buffer[j+l];
    if(sum>255)
      return 2;
    j+=16;
    j+=sum;
  }
  if(j > i+size)
    return 2;
  return 0;
}

struct sof_header
{
  uint16_t      marker;
  uint16_t      length;         /* 8 + 3 * nbr */
  unsigned char precision;      /* 2-16 8 for SOF0 */
  uint16_t      height;         /* 0-65535 */
  uint16_t      width;          /* 1-65535 */
  unsigned char nbr;            /* 1-255 */
#if 0
  unsigned char data[0];
#endif
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires \valid_read(buffer + (0..buffer_size-1));
  @ terminates \true;
  @ assigns \nothing;
  @*/
static int jpg_check_sof0(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int i)
{
  if(i+4 > buffer_size)
    return 0;
  {
    const struct sof_header *h=(const struct sof_header *)&buffer[i];
    const unsigned int length=be16(h->length);
    /*@ assert 0 <= length < 65536; */
    if(length < sizeof(struct sof_header)-2)
      return 1;
  }
  if(i+2+8 > buffer_size)
    return 0;
  {
    const struct sof_header *h=(const struct sof_header *)&buffer[i];
    const unsigned int length=be16(h->length);
    /*@ assert 0 <= length < 65536; */
    if(h->precision!=8 || be16(h->width)==0 || h->nbr==0)
      return 1;
    if(length < 8+h->nbr*3)
      return 1;
  }
//  if(i+2+be16(h->length) > buffer_size)
//    return 0;
  return 0;
}

/*@
  @ requires \valid_read(file_recovery);
  @ requires \valid(file_recovery->handle);
  @ requires 0 < file_recovery->blocksize <= 1048576;
  @ requires file_recovery->offset_error <= (1<<63) - 1;
  @ requires separation: \separated(file_recovery, file_recovery->handle, &errno);
  @ ensures \valid(file_recovery->handle);
  @ assigns *file_recovery->handle, errno;
  @ assigns Frama_C_entropy_source;
  @ assigns file_recovery->extra;
  @*/
static void jpg_search_marker(file_recovery_t *file_recovery)
{
  FILE* infile=file_recovery->handle;
  char sbuffer[40*8192];
  size_t nbytes;
  const uint64_t offset_error=file_recovery->offset_error;
  uint64_t offset_test=offset_error;
  uint64_t offset;
  /*@ assert offset_test == offset_error; */
  if(file_recovery->blocksize==0)
    return ;
  if(offset_test > 0x80000000)
    return ;
  /*@ assert offset_test <= 0x80000000; */
  offset=offset_test / file_recovery->blocksize * file_recovery->blocksize;
  if(my_fseek(infile, offset, SEEK_SET) < 0)
    return ;
  /*@ assert offset_test == offset_error; */
  /*@
    @ loop invariant offset_test >= offset_error;
    @ loop assigns nbytes, sbuffer[ 0 .. sizeof(sbuffer)-1];
    @ loop assigns *infile, errno;
    @ loop assigns Frama_C_entropy_source;
    @ loop assigns offset, offset_test;
    @ loop assigns file_recovery->extra;
    @ loop variant 0x80000000 + sizeof(sbuffer) - offset_test;
    @*/
  while((nbytes=fread(&sbuffer, 1, sizeof(sbuffer), infile))>0)
  {
    unsigned int i;
    const unsigned char *buffer=(const unsigned char *)sbuffer;
    /*@ assert 0 < nbytes <= sizeof(sbuffer); */
    if(offset_test > 0x80000000)
      return ;
#if defined(__FRAMAC__)
    Frama_C_make_unknown(&sbuffer, sizeof(sbuffer));
#endif
    /*@ assert offset_test >= offset_error; */
    offset=offset_test / file_recovery->blocksize * file_recovery->blocksize;
    i=offset_test % file_recovery->blocksize;
    /*@ assert offset + i == offset_test; */
    /*@ assert i == offset_test - offset; */
    /*@ assert offset_test >= offset_error; */
    /*@
      @ loop invariant offset + i >= offset_test;
      @ loop invariant offset_test >= offset_error;
      @ loop invariant 0 <= i < nbytes + file_recovery->blocksize;
      @ loop assigns i,file_recovery->extra;
      @ loop variant nbytes - (i+1);
      @*/
    while(i+1<nbytes)
    {
      const uint64_t tmp=offset + i;
      /*@ assert tmp == offset + i; */
      /*@ assert tmp >= offset_test; */
      /*@ assert offset_test >= offset_error; */
      if(buffer[i]==0xff &&
	  (buffer[i+1]==0xd8 ||			/* SOI */
	   buffer[i+1]==0xdb ||			/* DQT */
	   (buffer[i+1]>=0xc0 && buffer[i+1]<=0xcf) ||	/* SOF0 - SOF15, 0xc4=DHT */
	   buffer[i+1]==0xda ||				/* SOS: Start Of Scan */
	   buffer[i+1]==0xdd ||				/* DRI */
	   (buffer[i+1]>=0xe0 && buffer[i+1]<=0xef) ||	/* APP0 - APP15 */
	   buffer[i+1]==0xfe)				/* COM */
	)
      {
	file_recovery->extra=tmp - offset_error;
#ifndef DISABLED_FOR_FRAMAC
	if(file_recovery->extra % file_recovery->blocksize != 0)
	{
	  log_info("jpg_search_marker %s extra=%llu\n",
	      file_recovery->filename,
	      (long long unsigned)file_recovery->extra);
	}
#endif
	return ;
      }
      i+=file_recovery->blocksize;
    }
    offset_test += nbytes;
  }
  return ;
}

/*@
  @ requires valid_file_recovery(file_recovery);
  @ requires \valid_read(buffer + (0 .. nbytes-1));
  @ requires thumb_offset < nbytes;
  @ requires thumb_size > 0;
  @ requires thumb_offset + thumb_size <= nbytes;
  @ assigns  errno;
  @*/
static void jpg_save_thumbnail(const file_recovery_t *file_recovery, const char *buffer, const uint64_t nbytes, const uint64_t thumb_offset, const unsigned int thumb_size)
{
  char thumbname[2048];
  char *sep;
  /*@ assert sizeof(thumbname) == sizeof(file_recovery->filename); */
  /*@ assert valid_read_string((char *)&file_recovery->filename); */
  memcpy(thumbname,file_recovery->filename, sizeof(thumbname));
  thumbname[sizeof(thumbname)-1]='\0';
  /*@ assert valid_read_string(&thumbname[0]); */
  sep=strrchr(thumbname,'/');
  if(sep!=NULL
#ifndef DISABLED_FOR_FRAMAC
      && *(sep+1)=='f'
#endif
    )
  {
    FILE *out;
#ifndef DISABLED_FOR_FRAMAC
    *(sep+1)='t';
#endif
#ifndef DISABLED_FOR_FRAMAC
    if((out=fopen(thumbname,"wb"))!=NULL)
    {
      /*@ assert \valid_read(buffer + (0 .. nbytes - 1)); */
      /*@ assert 0 <= thumb_offset < nbytes; */
      /*@ assert \valid_read(buffer + (thumb_offset .. nbytes - 1)); */
      /*@ assert \valid_read(buffer + thumb_offset + (0 .. nbytes - 1 - thumb_offset)); */
      /*@ ghost const char *thumb_char=&buffer[thumb_offset]; */
      /*@ assert \valid_read(thumb_char + (0 .. nbytes - thumb_offset - 1)); */
      /*@ assert 0 < thumb_size <= nbytes - thumb_offset; */
      /*@ ghost uint64_t tmp_size=nbytes - thumb_offset; */
      /*@ assert 0 < thumb_size <= tmp_size; */
      /*@ assert \valid_read(thumb_char + (0 .. tmp_size - 1)); */
      /*@ assert \valid_read(thumb_char + (0 .. thumb_size - 1)); */
      if(fwrite(&buffer[thumb_offset], thumb_size, 1, out) < 1)
      {
#ifndef DISABLED_FOR_FRAMAC
	log_error("Can't write to %s: %s\n", thumbname, strerror(errno));
#endif
      }
      fclose(out);
      if(file_recovery->time!=0 && file_recovery->time!=(time_t)-1)
	set_date(thumbname, file_recovery->time, file_recovery->time);
    }
    else
    {
#ifndef DISABLED_FOR_FRAMAC
      log_error("fopen %s failed\n", thumbname);
#endif
    }
#endif
  }
}

/*@
  @ requires \valid(file_recovery);
  @ requires \valid(file_recovery->handle);
  @ requires \valid(thumb_offset_ptr);
  @ requires valid_read_string((char *)&file_recovery->filename);
  @ requires file_recovery->blocksize > 0;
  @ requires nbytes > 4;
  @ requires \valid_read(buffer + (0 .. nbytes-1));
  @ requires \initialized(&file_recovery->time);
  @ requires separation: \separated(file_recovery, file_recovery->handle, buffer+(..), thumb_offset_ptr, &errno);
  @ ensures  \valid(file_recovery->handle);
  @ assigns *file_recovery->handle, errno;
  @ assigns Frama_C_entropy_source;
  @ assigns file_recovery->extra;
  @ assigns file_recovery->time;
  @ assigns file_recovery->offset_error;
  @ assigns file_recovery->offset_ok;
  @ assigns *thumb_offset_ptr;
  @*/
static int jpg_check_app1(file_recovery_t *file_recovery, const unsigned int extract_thumb, const unsigned char *buffer, const unsigned int i, const unsigned int offset, const unsigned int size, const uint64_t nbytes, uint64_t *thumb_offset_ptr)
{ /* APP1 Exif information */
  const unsigned int tiff_offset=i+2+8;
  const unsigned char *potential_error=NULL;
  const unsigned char *tiff;
  unsigned int thumb_size=0;
  unsigned int tiff_size;
  uint64_t thumb_offset;
  *thumb_offset_ptr=0;
  if(tiff_offset >= nbytes || size <= 8)
    return 1;
  /*@ assert tiff_offset < nbytes; */
  /*@ assert size > 8; */
  tiff_size=size-0x08;
  if(nbytes - tiff_offset < tiff_size)
  {
    tiff_size=nbytes - tiff_offset;
    /*@ assert tiff_offset + tiff_size == nbytes; */
  }
  else
  {
    /*@ assert tiff_offset + tiff_size <= nbytes; */
  }
  /*@ assert tiff_offset + tiff_size <= nbytes; */
  if(tiff_size<sizeof(TIFFHeader))
    return 1;
  /*@ assert tiff_size >= sizeof(TIFFHeader); */
  /*@ assert \valid_read(buffer + (0 .. tiff_offset+tiff_size-1)); */
  /*@ assert \valid_read((buffer + tiff_offset) + (0 .. tiff_size-1)); */
  tiff=&buffer[tiff_offset];
  /*@ assert \valid_read(tiff+ (0 .. tiff_size-1)); */
  if(file_recovery->time==0)
  {
    /*@ assert \valid_read(tiff+ (0 .. tiff_size-1)); */
    file_recovery->time=get_date_from_tiff_header(tiff, tiff_size);
  }
  thumb_offset=find_tag_from_tiff_header(tiff, tiff_size, TIFFTAG_JPEGIFOFFSET, &potential_error);
  if(potential_error!=NULL)
  {
    file_recovery->offset_error=potential_error-buffer;
    return 0;
  }
  if(thumb_offset==0)
    return 1;
  /*@ assert 0 < thumb_offset; */
  thumb_offset+=tiff_offset;
  thumb_size=find_tag_from_tiff_header(tiff, tiff_size, TIFFTAG_JPEGIFBYTECOUNT, &potential_error);
  if(potential_error!=NULL)
  {
    file_recovery->offset_error=potential_error-buffer;
    return 0;
  }
  if(thumb_size==0)
    return 1;
  /*@ assert 0 < thumb_size; */
  *thumb_offset_ptr=thumb_offset;
  if(file_recovery->offset_ok<i)
    file_recovery->offset_ok=i;
  if(thumb_offset + 6 >= nbytes)
    return 1;
  /*@ assert 0 < thumb_offset < nbytes - 6; */
  /*@ assert thumb_offset < nbytes; */
  {
    unsigned int j=thumb_offset+2;
    unsigned int thumb_sos_found=0;
#ifdef DEBUG_JPEG
    unsigned int j_old=j;
#endif
    if(buffer[thumb_offset]!=0xff)
    {
      file_recovery->offset_error=thumb_offset;
      jpg_search_marker(file_recovery);
      return 0;
    }
    if(buffer[thumb_offset+1]!=0xd8)
    {
      file_recovery->offset_error=thumb_offset+1;
      return 0;
    }
    /*@ assert j == thumb_offset + 2; */
    /*@ assert j < nbytes - 4; */
    /*@
      @ loop invariant 0 < thumb_size;
      @ loop invariant 0 < thumb_offset < nbytes - 1;
      @ loop assigns j, thumb_sos_found;
      @ loop assigns errno, *file_recovery->handle,Frama_C_entropy_source;
      @ loop assigns file_recovery->offset_ok;
      @ loop assigns file_recovery->offset_error;
      @ loop assigns file_recovery->extra;
      @ loop variant nbytes - (j+4);
      @*/
    while(j+4<nbytes && thumb_sos_found==0)
    {
      /*@ assert j + 4 < nbytes; */
      if(buffer[j]!=0xff)
      {
	file_recovery->offset_error=j;
#ifdef DEBUG_JPEG
	log_info("%s thumb no marker at 0x%x\n", file_recovery->filename, j);
	log_error("%s Error between %u and %u\n", file_recovery->filename, j_old, j);
#endif
	jpg_search_marker(file_recovery);
	return 0;
      }
      if(buffer[j+1]==0xff)
      {
	/* See B.1.1.2 Markers in http://www.w3.org/Graphics/JPEG/itu-t81.pdf*/
	j++;
	continue;
      }
#ifdef DEBUG_JPEG
      log_info("%s thumb marker 0x%02x at 0x%x\n", file_recovery->filename, buffer[j+1], j);
#endif
      if(buffer[j+1]==0xda)	/* Thumb SOS: Start Of Scan */
      {
	thumb_sos_found=1;
      }
      else if(buffer[j+1]==0xc4)			/* DHT */
      {
	if(jpg_check_dht(buffer, nbytes, j, 2+((unsigned int)buffer[j+2]<<8)+buffer[j+3])!=0)
	{
	  file_recovery->offset_error=j+2;
	  return 0;
	}
      }
      else if(buffer[j+1]==0xdb ||			/* DQT */
	  buffer[j+1]==0xc0 ||			/* SOF0 */
	  buffer[j+1]==0xdd)				/* DRI */
      {
      }
      else if((buffer[j+1]>=0xc0 && buffer[j+1]<=0xcf) ||	/* SOF0 - SOF15 */
	  (buffer[j+1]>=0xe0 && buffer[j+1]<=0xef) ||		/* APP0 - APP15 */
	  buffer[j+1]==0xfe)					/* COM */
      {
	/* Unusual marker, bug ? */
      }
      else
      {
#ifndef DISABLED_FOR_FRAMAC
	log_info("%s thumb unknown marker 0x%02x at 0x%x\n", file_recovery->filename, buffer[j+1], j);
#endif
	file_recovery->offset_error=j;
	return 0;
      }
      if(file_recovery->offset_ok<j)
	file_recovery->offset_ok=j;
#ifdef DEBUG_JPEG
      j_old=j;
#endif
      {
	const unsigned int tmp=((unsigned int)buffer[j+2]<<8)+buffer[j+3];
	/*@ assert 0 <= tmp <= 65535; */
	j+=2U+tmp;
      }
    }
    if(thumb_sos_found==0)
      return 1;
  }
  if(extract_thumb==0)
    return 1;
  /* APP1 must be followed by a valid marker, this avoids many corrupted thumbnails */
  if(offset >= nbytes || buffer[offset]!=0xff)
    return 1;
  if(thumb_offset+thumb_size > nbytes)
    return 1;
  /*@ assert thumb_offset + thumb_size <= nbytes; */
  /*@ assert 0 < thumb_size; */
  /*@ assert thumb_offset < nbytes; */
  jpg_save_thumbnail(file_recovery, (const char *)buffer, nbytes, thumb_offset, thumb_size);
  return 1;
}

/*@
  @ requires \valid(file_recovery);
  @ requires \valid(file_recovery->handle);
  @ requires file_recovery->blocksize > 0;
  @ requires \initialized(&file_recovery->time);
  @ requires valid_read_string((char *)&file_recovery->filename);
  @ requires separation: \separated(file_recovery, file_recovery->handle, &errno, &Frama_C_entropy_source);
  @ assigns  errno;
  @ assigns  file_recovery->extra;
  @ assigns  *file_recovery->handle;
  @ assigns  file_recovery->offset_error;
  @ assigns  file_recovery->offset_ok;
  @ assigns  file_recovery->time;
  @ assigns  Frama_C_entropy_source;
 */
static uint64_t jpg_check_structure(file_recovery_t *file_recovery, const unsigned int extract_thumb)
{
  char sbuffer[40*8192];
  uint64_t thumb_offset=0;
  size_t nbytes;
  unsigned int offset;
  const unsigned char *buffer=(const unsigned char*)&sbuffer;
  file_recovery->extra=0;
  if(my_fseek(file_recovery->handle, 0, SEEK_SET) < 0)
    return 0;
  nbytes=fread(&sbuffer, 1, sizeof(sbuffer), file_recovery->handle);
#if defined(__FRAMAC__)
  Frama_C_make_unknown(sbuffer, sizeof(sbuffer));
#endif
  if(nbytes <= 0)
    return 0;
  /*@ assert nbytes > 0; */
  file_recovery->offset_error=0;
  /*@
    @ loop assigns offset, file_recovery->offset_error;
    @ loop variant nbytes - (offset + 30);
    @*/
  for(offset=file_recovery->blocksize; offset + 30 < nbytes && file_recovery->offset_error==0; offset+=file_recovery->blocksize)
  {
    if(buffer[offset]==0xff && buffer[offset+1]==0xd8 && buffer[offset+2]==0xff &&
	((buffer[offset+3]==0xe1 && memcmp(&buffer[offset+6], "http://ns.adobe.com/xap/", 24)!=0)
	 || buffer[offset+3]==0xec))
    {
      file_recovery->offset_error=offset;
    }
  }
  offset=2;
  /*@
    @ loop assigns errno;
    @ loop assigns file_recovery->extra;
    @ loop assigns *file_recovery->handle;
    @ loop assigns file_recovery->offset_error;
    @ loop assigns file_recovery->offset_ok;
    @ loop assigns file_recovery->time;
    @ loop assigns Frama_C_entropy_source;
    @ loop assigns offset;
    @ loop assigns thumb_offset;
    @ loop variant nbytes - (offset + 4);
    @*/
  while(offset + 4 < nbytes && buffer[offset]==0xff && is_marker_valid(buffer[offset+1]) && (file_recovery->offset_error==0 || offset < file_recovery->offset_error))
  {
    /*@ assert offset + 4 < nbytes; */
    const unsigned int i=offset;
    /*@ assert i == offset ; */
    /*@ assert i + 4 < nbytes; */
    /*@ assert i < nbytes; */
    const unsigned int size=((unsigned int)buffer[i+2]<<8)+buffer[i+3];
    if(buffer[i+1]==0xff)
    {
      /* See B.1.1.2 Markers in http://www.w3.org/Graphics/JPEG/itu-t81.pdf*/
      offset++;
      continue;
    }
#if defined(DEBUG_JPEG)
    log_info("%s marker ff%02x at 0x%x\n", file_recovery->filename, buffer[i+1], i);
#endif
    offset+=(uint64_t)2+size;
    if(buffer[i+1]==0xe1)
    { /* APP1 Exif information */
      if(jpg_check_app1(file_recovery, extract_thumb, buffer, i, offset, size, nbytes, &thumb_offset)==0)
	return 0;
    }
    else if(buffer[i+1]==0xc4)	/* DHT */
    {
      if(jpg_check_dht(buffer, nbytes, i, 2+size)!=0)
      {
	file_recovery->offset_error=i+2;
	return thumb_offset;
      }
    }
    if(file_recovery->offset_ok<i+1)
      file_recovery->offset_ok=i+1;
  }
  if(offset < nbytes && buffer[offset]!=0xff)
  {
#if defined(DEBUG_JPEG)
    log_info("%s no marker at 0x%x\n", file_recovery->filename, offset);
#endif
    file_recovery->offset_error=offset;
    jpg_search_marker(file_recovery);
    return thumb_offset;
  }
  if(offset + 4 < nbytes)
  {
    if(buffer[offset+1]==0xda)	/* SOS: Start Of Scan */
      file_recovery->offset_ok=offset+1;
    else
      file_recovery->offset_error=offset+1;
    return thumb_offset;
  }
  if(offset > nbytes && nbytes < sizeof(buffer))
  {
    file_recovery->offset_error=nbytes;
    return thumb_offset;
  }
  return thumb_offset;
}

/*@
  @ requires file_recovery->file_check == &file_check_mpo || file_recovery->file_check == &file_check_jpg;
  @ requires valid_file_check_param(file_recovery);
  @ ensures  valid_file_check_result(file_recovery);
  @ assigns  errno;
  @ assigns  file_recovery->calculated_file_size;
  @ assigns  file_recovery->extra;
  @ assigns  file_recovery->file_size;
  @ assigns  file_recovery->flags;
  @ assigns  *file_recovery->handle;
  @ assigns  file_recovery->offset_error;
  @ assigns  file_recovery->offset_ok;
  @ assigns  file_recovery->time;
  @ assigns  Frama_C_entropy_source;
  @*/
static void file_check_jpg(file_recovery_t *file_recovery)
{
  uint64_t thumb_offset;
  static uint64_t thumb_error=0;
  if(file_recovery->calculated_file_size<=2)
    file_recovery->calculated_file_size=0;
  /* FIXME REMOVE ME */
  file_recovery->flags=1;
  file_recovery->file_size=0;
  if(file_recovery->calculated_file_size==0)
    file_recovery->offset_error=0;
#ifdef DEBUG_JPEG
  log_info("file_check_jpg  %s calculated_file_size=%llu, error at %llu\n", file_recovery->filename,
      (long long unsigned)file_recovery->calculated_file_size,
      (long long unsigned)file_recovery->offset_error);
#endif
  if(file_recovery->offset_error!=0)
    return ;
  thumb_offset=jpg_check_structure(file_recovery, 1);
#ifdef DEBUG_JPEG
  log_info("jpg_check_structure error at %llu\n", (long long unsigned)file_recovery->offset_error);
#endif
#if defined(HAVE_LIBJPEG) && defined(HAVE_JPEGLIB_H)
  if(thumb_offset!=0 &&
      (file_recovery->checkpoint_status==0 || thumb_error!=0) &&
      (file_recovery->offset_error==0 || thumb_offset < file_recovery->offset_error))
  {
#ifdef DEBUG_JPEG
    log_info("jpg_check_thumb\n");
#endif
    thumb_error=jpg_check_thumb(file_recovery->handle, thumb_offset, file_recovery->blocksize, file_recovery->checkpoint_offset, file_recovery->flags);
    if(thumb_error!=0)
    {
#ifdef DEBUG_JPEG
      log_info("%s thumb corrupted at %llu, previous error at %llu\n",
	  file_recovery->filename, (long long unsigned)thumb_error,
	  (long long unsigned)file_recovery->offset_error);
#endif
      if(file_recovery->offset_error==0 || file_recovery->offset_error > thumb_error)
      {
#ifdef DEBUG_JPEG
	log_info("Thumb usefull, error at %llu\n", (long long unsigned)thumb_error);
#endif
	file_recovery->offset_error = thumb_error;
      }
    }
  }
#endif
  if(file_recovery->offset_error!=0)
    return ;
#if defined(HAVE_LIBJPEG) && defined(HAVE_JPEGLIB_H)
  jpg_check_picture(file_recovery);
#else
  file_recovery->file_size=file_recovery->calculated_file_size;
#endif
#if 0
    /* FIXME REMOVE ME */
  if(file_recovery->offset_error!=0)
  {
    file_recovery->file_size=file_recovery->offset_error;
    file_recovery->offset_error=0;
    fseek(file_recovery->handle, file_recovery->file_size, SEEK_SET);
    fwrite(jpg_footer, sizeof(jpg_footer), 1, file_recovery->handle);
    file_recovery->file_size+=2;
    return ;
  }
#endif
}

#if !defined(HAVE_LIBJPEG) || !defined(HAVE_JPEGLIB_H)
/*@
  @ requires \valid(file_recovery);
  @ assigns file_recovery->calculated_file_size;
  @*/
static data_check_t data_check_continue(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  file_recovery->calculated_file_size+=buffer_size/2;
  return DC_CONTINUE;
}
#endif

/*@
  @ requires file_recovery->data_check == &data_check_jpg2;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ ensures file_recovery->data_check == &data_check_jpg2 || file_recovery->data_check == \null || file_recovery->data_check == &data_check_continue;
  @ ensures file_recovery->data_check == \null ==> file_recovery->calculated_file_size == 0;
  @ assigns file_recovery->calculated_file_size;
  @ assigns file_recovery->data_check;
  @ assigns file_recovery->offset_error;
  @*/
static data_check_t data_check_jpg2(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@
    @ loop invariant file_recovery->data_check == \null ==> file_recovery->calculated_file_size == 0;
    @ loop invariant buffer_size <= 2 * PHOTOREC_MAX_BLOCKSIZE;
    @ loop assigns file_recovery->calculated_file_size;
    @ loop assigns file_recovery->data_check;
    @ loop assigns file_recovery->offset_error;
    @ loop variant file_recovery->file_size + buffer_size/2 - (file_recovery->calculated_file_size + 1);
    @*/
  while(file_recovery->calculated_file_size + buffer_size/2  > file_recovery->file_size &&
      file_recovery->calculated_file_size + 1 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size + buffer_size/2 - file_recovery->file_size;
    /*@ assert 0 <= i < buffer_size - 1; */
    /*@ assert file_recovery->data_check == &data_check_jpg2; */
    if(buffer[i]==0xFF)
    {
      if(buffer[i+1]==0xd9)
      {
	/* JPEG_EOI */
	file_recovery->calculated_file_size+=2;
	/*@ assert file_recovery->data_check == &data_check_jpg2; */
	/*@ assert file_recovery->calculated_file_size >= 2; */
	/*@ assert file_recovery->data_check == \null ==> file_recovery->calculated_file_size == 0; */
	return DC_STOP;
      }
      else if(buffer[i+1] >= 0xd0 && buffer[i+1] <= 0xd7)
      {
	/* JPEG_RST0 .. JPEG_RST7 markers */
#if 0
	if((buffer[i+1]==0xd0 && old_marker!=0 && old_marker!=0xd7) ||
	    (buffer[i+1]!=0xd0 && old_marker+1 != buffer[i+1]))
	{
#ifdef DEBUG_JPEG
	  log_info("Rejected due to JPEG_RST marker\n");
#endif
	  file_recovery->calculated_file_size++;
	  return DC_STOP;
	}
	/* TODO: store old_marker in file_recovery */
	old_marker=buffer[i+1];
#endif
	/*@ assert file_recovery->data_check == &data_check_jpg2; */
      }
      else if(buffer[i+1] == 0xda || buffer[i+1] == 0xc4)
      {
	/* SOS and DHT may be embedded by progressive jpg */
#if defined(HAVE_LIBJPEG) && defined(HAVE_JPEGLIB_H)
	file_recovery->data_check=NULL;
	file_recovery->calculated_file_size=0;
#else
	file_recovery->data_check=data_check_continue;
	file_recovery->calculated_file_size=file_recovery->file_size + buffer_size/2;
#endif
	/*@ assert file_recovery->data_check == \null || file_recovery->data_check == &data_check_continue; */
	/*@ assert file_recovery->data_check == \null ==> file_recovery->calculated_file_size == 0; */
	return DC_CONTINUE;
      }
      else if(buffer[i+1]!=0x00)
      {
#ifdef DEBUG_JPEG
	log_info("%s data_check_jpg2 marker 0x%02x at 0x%llx\n", file_recovery->filename, buffer[i+1],
	    (long long unsigned)file_recovery->calculated_file_size);
#endif
	file_recovery->offset_error=file_recovery->calculated_file_size;
	/*@ assert file_recovery->data_check == &data_check_jpg2; */
	/*@ assert file_recovery->data_check == \null ==> file_recovery->calculated_file_size == 0; */
	return DC_STOP;
      }
    }
    /*@ assert file_recovery->data_check == &data_check_jpg2; */
    file_recovery->calculated_file_size++;
  }
  /*@ assert file_recovery->data_check == &data_check_jpg2; */
  /*@ assert file_recovery->data_check == \null ==> file_recovery->calculated_file_size == 0; */
  return DC_CONTINUE;
}

/*@
  @ requires buffer_size >= 8;
  @ requires file_recovery->data_check == &data_check_jpg;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ ensures file_recovery->data_check == &data_check_jpg2 || file_recovery->data_check == &data_check_jpg || file_recovery->data_check == &data_check_size || file_recovery->data_check == \null || file_recovery->data_check == &data_check_continue;
  @ ensures file_recovery->data_check == &data_check_jpg2 ==> file_recovery->calculated_file_size >= 2;
  @ assigns file_recovery->calculated_file_size;
  @ assigns file_recovery->data_check;
  @ assigns file_recovery->file_check;
  @ assigns file_recovery->offset_error;
  @*/
/* FIXME requires file_recovery->file_size == 0 || file_recovery->calculated_file_size >= file_recovery->file_size - 4; */
/* FIXME ensures \result == DC_CONTINUE ==> (file_recovery->calculated_file_size >= file_recovery->file_size + buffer_size/2 - 4); */
static data_check_t data_check_jpg(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /* Skip the SOI */
  if(file_recovery->calculated_file_size<2)
    file_recovery->calculated_file_size=2;
  /*@ assert file_recovery->calculated_file_size >= 2; */
  /*@ assert file_recovery->data_check == &data_check_jpg; */
  /* Search SOS */
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@
    @ loop invariant buffer_size <= 2 * PHOTOREC_MAX_BLOCKSIZE;
    @ loop assigns file_recovery->calculated_file_size;
    @ loop assigns file_recovery->data_check;
    @ loop assigns file_recovery->file_check;
    @ loop assigns file_recovery->offset_error;
    @ loop variant file_recovery->file_size + buffer_size/2 - (file_recovery->calculated_file_size + 4);
    @*/
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 4 < file_recovery->file_size + buffer_size/2)
  {
    /*@ assert file_recovery->data_check == &data_check_jpg; */
    const unsigned int i=file_recovery->calculated_file_size + buffer_size/2 - file_recovery->file_size;
    /*@ assert 0 <= i < buffer_size - 4 ; */
    if(buffer[i]==0xFF && buffer[i+1]==0xFF)
      file_recovery->calculated_file_size++;
    else if(buffer[i]==0xFF)
    {
      const unsigned int size=((unsigned int)buffer[i+2]<<8)+buffer[i+3];
      const uint64_t old_calculated_file_size=file_recovery->calculated_file_size;
#ifdef DEBUG_JPEG
      log_info("data_check_jpg %02x%02x at %llu, next expected at %llu\n", buffer[i], buffer[i+1],
	  (long long unsigned)file_recovery->calculated_file_size,
	  (long long unsigned)file_recovery->calculated_file_size+2+size);
#endif
      file_recovery->calculated_file_size+=(uint64_t)2+size;
      if(buffer[i+1]==0xc0)	/* SOF0 */
      {
	if(jpg_check_sof0(buffer, buffer_size, i)!=0)
	{
	  /*@ assert file_recovery->data_check == &data_check_jpg; */
	  return DC_STOP;
	}
      }
      else if(buffer[i+1]==0xc4)	/* DHT */
      {
	if(jpg_check_dht(buffer, buffer_size, i, 2+size)!=0)
	{
	  /*@ assert file_recovery->data_check == &data_check_jpg; */
	  return DC_STOP;
	}
      }
      else if(buffer[i+1]==0xda)	/* SOS: Start Of Scan */
      {
	data_check_t tmp;
	file_recovery->data_check=&data_check_jpg2;
	/*@ assert file_recovery->calculated_file_size >= 2; */
	tmp=data_check_jpg2(buffer, buffer_size, file_recovery);
	/*@ assert file_recovery->data_check == &data_check_jpg2 || file_recovery->data_check == \null || file_recovery->data_check == &data_check_continue; */
	/*@ assert file_recovery->data_check == &data_check_jpg2 ==> file_recovery->calculated_file_size >= 2; */
	return tmp;
      }
      else if(buffer[i+1]==0xe2)	/* APP2 Exif information */
      {
	if(i+8 < buffer_size &&
	    buffer[i+4]=='M' && buffer[i+5]=='P' && buffer[i+6]=='F' && buffer[i+7]==0)
	{
	  const uint64_t offset=old_calculated_file_size+8;
	  if(i>=buffer_size/2)
	  {
	    /* Restore previous value */
	    file_recovery->calculated_file_size=old_calculated_file_size;
	    /*@ assert file_recovery->data_check == &data_check_jpg; */
	    return DC_CONTINUE;
	  }
	  /*@ assert 0 <= i < buffer_size / 2 ; */
	  if( i + size <= buffer_size)
	  {
	    /*@ assert i + size <= buffer_size; */
	    /*@ assert size <= buffer_size - i; */
	    if(size >= 16)
	    {
	      /*@ assert 16 <= size <= 65535; */
	      /*@ assert \valid_read(buffer + (0 .. buffer_size-1)); */
	      /*@ assert \valid_read(buffer + (0 .. i+size-1)); */
	      /*@ assert \valid_read((buffer + i ) + (0 .. size-1)); */
	      /*@ assert \valid_read((buffer + i + 8) + (0 .. size-8-1)); */
	      const unsigned char *mpo=buffer + i + 8;
	      const unsigned int size_mpo=size-8;
	      /*@ assert \valid_read(mpo + (0 .. size-8-1)); */
	      /*@ assert \valid_read(mpo + (0 .. size_mpo-1)); */
	      const uint64_t calculated_file_size=check_mpo(mpo, offset, size_mpo);
	      if(calculated_file_size > 0)
	      {
		/* Multi-picture format */
		file_recovery->calculated_file_size=calculated_file_size;
		file_recovery->data_check=&data_check_size;
		file_recovery->file_check=&file_check_mpo;
		/*@ assert file_recovery->data_check == &data_check_size; */
		return DC_CONTINUE;
	      }
	    }
	  }
	  else
	  {
	    const unsigned int size_test=buffer_size-i;
	    /*@ assert size_test == buffer_size - i; */
	    if(size_test >= 16)
	    {
	      /*@ assert 16 <= size_test; */
	      const uint64_t calculated_file_size=check_mpo(buffer+i+8, offset, size_test-8);
	      if(calculated_file_size > 0)
	      {
		/* Multi-picture format */
		file_recovery->calculated_file_size=calculated_file_size;
		file_recovery->data_check=&data_check_size;
		file_recovery->file_check=&file_check_mpo;
		/*@ assert file_recovery->data_check == &data_check_size; */
		return DC_CONTINUE;
	      }
	    }
	  }
	}
      }
    }
    else
    {
#if 0
      log_info("data_check_jpg %02x at %llu\n", buffer[i],
	  (long long unsigned)file_recovery->calculated_file_size);
#endif
      /*@ assert file_recovery->data_check == &data_check_jpg; */
      return DC_STOP;
    }
  }
  /*@ assert file_recovery->data_check == &data_check_jpg; */
  /*@ assert file_recovery->calculated_file_size < file_recovery->file_size - buffer_size/2 || file_recovery->calculated_file_size >= file_recovery->file_size + buffer_size/2 - 4; */
  /*X TODO assert file_recovery->calculated_file_size >= file_recovery->file_size + buffer_size/2 - 4; */
  return DC_CONTINUE;
}

/*@
  @ requires valid_register_header_check(file_stat);
  @*/
static void register_header_check_jpg(file_stat_t *file_stat)
{
  static const unsigned char jpg_header[3]= { 0xff,0xd8,0xff};
  register_header_check(0, jpg_header, sizeof(jpg_header), &header_check_jpg, file_stat);
}
#endif

const char*td_jpeg_version(void)
{
#if defined(HAVE_LIBJPEG)
#ifdef LIBJPEG_TURBO_VERSION
#define td_xstr(s) td_str(s)
#define td_str(s) #s
  static char buffer[32];
  sprintf(buffer,"libjpeg-turbo-%s", "" td_xstr(LIBJPEG_TURBO_VERSION));
  return buffer;
#elif defined(JPEG_LIB_VERSION)
  static char buffer[32];
  sprintf(buffer,"%d", JPEG_LIB_VERSION);
  return buffer;
#else
  return "yes";
#endif
#else
  return "none";
#endif
}

#if defined(MAIN_jpg)
#define BLOCKSIZE 65536u
int main()
{
  const char fn[] = "recup_dir.1/f0000000.jpg";
  unsigned char buffer[BLOCKSIZE];
  file_recovery_t file_recovery_new;
  file_recovery_t file_recovery;
  file_stat_t file_stats;

  /*@ assert \valid(buffer + (0 .. (BLOCKSIZE - 1))); */
#if defined(__FRAMAC__)
  Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif

  reset_file_recovery(&file_recovery);
  file_recovery.blocksize=BLOCKSIZE;
  file_recovery_new.blocksize=BLOCKSIZE;
  file_recovery_new.data_check=NULL;
  file_recovery_new.file_stat=NULL;
  file_recovery_new.file_check=NULL;
  file_recovery_new.file_rename=NULL;
  file_recovery_new.calculated_file_size=0;
  file_recovery_new.file_size=0;
  file_recovery_new.offset_ok=0;
  file_recovery_new.checkpoint_status=0;
  file_recovery_new.location.start=0;
  file_recovery_new.offset_error=0;
  file_recovery_new.time=0;

  file_stats.file_hint=&file_hint_jpg;
  file_stats.not_recovered=0;
  file_stats.recovered=0;
  register_header_check_jpg(&file_stats);
  if(header_check_jpg(buffer, BLOCKSIZE, 0u, &file_recovery, &file_recovery_new)!=1)
    return 0;
  /*@ assert file_recovery_new.file_check == file_check_jpg; */
  /*@ assert file_recovery_new.extension == file_hint_jpg.extension; */
  /*@ assert valid_read_string(file_recovery_new.extension); */
  /*@ assert file_recovery_new.file_size == 0;	*/
  /*@ assert file_recovery_new.offset_ok == 0;	*/
  /*@ assert valid_read_string((char *)&fn); */
  /*@ assert \initialized(&file_recovery_new.time); */
  memcpy(file_recovery_new.filename, fn, sizeof(fn));
  /*@ assert valid_read_string((char *)&file_recovery_new.filename); */
  /*@ assert file_recovery_new.offset_ok == 0;	*/
  file_recovery_new.file_stat=&file_stats;
  {
    unsigned char big_buffer[2*BLOCKSIZE];
    data_check_t res_data_check=DC_CONTINUE;
    memset(big_buffer, 0, BLOCKSIZE);
    memcpy(big_buffer + BLOCKSIZE, buffer, BLOCKSIZE);
    /*@ assert file_recovery_new.data_check == &data_check_jpg; */
    /*@ assert file_recovery_new.file_size == 0; */;
    res_data_check=data_check_jpg(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    /*@ assert file_recovery_new.data_check == &data_check_jpg2 ==> file_recovery_new.calculated_file_size >= 2; */
    file_recovery_new.file_size+=BLOCKSIZE;
    if(res_data_check == DC_CONTINUE)
    {
      memcpy(big_buffer, big_buffer + BLOCKSIZE, BLOCKSIZE);
#if defined(__FRAMAC__)
      Frama_C_make_unknown((char *)big_buffer + BLOCKSIZE, BLOCKSIZE);
#endif
      /*@ assert file_recovery_new.data_check == &data_check_jpg || file_recovery_new.data_check == &data_check_jpg2 || file_recovery_new.data_check == &data_check_size || file_recovery_new.data_check == NULL; */
      if(file_recovery_new.data_check == &data_check_jpg)
	res_data_check=data_check_jpg(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
      else if(file_recovery_new.data_check == &data_check_jpg2)
	res_data_check=data_check_jpg2(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
      else if(file_recovery_new.data_check == &data_check_size)
	res_data_check=data_check_size(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
      file_recovery_new.file_size+=BLOCKSIZE;
      if(res_data_check == DC_CONTINUE)
      {
	memcpy(big_buffer, big_buffer + BLOCKSIZE, BLOCKSIZE);
#if defined(__FRAMAC__)
	Frama_C_make_unknown((char *)big_buffer + BLOCKSIZE, BLOCKSIZE);
#endif
	/*@ assert file_recovery_new.data_check == &data_check_jpg || file_recovery_new.data_check == &data_check_jpg2 || file_recovery_new.data_check == &data_check_size || file_recovery_new.data_check == NULL; */
	if(file_recovery_new.data_check == &data_check_jpg)
	  res_data_check=data_check_jpg(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
	else if(file_recovery_new.data_check == &data_check_jpg2)
	  res_data_check=data_check_jpg2(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
	else if(file_recovery_new.data_check == &data_check_size)
	  res_data_check=data_check_size(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
	file_recovery_new.file_size+=BLOCKSIZE;
      }
    }
  }
  /*@ assert file_recovery_new.offset_ok == 0;	*/
  {
    file_recovery_t file_recovery_new2;
    /* Test when another file of the same is detected in the next block */
    file_recovery_new2.blocksize=BLOCKSIZE;
    file_recovery_new2.file_stat=NULL;
    file_recovery_new2.file_check=NULL;
    file_recovery_new2.location.start=BLOCKSIZE;
    file_recovery_new.handle=NULL;	/* In theory should be not null */
    header_check_jpg(buffer, BLOCKSIZE, 0, &file_recovery_new, &file_recovery_new2);
  }
  /*@ assert file_recovery_new.offset_ok == 0;	*/
  /*@ assert file_recovery_new.file_check == file_check_jpg || file_recovery_new.file_check == file_check_mpo; */
  if(file_recovery_new.file_check == file_check_jpg)
  {
    file_recovery_new.handle=fopen(fn, "rb");
    if(file_recovery_new.handle!=NULL)
    {
      file_check_jpg(&file_recovery_new);
      fclose(file_recovery_new.handle);
    }
  }
  else
  {
    /*@ assert file_recovery_new.file_check == file_check_mpo; */
    file_recovery_new.handle=fopen(fn, "rb");
    if(file_recovery_new.handle!=NULL)
    {
      file_check_mpo(&file_recovery_new);
      fclose(file_recovery_new.handle);
    }
  }
  return 0;
}
#endif
