/*

    File: file_tiff_be.c

    Copyright (C) 1998-2005,2007-2009, 2017 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_jpg)
extern const file_hint_t file_hint_jpg;
#endif
extern const file_hint_t file_hint_tiff;
static const char *extension_dcr="dcr";
static const char *extension_dng="dng";
static const char *extension_nef="nef";
static const char *extension_pef="pef";

#ifndef MAIN_tiff_le
/*@
  @ requires \valid_read(buffer+(0..tiff_size-1));
  @ terminates \true;
  @ ensures \result <= 0xffff;
  @ assigns \nothing;
  @ */
static unsigned int get_nbr_fields_be(const unsigned char *buffer, const unsigned int tiff_size, const unsigned int offset_hdr)
{
  const unsigned char *ptr_hdr;
  const struct ifd_header *hdr;
  if(sizeof(struct ifd_header) > tiff_size)
    return 0;
  /*@ assert tiff_size >= sizeof(struct ifd_header); */
  if(offset_hdr > tiff_size - sizeof(struct ifd_header))
    return 0;
  /*@ assert offset_hdr + sizeof(struct ifd_header) <= tiff_size; */
  ptr_hdr=&buffer[offset_hdr];
  /*@ assert \valid_read(ptr_hdr + (0 .. sizeof(struct ifd_header)-1)); */
  hdr=(const struct ifd_header *)ptr_hdr;
  /*@ assert \valid_read(hdr); */
  return be16(hdr->nbr_fields);
}

/*@
  @ requires \valid_read(buffer+(0..tiff_size-1));
  @ requires \valid(potential_error);
  @ requires \separated(potential_error, buffer+(..));
  @ terminates \true;
  @ assigns *potential_error;
  @
 */
static unsigned int find_tag_from_tiff_header_be_aux(const unsigned char *buffer, const unsigned int tiff_size, const unsigned int tag, const unsigned char**potential_error, const unsigned int offset_hdr)
{
  const unsigned char *ptr_hdr;
  const struct ifd_header *hdr;
  unsigned int i;
  unsigned int nbr_fields;
  if(sizeof(struct ifd_header) > tiff_size)
    return 0;
  /*@ assert tiff_size >= sizeof(struct ifd_header); */
  if(offset_hdr > tiff_size - sizeof(struct ifd_header))
    return 0;
  /*@ assert offset_hdr + sizeof(struct ifd_header) <= tiff_size; */
  ptr_hdr=&buffer[offset_hdr];
  /*@ assert \valid_read(ptr_hdr + (0 .. sizeof(struct ifd_header)-1)); */
  hdr=(const struct ifd_header *)ptr_hdr;
  /*@ assert \valid_read(hdr); */
  nbr_fields=be16(hdr->nbr_fields);
  /*@ assert \valid_read(buffer+(0..tiff_size-1)); */
  /*@
    @ loop invariant \valid_read(buffer+(0..tiff_size-1));
    @ loop invariant \valid(potential_error);
    @ loop assigns i, *potential_error;
    @ loop variant nbr_fields - i;
    @*/
  for(i=0; i < nbr_fields; i++)
  {
    /*@ assert \valid_read(buffer+(0..tiff_size-1)); */
    const unsigned int offset_entry=offset_hdr + 2 + i * sizeof(TIFFDirEntry);
    const unsigned char *ptr_entry;
    const TIFFDirEntry *tmp;
    if(offset_entry + sizeof(TIFFDirEntry) > tiff_size)
      return 0;
    /*@ assert offset_entry + sizeof(TIFFDirEntry) <= tiff_size; */
    /*X assert \valid_read(buffer + (0 .. offset_entry + sizeof(TIFFDirEntry)-1)); */
    /*X assert \valid_read((buffer + offset_entry) + (0 .. sizeof(TIFFDirEntry)-1)); */
    ptr_entry=buffer + offset_entry;
    /*@ assert \valid_read(ptr_entry + (0 .. sizeof(TIFFDirEntry)-1)); */
    tmp=(const TIFFDirEntry *)ptr_entry;
    /*@ assert \valid_read(tmp); */
    if(be16(tmp->tdir_type) > 18 && (*potential_error==NULL || *potential_error > (const unsigned char*)&tmp->tdir_type))
    {
      *potential_error = (const unsigned char*)&tmp->tdir_type;
    }
    if(be16(tmp->tdir_tag)==tag)
    {
      /*@ assert \valid_read(buffer+(0..tiff_size-1)); */
      return be32(tmp->tdir_offset);
    }
  }
  /*@ assert \valid_read(buffer+(0..tiff_size-1)); */
  return 0;
}

unsigned int find_tag_from_tiff_header_be(const unsigned char *buffer, const unsigned int tiff_size, const unsigned int tag, const unsigned char**potential_error)
{
  /*@ assert tiff_size >= sizeof(TIFFHeader); */
  /*@ assert tiff_size >= sizeof(struct ifd_header); */
  /*@ assert \valid_read(buffer+(0..tiff_size-1)); */
  const TIFFHeader *tiff=(const TIFFHeader *)buffer;
  unsigned int offset_ifd0;
  unsigned int offset_exififd;
  /*@ assert \valid_read(tiff); */
  offset_ifd0=be32(tiff->tiff_diroff);
  if(offset_ifd0 >= tiff_size)
    return 0;
  /*@ assert offset_ifd0 < tiff_size; */
  if(offset_ifd0 > tiff_size - sizeof(struct ifd_header))
    return 0;
  /*@ assert \valid_read(buffer+(0..tiff_size-1)); */
  /*@ assert offset_ifd0 + sizeof(struct ifd_header) <= tiff_size; */
  {
    const unsigned int tmp=find_tag_from_tiff_header_be_aux(buffer, tiff_size, tag, potential_error, offset_ifd0);
    /*@ assert \valid_read(buffer+(0..tiff_size-1)); */
    if(tmp)
      return tmp;
  }
  offset_exififd=find_tag_from_tiff_header_be_aux(buffer, tiff_size, TIFFTAG_EXIFIFD, potential_error, offset_ifd0);
  /*@ assert \valid_read(buffer+(0..tiff_size-1)); */
  if(offset_exififd <= tiff_size - sizeof(struct ifd_header))
  {
    /* Exif */
    const unsigned int tmp=find_tag_from_tiff_header_be_aux(buffer, tiff_size, tag, potential_error, offset_exififd);
    /*@ assert \valid_read(buffer+(0..tiff_size-1)); */
    if(tmp)
      return tmp;
  }
  {
    const unsigned int nbr_fields=get_nbr_fields_be(buffer, tiff_size, offset_ifd0);
    unsigned int offset_tiff_next_diroff;
    offset_tiff_next_diroff=offset_ifd0 + 2 + nbr_fields * sizeof(TIFFDirEntry);
    /*@ assert tiff_size >= 4; */
    if(offset_tiff_next_diroff < tiff_size - 4)
    {
      const unsigned char *ptr_hdr;
      const uint32_t *tiff_next_diroff;
      unsigned int offset_ifd1;
      /*@ assert offset_tiff_next_diroff + 4 <= tiff_size; */
      ptr_hdr=&buffer[offset_tiff_next_diroff];
      /*@ assert \valid_read(ptr_hdr + (0 .. 4-1)); */
      tiff_next_diroff=(const uint32_t *)ptr_hdr;
      /*@ assert \valid_read(tiff_next_diroff); */
      /* IFD1 */
      offset_ifd1=be32(*tiff_next_diroff);
      if(offset_ifd1 > 0)
	return find_tag_from_tiff_header_be_aux(buffer, tiff_size, tag, potential_error, offset_ifd1);
    }
  }
  /*@ assert \valid_read(buffer+(0..tiff_size-1)); */
  return 0;
}

#if !defined(MAIN_tiff_le) && !defined(MAIN_jpg) && !defined(SINGLE_FORMAT_jpg)
/*@
  @ requires nbr <= 2048;
  @ requires \valid_read(offsetp + (0 .. nbr-1));
  @ requires \valid_read(sizep + (0 .. nbr-1));
  @ requires \initialized(offsetp + (0 .. nbr-1));
  @ requires \initialized(sizep + (0 .. nbr-1));
  @ terminates \true;
  @ assigns \nothing;
  @*/
static uint64_t parse_strip_be_aux(const uint32_t *offsetp, const uint32_t *sizep, const unsigned int nbr)
{
  unsigned int i;
  uint64_t max_offset=0;
  /*@
    @ loop invariant \valid_read(offsetp + (0 .. nbr-1));
    @ loop invariant \valid_read(sizep + (0 .. nbr-1));
    @ loop assigns i, max_offset;
    @ loop variant nbr - i;
    @*/
  for(i=0; i<nbr; i++)
  {
    /*@ assert 0 <= i < nbr; */
    const uint64_t tmp=(uint64_t)be32(offsetp[i]) + be32(sizep[i]);
    if(max_offset < tmp)
      max_offset=tmp;
  }
  return max_offset;
}

/*@
  @ requires \valid(handle);
  @ requires \valid_read(entry_strip_offsets);
  @ requires \valid_read(entry_strip_bytecounts);
  @ requires \separated(handle, &errno, &Frama_C_entropy_source, &__fc_heap_status, \union(entry_strip_offsets, entry_strip_bytecounts));
  @ assigns *handle, errno;
  @ assigns Frama_C_entropy_source;
  @*/
static uint64_t parse_strip_be(FILE *handle, const TIFFDirEntry *entry_strip_offsets, const TIFFDirEntry *entry_strip_bytecounts)
{
  const unsigned int nbr=(be32(entry_strip_offsets->tdir_count)<2048?
      be32(entry_strip_offsets->tdir_count):
      2048);
  /*@ assert nbr <= 2048; */
  char offsetp_buf[2048*sizeof(uint32_t)];
  char sizep_buf[2048*sizeof(uint32_t)];
  /* be32() isn't required to compare the 2 values */
  if(entry_strip_offsets->tdir_count != entry_strip_bytecounts->tdir_count)
    return TIFF_ERROR;
  /*@ assert entry_strip_offsets->tdir_count == entry_strip_bytecounts->tdir_count; */
  if(nbr==0 ||
      be16(entry_strip_offsets->tdir_type)!=4 ||
      be16(entry_strip_bytecounts->tdir_type)!=4)
    return TIFF_ERROR;
  /*@ assert 0 < nbr <= 2048; */
  if(fseek(handle, be32(entry_strip_offsets->tdir_offset), SEEK_SET) < 0 ||
      fread(&offsetp_buf, sizeof(uint32_t), nbr, handle) != nbr)
  {
    return TIFF_ERROR;
  }
  if(fseek(handle, be32(entry_strip_bytecounts->tdir_offset), SEEK_SET) < 0 ||
      fread(&sizep_buf, sizeof(uint32_t), nbr, handle) != nbr)
  {
    return TIFF_ERROR;
  }
#if defined(__FRAMAC__)
  Frama_C_make_unknown(offsetp_buf, 2048*sizeof(uint32_t));
  Frama_C_make_unknown(sizep_buf, 2048*sizeof(uint32_t));
#endif
  /*@ assert \initialized(offsetp_buf + (0 .. nbr*sizeof(uint32_t)-1)); */
  /*@ assert \initialized(sizep_buf + (0 .. nbr*sizeof(uint32_t)-1)); */
  return parse_strip_be_aux((const uint32_t *)&offsetp_buf, (const uint32_t *)&sizep_buf, nbr);
}

/*@
  @ requires type == 1 ==> \valid_read((const char *)val);
  @ requires type == 1 ==> \initialized((const char *)val);
  @ requires type == 3 ==> \valid_read((const char *)val + ( 0 .. 2));
  @ requires type == 3 ==> \initialized((const char *)val + ( 0 .. 2));
  @ requires type == 4 ==> \valid_read((const char *)val + ( 0 .. 4));
  @ requires type == 4 ==> \initialized((const char *)val + ( 0 .. 4));
  @ terminates \true;
  @ assigns \nothing;
  @*/
static unsigned int tiff_be_read(const void *val, const unsigned int type)
{
  switch(type)
  {
    case 1:
      {
        const uint8_t *ptr=(const uint8_t *)val;
        /*@ assert \valid_read(ptr); */
        return *ptr;
      }
    case 3:
      {
        const uint16_t *ptr=(const uint16_t *)val;
        /*@ assert \valid_read(ptr); */
	const uint16_t tmp=*ptr;
        return be16(tmp);
      }
    case 4:
      {
        const uint32_t *ptr=(const uint32_t *)val;
        /*@ assert \valid_read(ptr); */
	const uint32_t tmp=*ptr;
        return be32(tmp);
      }
    default:
      return 0;
  }
}
#endif

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
    return TIFF_ERROR;
  if(fseek(in, tiff_diroff, SEEK_SET) < 0)
    return TIFF_ERROR;
  data_read=fread(buffer, 1, sizeof(buffer), in);
  if(data_read<2)
    return TIFF_ERROR;
  /*@ assert data_read >= 2; */
#if defined(__FRAMAC__)
  Frama_C_make_unknown((char *)buffer, sizeof(buffer));
#endif
  /*@ assert 2 <= data_read <= sizeof(buffer); */
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
  if(n > (unsigned int)(data_read-2)/12)
    n=(data_read-2)/12;
  if(n==0)
    return TIFF_ERROR;
  for(i=0;i<n;i++)
  {
    const uint64_t val=(uint64_t)be32(entry->tdir_count) * tiff_type2size(be16(entry->tdir_type));
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
	return TIFF_ERROR;
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
#endif

#if !defined(MAIN_tiff_le) && !defined(MAIN_jpg) && !defined(SINGLE_FORMAT_jpg) && !defined(SINGLE_FORMAT_rw2) && !defined(SINGLE_FORMAT_orf) && !defined(SINGLE_FORMAT_wdp)
/*@
  @ requires valid_file_check_param(fr);
  @ requires valid_read_string(fr->extension);
  @ requires depth <= 5;
  @ decreases 5 - depth;
  @ ensures valid_file_check_param(fr);
  @ ensures valid_read_string(fr->extension);
  @ assigns *fr->handle, errno;
  @ assigns Frama_C_entropy_source;
  @*/
static uint64_t file_check_tiff_be_aux(file_recovery_t *fr, const uint32_t tiff_diroff, const unsigned int depth, const unsigned int count)
{
  char buffer[8192];
  const unsigned char *ubuffer=(const unsigned char *)buffer;
  /*@ assert \valid_read(ubuffer + (0 .. sizeof(buffer)-1)); */
  unsigned int i,n;
  int data_read;
  uint64_t alphabytecount=0;
  uint64_t alphaoffset=0;
  uint64_t imagebytecount=0;
  uint64_t imageoffset=0;
  uint64_t jpegifbytecount=0;
  uint64_t jpegifoffset=0;
  uint64_t max_offset=0;
  uint64_t strip_bytecounts=0;
  uint64_t strip_offsets=0;
  uint64_t tile_bytecounts=0;
  uint64_t tile_offsets=0;
  unsigned int sorted_tag_error=0;
  unsigned int tdir_tag_old=0;
  const TIFFDirEntry *entries=(const TIFFDirEntry *)&buffer[2];
  const TIFFDirEntry *entry_strip_offsets=NULL;
  const TIFFDirEntry *entry_strip_bytecounts=NULL;
  const TIFFDirEntry *entry_tile_offsets=NULL;
  const TIFFDirEntry *entry_tile_bytecounts=NULL;
  /*@ assert \valid(fr); */
  /*@ assert \valid(fr->handle); */
  /*@ assert \valid_read(&fr->extension); */
  /*@ assert valid_read_string(fr->extension); */
#ifdef DEBUG_TIFF
  log_info("file_check_tiff_be_aux(fr, %lu, %u, %u)\n", (long unsigned)tiff_diroff, depth, count);
#endif
  if(depth>4)
    return TIFF_ERROR;
  /*@ assert depth <= 4; */
  if(count>16)
    return TIFF_ERROR;
  /*@ assert count <= 16; */
  if(tiff_diroff < sizeof(TIFFHeader))
    return TIFF_ERROR;
  if(fseek(fr->handle, tiff_diroff, SEEK_SET) < 0)
    return TIFF_ERROR;
  data_read=fread(buffer, 1, sizeof(buffer), fr->handle);
#if defined(__FRAMAC__)
  data_read = Frama_C_interval(0, sizeof(buffer));
  /*@ assert 0 <= data_read <= sizeof(buffer); */
  Frama_C_make_unknown(buffer, sizeof(buffer));
#endif
  if(data_read<2)
    return TIFF_ERROR;
  /*@ assert 2 <= data_read <= sizeof(buffer); */
  n=(ubuffer[0]<<8)+ubuffer[1];
#ifdef DEBUG_TIFF
  log_info("file_check_tiff_be_aux(fr, %lu, %u, %u) => %u entries\n", (long unsigned)tiff_diroff, depth, count, n);
#endif
  if(n==0)
    return TIFF_ERROR;
  /*@ assert 0 < n <= 65535; */
  /*@ assert sizeof(TIFFDirEntry)==12; */
  /*X
    X loop invariant 0 <= i <=n && i <= (data_read-2)/12;
    X*/
  /*@
    @ loop invariant valid_file_check_param(fr);
    @ loop assigns *fr->handle, errno;
    @ loop assigns Frama_C_entropy_source;
    @ loop assigns i, sorted_tag_error, tdir_tag_old;
    @ loop assigns alphabytecount;
    @ loop assigns alphaoffset;
    @ loop assigns imagebytecount;
    @ loop assigns imageoffset;
    @ loop assigns jpegifbytecount;
    @ loop assigns jpegifoffset;
    @ loop assigns max_offset;
    @ loop assigns strip_bytecounts;
    @ loop assigns strip_offsets;
    @ loop assigns tile_bytecounts;
    @ loop assigns tile_offsets;
    @ loop assigns entry_strip_offsets;
    @ loop assigns entry_strip_bytecounts;
    @ loop assigns entry_tile_offsets;
    @ loop assigns entry_tile_bytecounts;
    @ loop variant n-i;
    @*/
  for(i=0; i < n && i < (unsigned int)(data_read-2)/12; i++)
  {
    /*@ assert \valid(fr); */
    /*@ assert \valid(fr->handle); */
    /*@ assert \valid_read(&fr->extension); */
    /*@ assert valid_read_string(fr->extension); */
    const TIFFDirEntry *entry=&entries[i];
    /*@ assert 0 <= i < n; */
    /*@ assert \valid_read(entry); */
    const unsigned int tdir_count=be32(entry->tdir_count);
    const unsigned int tdir_tag=be16(entry->tdir_tag);
    const uint64_t val=(uint64_t)tdir_count * tiff_type2size(be16(entry->tdir_type));
#ifdef DEBUG_TIFF
    log_info("%u tag=%u(0x%x) %s type=%u count=%lu offset=%lu(0x%lx) val=%lu\n",
	i,
	tdir_tag,
	tdir_tag,
	tag_name(tdir_tag),
	be16(entry->tdir_type),
	(long unsigned)tdir_count,
	(long unsigned)be32(entry->tdir_offset),
	(long unsigned)be32(entry->tdir_offset),
	(long unsigned)val);
#endif
    if(tdir_tag_old > tdir_tag)
    { /* Entries must be sorted by tag */
      if(sorted_tag_error > 0)
      {
	return TIFF_ERROR;
      }
      else
	sorted_tag_error=1;
    }
    if(val>4)
    {
      const uint64_t new_offset=be32(entry->tdir_offset)+val;
      if(new_offset==0)
	return TIFF_ERROR;
      if(max_offset < new_offset)
	max_offset=new_offset;
    }
    if(tdir_count==1 && val<=4)
    {
      const unsigned int tmp=tiff_be_read(&entry->tdir_offset, be16(entry->tdir_type));
      switch(tdir_tag)
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
	    /*@ assert valid_file_check_param(fr); */
	    /*@ assert valid_read_string(fr->extension); */
	    /*@ assert depth <= 4; */
	    const uint64_t new_offset=file_check_tiff_be_aux(fr, tmp, depth+1, 0);
	    /*@ assert valid_file_check_param(fr); */
	    /*@ assert valid_read_string(fr->extension); */
	    if(new_offset==TIFF_ERROR)
	      return TIFF_ERROR;
	    if(max_offset < new_offset)
	      max_offset=new_offset;
	  }
	  break;
	case TIFFTAG_SUBIFD:
	  {
	    /*@ assert valid_file_check_param(fr); */
	    /*@ assert valid_read_string(fr->extension); */
	    /*@ assert depth <= 4; */
	    const uint64_t new_offset=file_check_tiff_be_aux(fr, tmp, depth+1, 0);
	    /*@ assert valid_file_check_param(fr); */
	    /*@ assert valid_read_string(fr->extension); */
	    if(new_offset==TIFF_ERROR)
	      return TIFF_ERROR;
	    if(max_offset < new_offset)
	      max_offset=new_offset;
	  }
	  break;
#ifdef ENABLE_TIFF_MAKERNOTE
	case EXIFTAG_MAKERNOTE:
	  {
	    const uint64_t new_offset=tiff_be_makernote(fr->handle, tmp);
	    if(new_offset==TIFF_ERROR)
	      return TIFF_ERROR;
	    if(max_offset < new_offset)
	      max_offset=new_offset;
	  }
	  break;
#endif
      }
    }
    else if(tdir_count > 1)
    {
      /*@ assert tdir_count > 1; */
      switch(tdir_tag)
      {
	case TIFFTAG_EXIFIFD:
	case TIFFTAG_KODAKIFD:
	case TIFFTAG_SUBIFD:
	  if(be16(entry->tdir_type)==4)
	  {
	    const unsigned int nbr=(tdir_count<32?tdir_count:32);
	    /*@ assert 2 <= nbr <= 32; */
	    char subifd_offsetp_buf[32*sizeof(uint32_t)];
	    const uint32_t *subifd_offsetp=(const uint32_t *)&subifd_offsetp_buf;
	    /*@ assert \valid_read(subifd_offsetp + (0 .. 31)); */
	    unsigned int j;
	    if(fseek(fr->handle, be32(entry->tdir_offset), SEEK_SET) < 0)
	    {
	      return TIFF_ERROR;
	    }
	    if(fread(&subifd_offsetp_buf, sizeof(uint32_t), nbr, fr->handle) != nbr)
	    {
	      return TIFF_ERROR;
	    }
#if defined(__FRAMAC__)
	    Frama_C_make_unknown(&subifd_offsetp_buf, sizeof(subifd_offsetp_buf));
#endif
	    /*@
	      @ loop invariant valid_file_check_param(fr);
	      @ loop invariant \separated(fr, fr->handle, fr->extension, &errno, &Frama_C_entropy_source);
	      @ loop assigns *fr->handle, errno;
	      @ loop assigns Frama_C_entropy_source;
	      @ loop assigns j, max_offset;
	      @ loop variant nbr - j;
	      @*/
	    for(j=0; j<nbr; j++)
	    {
	      /*@ assert valid_file_check_param(fr); */
	      /*@ assert valid_read_string(fr->extension); */
	      /*@ assert depth <= 4; */
	      const uint64_t new_offset=file_check_tiff_be_aux(fr, be32(subifd_offsetp[j]), depth+1, 0);
	      /*@ assert valid_file_check_param(fr); */
	      /*@ assert valid_read_string(fr->extension); */
	      if(new_offset==TIFF_ERROR)
	      {
		return TIFF_ERROR;
	      }
	      if(max_offset < new_offset)
		max_offset = new_offset;
	    }
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
    tdir_tag_old=tdir_tag;
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
    if(tmp==TIFF_ERROR)
      return TIFF_ERROR;
    if(max_offset < tmp)
      max_offset=tmp;
  }
  if(entry_tile_offsets != NULL && entry_tile_bytecounts != NULL)
  {
    const uint64_t tmp=parse_strip_be(fr->handle, entry_tile_offsets, entry_tile_bytecounts);
    if(tmp==TIFF_ERROR)
      return TIFF_ERROR;
    if(max_offset < tmp)
      max_offset=tmp;
  }
  if(data_read < 4)
    return max_offset;
  /*@ assert data_read >= 4; */
  {
    const unsigned int offset_ptr_offset=2+12*n;
    uint64_t new_offset;
    if(offset_ptr_offset > data_read-4)
      return max_offset;
    /*@ assert offset_ptr_offset <= data_read - 4; */
    /*@ assert offset_ptr_offset + 4 <= data_read; */
    {
      /*@ assert \valid_read(ubuffer + (0 .. offset_ptr_offset + 4 - 1)); */
      const unsigned char *ptr_offset=&ubuffer[offset_ptr_offset];
      /*@ assert \valid_read(ptr_offset + (0 .. 4 - 1)); */
      const uint32_t *ptr32_offset=(const uint32_t *)ptr_offset;
      /*@ assert \valid_read(ptr32_offset); */
      const unsigned int next_diroff=be32(*ptr32_offset);
      if(next_diroff == 0)
	return max_offset;
      /*@ assert valid_file_check_param(fr); */
      /*@ assert valid_read_string(fr->extension); */
      /*@ assert depth <= 4; */
      new_offset=file_check_tiff_be_aux(fr, next_diroff, depth+1, count+1);
      /*@ assert valid_file_check_param(fr); */
      /*@ assert valid_read_string(fr->extension); */
    }
    if(new_offset != TIFF_ERROR && max_offset < new_offset)
      max_offset=new_offset;
  }
  return max_offset;
}

/*@
  @ requires fr->file_check==&file_check_tiff_be;
  @ requires valid_file_check_param(fr);
  @ ensures  valid_file_check_result(fr);
  @ assigns  errno;
  @ assigns  fr->file_size;
  @ assigns  *fr->handle;
  @ assigns  Frama_C_entropy_source;
  @*/
static void file_check_tiff_be(file_recovery_t *fr)
{
  /*@ assert \valid(fr); */
  uint64_t calculated_file_size=0;
  char buffer[sizeof(TIFFHeader)];
  const TIFFHeader *header=(const TIFFHeader *)&buffer;
  /*@ assert \valid_read(header); */
  if(fseek(fr->handle, 0, SEEK_SET) < 0 ||
      fread(&buffer, sizeof(TIFFHeader), 1, fr->handle) != 1)
  {
    fr->file_size=0;
    return;
  }
#if defined(__FRAMAC__)
  Frama_C_make_unknown(&buffer, sizeof(TIFFHeader));
#endif
  if(header->tiff_magic==TIFF_BIGENDIAN)
    calculated_file_size=file_check_tiff_be_aux(fr, be32(header->tiff_diroff), 0, 0);
  /*@ assert \valid(fr->handle); */
#ifdef DEBUG_TIFF
  log_info("TIFF Current   %llu\n", (unsigned long long)fr->file_size);
  log_info("TIFF Estimated %llu %llx\n", (unsigned long long)calculated_file_size, (unsigned long long)calculated_file_size);
#endif
  if(fr->file_size < calculated_file_size || calculated_file_size==0 || calculated_file_size==TIFF_ERROR)
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

/*@
  @ requires separation: \separated(&file_hint_tiff, buffer+(..), file_recovery, file_recovery_new);
  @ ensures (\result == 1) ==> (file_recovery_new->file_check == &file_check_tiff_be);
  @ ensures (\result == 1) ==> (file_recovery_new->extension == file_hint_tiff.extension ||
				file_recovery_new->extension == extension_dcr ||
				file_recovery_new->extension == extension_dng ||
				file_recovery_new->extension == extension_nef ||
				file_recovery_new->extension == extension_pef);
  @*/
int header_check_tiff_be(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /*@ assert buffer_size >= 20; */
  const unsigned char *potential_error=NULL;
  const TIFFHeader *header=(const TIFFHeader *)buffer;
  /*@ assert \valid_read(header); */
  if((uint32_t)be32(header->tiff_diroff) < sizeof(TIFFHeader))
    return 0;
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_jpg)
  if(file_recovery->file_stat!=NULL &&
      file_recovery->file_stat->file_hint==&file_hint_jpg)
  {
    if(header_ignored_adv(file_recovery, file_recovery_new)==0)
      return 0;
  }
#endif
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_tiff.extension;
  if(find_tag_from_tiff_header_be(buffer, buffer_size, TIFFTAG_DNGVERSION, &potential_error)!=0)
  {
    /* Adobe Digital Negative, ie. PENTAX K-30 */
    file_recovery_new->extension=extension_dng;
  }
  else
  {
    const unsigned int tag_make=find_tag_from_tiff_header_be(buffer, buffer_size, TIFFTAG_MAKE, &potential_error);
    if(tag_make!=0 && tag_make < buffer_size - 20)
    {
      if( memcmp(&buffer[tag_make], "PENTAX Corporation ", 20)==0 ||
	  memcmp(&buffer[tag_make], "PENTAX             ", 20)==0)
	file_recovery_new->extension=extension_pef;
      else if(memcmp(&buffer[tag_make], "NIKON CORPORATION", 18)==0)
	file_recovery_new->extension=extension_nef;
      else if(memcmp(&buffer[tag_make], "Kodak", 6)==0)
	file_recovery_new->extension=extension_dcr;
    }
  }
  file_recovery_new->time=get_date_from_tiff_header(buffer, buffer_size);
  file_recovery_new->file_check=&file_check_tiff_be;
  return 1;
}
#endif
#endif

#if defined(MAIN_tiff_be)
#define BLOCKSIZE 65536u
int main()
{
  const char fn[] = "recup_dir.1/f0000000.tif";
  unsigned char buffer[BLOCKSIZE];
  int res;
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
  file_recovery_new.extension=NULL;
  file_recovery_new.file_stat=NULL;
  file_recovery_new.file_check=NULL;
  file_recovery_new.file_rename=NULL;
  file_recovery_new.calculated_file_size=0;
  file_recovery_new.file_size=0;
  file_recovery_new.location.start=0;

  file_stats.file_hint=&file_hint_tiff;
  file_stats.not_recovered=0;
  file_stats.recovered=0;
  file_hint_tiff.register_header_check(&file_stats);
  if(header_check_tiff_be(buffer, BLOCKSIZE, 0u, &file_recovery, &file_recovery_new)!=1)
    return 0;
  /*@ assert file_recovery_new.file_check == &file_check_tiff_be; */
  /*@ assert valid_read_string(file_recovery_new.extension); */
  /*@ assert (file_recovery_new.extension == file_hint_tiff.extension ||
    file_recovery_new.extension == extension_dcr ||
    file_recovery_new.extension == extension_dng ||
    file_recovery_new.extension == extension_nef ||
    file_recovery_new.extension == extension_pef); */
  /*@ assert valid_read_string((char *)&fn); */
  memcpy(file_recovery_new.filename, fn, sizeof(fn));
  /*@ assert valid_read_string(file_recovery_new.extension); */
  file_recovery_new.file_stat=&file_stats;
  /*@ assert valid_read_string(file_recovery_new.extension); */
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  /*@ assert file_recovery_new.data_check == \null; */
  /*@ assert file_recovery_new.file_stat->file_hint!=NULL; */
  {
    /*@ assert valid_read_string(file_recovery_new.extension); */
    file_recovery_t file_recovery_new2;
    file_recovery_new2.blocksize=BLOCKSIZE;
    file_recovery_new2.file_stat=NULL;
    file_recovery_new2.file_check=NULL;
    file_recovery_new2.location.start=BLOCKSIZE;
    file_recovery_new.handle=NULL;	/* In theory should be not null */
#if defined(__FRAMAC__)
    Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif
    header_check_tiff_be(buffer, BLOCKSIZE, 0, &file_recovery_new, &file_recovery_new2);
  }
  /*@ assert file_recovery_new.file_check == &file_check_tiff_be; */
  {
    file_recovery_new.handle=fopen(fn, "rb");
    if(file_recovery_new.handle!=NULL)
    {
      file_check_tiff_be(&file_recovery_new);
      fclose(file_recovery_new.handle);
    }
  }
  return 0;
}
#endif
