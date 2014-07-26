/*

    File: file_swf.c

    Copyright (C) 2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include <stdio.h>
#include "types.h"
#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif
#include "filegen.h"
#include "common.h"

static void register_header_check_swf(file_stat_t *file_stat);

const file_hint_t file_hint_swf= {
  .extension="swf",
  .description="Macromedia Flash (Compiled)",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_swf
};

struct swf_header
{
  char magic[3];
  unsigned char version;
  uint32_t size;
} __attribute__ ((__packed__));

static int read_SB(const unsigned char **data, unsigned int *offset_bit, unsigned int nbit)
{
  int res=0;
  const unsigned int sign=((**data) >>(7 - (*offset_bit)))&1;
  while(nbit>1)
  {
    (*offset_bit)++;
    if(*offset_bit==8)
    {
      (*data)++;
      *offset_bit=0;
    }
    res=(res<<1)|((**data>>(7 - *offset_bit))&1);
    nbit--;
  }
  if(sign)
    res=-res;
  return res;
}

static int header_check_swfc(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct swf_header *hdr=(const struct swf_header *)buffer;
  /* Compressed flash with Z_DEFLATED */
  if(!(buffer[3]>=6 && buffer[3]<=20 && (buffer[8]&0x0f)==8))
    return 0;
  if(le32(hdr->size) < 9)
    return 0;
#if defined(HAVE_ZLIB_H) && defined(HAVE_LIBZ)
  {
    const unsigned char *buffer_compr=buffer+8;
    unsigned char buffer_uncompr[512];
    const unsigned int comprLen=(buffer_size<512?buffer_size:512)-8;
    const unsigned int uncomprLen=512-1;
    int err;
    const unsigned char *data=(const unsigned char *)&buffer_uncompr;
    unsigned int offset_bit=5;
    unsigned int nbit;
    /* a twip is 1/20th of a logical pixel */
    int Xmin, Xmax, Ymin, Ymax;
    z_stream d_stream; /* decompression stream */
    d_stream.zalloc = (alloc_func)0;
    d_stream.zfree = (free_func)0;
    d_stream.opaque = (voidpf)0;

    d_stream.next_in  = (Bytef*)buffer_compr;
    d_stream.avail_in = 0;
    d_stream.next_out = buffer_uncompr;

    err = inflateInit(&d_stream);
    if(err!=Z_OK)
      return 0;
    while (d_stream.total_out < uncomprLen && d_stream.total_in < comprLen) {
      d_stream.avail_in = d_stream.avail_out = 1; /* force small buffers */
      err = inflate(&d_stream, Z_NO_FLUSH);
      if (err == Z_STREAM_END) break;
      if(err!=Z_OK)
      {
	/* Decompression has failed, free ressources */
	inflateEnd(&d_stream);
	return 0;
      }
    }
    err = inflateEnd(&d_stream);
    if(err!=Z_OK)
    {
      return 0;
    }
    /* Probably too small to be a file */
    if(d_stream.total_out < 16)
      return 0;
    nbit=(*data)>>3;
    if(nbit<=1)
      return 0;
    Xmin=read_SB(&data, &offset_bit, nbit);
    Xmax=read_SB(&data, &offset_bit, nbit);
    Ymin=read_SB(&data, &offset_bit, nbit);
    Ymax=read_SB(&data, &offset_bit, nbit);
    if(Xmin!=0 || Ymin!=0 || Xmax<=0 || Ymax<=0)
      return 0;
  }
#endif
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension="swc";
  file_recovery_new->calculated_file_size=le32(hdr->size);
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static int header_check_swf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /* http://www.adobe.com/go/swfspec */
  const struct swf_header *hdr=(const struct swf_header *)buffer;
  const unsigned char *data=&buffer[8];
  unsigned int offset_bit=5;
  unsigned int nbit;
  /* a twip is 1/20th of a logical pixel */
  int Xmin, Xmax, Ymin, Ymax;
  if(!(buffer[3]>=3 && buffer[3]<=20))
    return 0;
  if(le32(hdr->size) < 9)
    return 0;
  nbit=(*data)>>3;
  if(nbit<=1)
    return 0;
  Xmin=read_SB(&data, &offset_bit, nbit);
  Xmax=read_SB(&data, &offset_bit, nbit);
  Ymin=read_SB(&data, &offset_bit, nbit);
  Ymax=read_SB(&data, &offset_bit, nbit);
  if(Xmin!=0 || Ymin!=0 || Xmax<=0 || Ymax<=0)
    return 0;
#if 0
  data=&buffer[8+(5+4*nbit+8-1)/8];
#endif
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_swf.extension;
  file_recovery_new->calculated_file_size=le32(hdr->size);
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static void register_header_check_swf(file_stat_t *file_stat)
{
  register_header_check(0, "CWS", 3, &header_check_swfc, file_stat);
  register_header_check(0, "FWS", 3, &header_check_swf, file_stat);
}
