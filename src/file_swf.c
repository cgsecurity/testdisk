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
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_swf)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#if defined(DISABLED_FOR_FRAMAC)
#undef HAVE_ZLIB_H
#undef HAVE_LIBZ
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
#if defined(__FRAMAC__)
#include "__fc_builtin.h"
#endif

static const char *extension_swc="swc";
/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_swf(file_stat_t *file_stat);

const file_hint_t file_hint_swf= {
  .extension="swf",
  .description="Macromedia Flash (Compiled)",
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
} __attribute__ ((gcc_struct, __packed__));

struct swfz_header
{
  char magic[3];
  unsigned char version;
  uint32_t scriptLen;
  uint32_t compressedLen;
  uint8_t  LZMA_props[5];
} __attribute__ ((gcc_struct, __packed__));
// followed by LZMA data  and 6 bytes for LZMA end marker
// scriptLen is the uncompressed length of the SWF data. Includes 4 bytes SWF header and
// 4 bytes for scriptLen it
// compressedLen does not include header (4+4+4 bytes) or lzma props (5 bytes)
// compressedLen does include LZMA end marker (6 bytes)

/*@
  @ requires \valid(data);
  @ requires \valid_read(*data + (0..3));
  @ requires \valid(offset_bit);
  @ requires 0 <= *offset_bit <= 7;
  @ requires 2 <= nbit <= 31;
  @ requires separation: \separated(data, offset_bit, *data + (0..(nbit+*offset_bit)/8));
  @ terminates \true;
  @ ensures  0 <= *offset_bit <= 7;
  @ assigns *data, *offset_bit;
  @*/
static int read_SB(const unsigned char **data, unsigned int *offset_bit, unsigned int nbit)
{
  int res=0;
  const unsigned int sign=((**data) >>(7 - (*offset_bit)))&1;
  /*@
     loop unroll 31;
     loop assigns nbit, *offset_bit, *data, res;
     loop variant nbit;
     */
  while(nbit>1)
  {
    /*@ assert 0 <= *offset_bit <= 7; */
    (*offset_bit)++;
    /*@ assert 1 <= *offset_bit <= 8; */
    if(*offset_bit==8)
    {
      (*data)++;
      *offset_bit=0;
    }
    /*@ assert 0 <= *offset_bit <= 7; */
    res=(res<<1)|((**data>>(7 - *offset_bit))&1);
    nbit--;
  }
  if(sign)
    res=-res;
  return res;
}

/*@
  @ requires buffer_size >= 512;
  @ requires separation: \separated(&file_hint_swf, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ ensures (\result == 1) ==> (file_recovery_new->data_check == &data_check_size);
  @ ensures (\result == 1) ==> (file_recovery_new->file_check == &file_check_size_max);
  @ ensures (\result == 1) ==> (file_recovery_new->file_rename == \null);
  @ ensures (\result == 1) ==> (file_recovery_new->extension == extension_swc);
  @ assigns  *file_recovery_new;
  @*/
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
    /* assert nbit <= 31; */
    if(nbit<=1)
      return 0;
    /* assert 2 <= nbit <= 31; */
    Xmin=read_SB(&data, &offset_bit, nbit);
    Xmax=read_SB(&data, &offset_bit, nbit);
    Ymin=read_SB(&data, &offset_bit, nbit);
    Ymax=read_SB(&data, &offset_bit, nbit);
    if(Xmin!=0 || Ymin!=0 || Xmax<=0 || Ymax<=0)
      return 0;
  }
#endif
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=extension_swc;
  file_recovery_new->calculated_file_size=le32(hdr->size);
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size_max;
  return 1;
}

/*@
  @ requires buffer_size >= sizeof(struct swf_header);
  @ requires separation: \separated(&file_hint_swf, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ ensures (\result == 1) ==> (file_recovery_new->data_check == &data_check_size);
  @ ensures (\result == 1) ==> (file_recovery_new->file_check == &file_check_size);
  @ ensures (\result == 1) ==> (file_recovery_new->file_rename == \null);
  @ ensures (\result == 1) ==> (file_recovery_new->extension == file_hint_swf.extension);
  @ assigns  *file_recovery_new;
  @*/
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

/*@
  @ requires buffer_size >= sizeof(struct swfz_header);
  @ requires separation: \separated(&file_hint_swf, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ ensures (\result == 1) ==> (file_recovery_new->data_check == &data_check_size);
  @ ensures (\result == 1) ==> (file_recovery_new->file_check == &file_check_size_max);
  @ ensures (\result == 1) ==> (file_recovery_new->file_rename == \null);
  @ ensures (\result == 1) ==> (file_recovery_new->extension == file_hint_swf.extension);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_swfz(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct swfz_header *hdr=(const struct swfz_header *)buffer;
  const unsigned int compressedLen=le32(hdr->compressedLen);
  const unsigned int scriptLen=le32(hdr->scriptLen);
  /* ZWS file compression is permitted in SWF 13 or later only. */
  if(hdr->version < 13 || hdr->version > 50 || scriptLen < 8 || compressedLen < 6)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_swf.extension;
  file_recovery_new->calculated_file_size=(uint64_t)4+4+4+5+compressedLen;
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size_max;
  return 1;
}

/*@
  @ requires valid_register_header_check(file_stat);
  @*/
static void register_header_check_swf(file_stat_t *file_stat)
{
  register_header_check(0, "CWS", 3, &header_check_swfc, file_stat);
  register_header_check(0, "FWS", 3, &header_check_swf, file_stat);
  register_header_check(0, "ZWS", 3, &header_check_swfz, file_stat);
}
#endif

#if defined(MAIN_swf)
#define BLOCKSIZE 65536u
int main(void)
{
  const char fn[] = "recup_dir.1/f0000000.swf";
  unsigned char buffer[BLOCKSIZE];
  file_recovery_t file_recovery_new;
  file_recovery_t file_recovery;
  file_stat_t file_stats;

  /*@ assert \valid(buffer + (0 .. (BLOCKSIZE - 1))); */
#if defined(__FRAMAC__)
  Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif

  reset_file_recovery(&file_recovery);
  /*@ assert file_recovery.file_stat == \null; */
  file_recovery.blocksize=BLOCKSIZE;
  file_recovery_new.blocksize=BLOCKSIZE;
  file_recovery_new.data_check=NULL;
  file_recovery_new.file_stat=NULL;
  file_recovery_new.file_check=NULL;
  file_recovery_new.file_rename=NULL;
  file_recovery_new.calculated_file_size=0;
  file_recovery_new.file_size=0;
  file_recovery_new.location.start=0;

  file_stats.file_hint=&file_hint_swf;
  file_stats.not_recovered=0;
  file_stats.recovered=0;
  register_header_check_swf(&file_stats);
  if(header_check_swf(buffer, BLOCKSIZE, 0u, &file_recovery, &file_recovery_new)!=1 ||
      header_check_swfc(buffer, BLOCKSIZE, 0u, &file_recovery, &file_recovery_new)!=1 ||
      header_check_swfz(buffer, BLOCKSIZE, 0u, &file_recovery, &file_recovery_new)!=1)
    return 0;
  /*@ assert valid_read_string((char *)&fn); */
  memcpy(file_recovery_new.filename, fn, sizeof(fn));
  file_recovery_new.file_stat=&file_stats;
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  /*@ assert file_recovery_new.extension == file_hint_swf.extension || file_recovery_new.extension == extension_swc; */
  /*@ assert file_recovery_new.file_size == 0;	*/
  /*@ assert file_recovery_new.file_check == &file_check_size || file_recovery_new.file_check == &file_check_size_max; */
  /*@ assert file_recovery_new.data_check == &data_check_size; */
  /*@ assert file_recovery_new.file_stat->file_hint!=NULL; */
  {
    unsigned char big_buffer[2*BLOCKSIZE];
    data_check_t res_data_check=DC_CONTINUE;
    memset(big_buffer, 0, BLOCKSIZE);
    memcpy(big_buffer + BLOCKSIZE, buffer, BLOCKSIZE);
    /*@ assert file_recovery_new.data_check == &data_check_size; */
    /*@ assert file_recovery_new.file_size == 0; */;
    /*@ assert file_recovery_new.file_size <= file_recovery_new.calculated_file_size; */;
    res_data_check=data_check_size(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    file_recovery_new.file_size+=BLOCKSIZE;
    if(res_data_check == DC_CONTINUE)
    {
      memcpy(big_buffer, big_buffer + BLOCKSIZE, BLOCKSIZE);
#if defined(__FRAMAC__)
      Frama_C_make_unknown((char *)big_buffer + BLOCKSIZE, BLOCKSIZE);
#endif
      data_check_size(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    }
  }
  {
    file_recovery_t file_recovery_new2;
    file_recovery_new2.blocksize=BLOCKSIZE;
    file_recovery_new2.file_stat=NULL;
    file_recovery_new2.file_check=NULL;
    file_recovery_new2.location.start=BLOCKSIZE;
    file_recovery_new.handle=NULL;	/* In theory should be not null */
#if defined(__FRAMAC__)
    Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif
    /*@ assert valid_read_string((char *)file_recovery_new.filename); */
    header_check_swf(buffer, BLOCKSIZE, 0, &file_recovery_new, &file_recovery_new2);
  }
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  file_recovery_new.handle=fopen(fn, "rb");
  /*@ assert file_recovery_new.file_check == &file_check_size || file_recovery_new.file_check == &file_check_size_max; */
  if(file_recovery_new.handle!=NULL)
  {
    if(file_recovery_new.file_check == &file_check_size)
      file_check_size(&file_recovery_new);
    else
      file_check_size_max(&file_recovery_new);
    fclose(file_recovery_new.handle);
  }
  return 0;
}
#endif
