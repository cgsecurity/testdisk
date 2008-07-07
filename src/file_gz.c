/*

    File: file_gz.c

    Copyright (C) 2006-2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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

static void register_header_check_gz(file_stat_t *file_stat);
static int header_check_gz(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_gz= {
  .extension="gz",
  .description="gzip compressed data",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_gz
};

static const unsigned char gz_header_magic[3]= {0x1F, 0x8B, 0x08};

static void register_header_check_gz(file_stat_t *file_stat)
{
  register_header_check(0, gz_header_magic,sizeof(gz_header_magic), &header_check_gz, file_stat);
}

static int header_check_gz(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /* gzip file format:
   * a 10-byte header, containing a magic number, a version number and a timestamp
   * optional extra headers, such as the original file name,
   * a body, containing a deflate-compressed payload
   * a CRC-32 checksum
   * the length (32 bits) of the original uncompressed data
   */
  /* gzip, deflate */
  if(buffer[0]==0x1F && buffer[1]==0x8B && buffer[2]==0x08 && (buffer[3]&0xe0)==0)
  {
    unsigned int off=10;
    const unsigned int flags=buffer[3];
    int err;
    /* flags:
    bit 0   FTEXT
    bit 1   FHCRC
    bit 2   FEXTRA
    bit 3   FNAME
    bit 4   FCOMMENT
    bit 5   reserved
    bit 6   reserved
    bit 7   reserved
    */
#define GZ_FTEXT 	1
#define GZ_FHCRC	2
#define GZ_FEXTRA	4
#define GZ_FNAME	8
#define GZ_FCOMMENT     0x10
    /*
       4,5,6,7: mtime
       8: xfl/extra flags
       9: OS	3 - Unix, 7 - Macintosh, 11 - NTFS filesystem (NT)
    */
    if((flags&GZ_FEXTRA)!=0)
    {
      off+=2;
      off=+buffer[10]|(buffer[11]<<8);
    }
    if((flags&GZ_FNAME)!=0)
    {
      while(buffer[off++]!='\0');
    }
    if((flags&GZ_FCOMMENT)!=0)
    {
      while(buffer[off++]!='\0');
    }
    if((flags&GZ_FHCRC)!=0)
    {
      off+=2;
    }
#if defined(HAVE_ZLIB_H) && defined(HAVE_LIBZ)
    if(buffer_size>off && 512>off)
    {
      const unsigned char *buffer_compr=buffer+off;
      unsigned char buffer_uncompr[512];
      const unsigned int comprLen=(buffer_size<512?buffer_size:512)-off;
      unsigned int uncomprLen=512-1;
      z_stream d_stream; /* decompression stream */
      d_stream.zalloc = (alloc_func)0;
      d_stream.zfree = (free_func)0;
      d_stream.opaque = (voidpf)0;

      d_stream.next_in  = buffer_compr;
      d_stream.avail_in = 0;
      d_stream.next_out = buffer_uncompr;

      err = inflateInit2(&d_stream, -MAX_WBITS);
      if(err!=Z_OK)
	return 0;
      while (d_stream.total_out < uncomprLen && d_stream.total_in < comprLen) {
	d_stream.avail_in = d_stream.avail_out = 1; /* force small buffers */
	err = inflate(&d_stream, Z_NO_FLUSH);
	if (err == Z_STREAM_END) break;
	if(err!=Z_OK)
	  return 0;
      }
      err = inflateEnd(&d_stream);
      if(err!=Z_OK)
	return 0;
      buffer_uncompr[d_stream.total_out]='\0';
      if(strstr((const char*)&buffer_uncompr, "<!DOCTYPE KMYMONEY-FILE>")!=NULL)
      {
	reset_file_recovery(file_recovery_new);
	file_recovery_new->min_filesize=22;
	file_recovery_new->time=buffer[4]|(buffer[5]<<8)|(buffer[6]<<16)|(buffer[7]<<24);
	file_recovery_new->extension=file_hint_gz.extension;
	file_recovery_new->extension="kmy";
	return 1;
      }
    }
#endif
    reset_file_recovery(file_recovery_new);
    file_recovery_new->min_filesize=22;
    file_recovery_new->time=buffer[4]|(buffer[5]<<8)|(buffer[6]<<16)|(buffer[7]<<24);
    file_recovery_new->extension=file_hint_gz.extension;
    return 1;
  }
  return 0;
}
