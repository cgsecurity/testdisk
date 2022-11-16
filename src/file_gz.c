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

#if defined(DISABLED_FOR_FRAMAC)
#undef HAVE_LIBZ
#undef HAVE_ZLIB_H
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "file_gz.h"

#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_gz)
#include "filegen.h"
#include "common.h"

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_gz(file_stat_t *file_stat);
#ifndef SINGLE_FORMAT
extern const file_hint_t file_hint_doc;
#endif

const file_hint_t file_hint_gz= {
  .extension="gz",
  .description="gzip compressed data",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_gz
};

struct gzip_header
{
  uint16_t id;
  uint8_t  compression_method;
  uint8_t  flags;
  uint32_t mtime;
  uint8_t  extra_flags;
  uint8_t  os;
} __attribute__ ((gcc_struct, __packed__));

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

/*@
  @ requires file_recovery->file_rename==&file_rename_gz;
  @ requires valid_file_rename_param(file_recovery);
  @ ensures  valid_file_rename_result(file_recovery);
  @*/
static void file_rename_gz(file_recovery_t *file_recovery)
{
  unsigned char buffer[512];
  FILE *file;
  int buffer_size;
  if((file=fopen(file_recovery->filename, "rb"))==NULL)
    return;
  buffer_size=fread(buffer, 1, sizeof(buffer), file);
  fclose(file);
  if(buffer_size<10)
    return;
  /*@ assert \initialized(buffer+(0..10)); */
  if(!(buffer[0]==0x1F && buffer[1]==0x8B && buffer[2]==0x08 && (buffer[3]&0xe0)==0))
    return ;
  {
    const unsigned int flags=buffer[3];
    int off=10;
    if((flags&GZ_FEXTRA)!=0)
    {
      if(buffer_size<12)
	return;
      /*@ assert \initialized(buffer + (0 .. 12)); */
      off+=2;
      off+=buffer[10]|(buffer[11]<<8);
    }
    if((flags&GZ_FNAME)!=0)
    {
      file_rename(file_recovery, buffer, buffer_size, off, NULL, 1);
    }
  }
}

#if defined(HAVE_ZLIB_H) && defined(HAVE_LIBZ)
/*@ assigns \nothing; */
static void file_check_bgzf(file_recovery_t *file_recovery)
{
}

/*@
  @ requires buffer_size >= sizeof(struct gzip_header);
  @ requires \valid_read(buffer+(0..buffer_size-1));
  @ requires \valid_read(buffer_uncompr + (0 .. 4-1));
  @ requires \valid(file_recovery_new);
  @ requires separation: \separated(buffer+(..), file_recovery_new);
  @ requires valid_file_recovery(file_recovery_new);
  @ ensures  \result == 1;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_bgzf(const unsigned char *buffer, const unsigned char *buffer_uncompr, const unsigned int buffer_size, file_recovery_t *file_recovery_new)
{
  const struct gzip_header *gz=(const struct gzip_header *)buffer;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->min_filesize=22;
  file_recovery_new->time=le32(gz->mtime);
  file_recovery_new->file_rename=&file_rename_gz;
  file_recovery_new->file_check=&file_check_bgzf;
  if(memcmp(buffer_uncompr, "BAI\1", 4)==0)
  {
    /* https://github.com/samtools/hts-specs SAM/BAM and related high-throughput sequencing file formats */
    file_recovery_new->extension="bai";
    /*@ assert valid_file_recovery(file_recovery_new); */
    return 1;
  }
  if(memcmp(buffer_uncompr, "BAM\1", 4)==0)
  {
    /* https://github.com/samtools/hts-specs SAM/BAM and related high-throughput sequencing file formats */
    file_recovery_new->extension="bam";
    /*@ assert valid_file_recovery(file_recovery_new); */
    return 1;
  }
  if(memcmp(buffer_uncompr, "CSI\1", 4)==0)
  {
    /* https://github.com/samtools/hts-specs SAM/BAM and related high-throughput sequencing file formats */
    file_recovery_new->extension="csi";
    /*@ assert valid_file_recovery(file_recovery_new); */
    return 1;
  }
  file_recovery_new->extension="bgz";
  /*@ assert valid_file_recovery(file_recovery_new); */
  return 1;
}
#endif

/*@
  @ requires buffer_size >= 16;
  @ requires separation: \separated(&file_hint_gz, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @*/
static int header_check_gz(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  unsigned int off=10;
  const unsigned int flags=buffer[3];
  const struct gzip_header *gz=(const struct gzip_header *)buffer;
  int bgzf=0;
  /* gzip file format:
   * a 10-byte header, containing a magic number, a version number and a timestamp
   * optional extra headers, such as the original file name,
   * a body, containing a deflate-compressed payload
   * a CRC-32 checksum
   * the length (32 bits) of the original uncompressed data
   */
  /* gzip, deflate */
  if(!(buffer[0]==0x1F && buffer[1]==0x8B && buffer[2]==0x08 && (buffer[3]&0xe0)==0))
    return 0;

  /*
   * 4,5,6,7: mtime
   * 8: xfl/extra flags
   * 9: OS	3 - Unix, 7 - Macintosh, 11 - NTFS filesystem (NT)
   */
  if((flags&GZ_FEXTRA)!=0)
  {
    off+=2;
    off+=buffer[10]|(buffer[11]<<8);
    if(buffer[12]=='B' && buffer[13]=='C' && buffer[14]==2 && buffer[15]==0)
      bgzf=1;
  }
  if((flags&GZ_FNAME)!=0)
  {
    for(; off<buffer_size && buffer[off]!='\0'; off++)
    {
    }
    off++;
  }
  if((flags&GZ_FCOMMENT)!=0)
  {
    for(; off<buffer_size && buffer[off]!='\0'; off++)
    {
    }
    off++;
  }
  if((flags&GZ_FHCRC)!=0)
  {
    off+=2;
  }
  if(off >= 512 || off >= buffer_size)
    return 0;
  /*@ assert off < 512; */
  /*@ assert off < buffer_size ; */
#if defined(HAVE_ZLIB_H) && defined(HAVE_LIBZ)
  {
    static const unsigned char schematic_header[12]={ 0x0a, 0x00, 0x09,
      'S', 'c', 'h', 'e', 'm', 'a', 't', 'i', 'c'};
    static const unsigned char tar_header_posix[8]  = { 'u','s','t','a','r',' ',' ',0x00};
    const unsigned char *buffer_compr=buffer+off;
    unsigned char buffer_uncompr[4096];
    const unsigned int uncomprLen=sizeof(buffer_uncompr)-1;
    const unsigned int bs=td_max(512U,file_recovery_new->blocksize);
    /*@ assert bs >=512; */
    const unsigned int comprLen=td_min(buffer_size,bs)-off;
    /*@ assert comprLen > 0; */
    int err;
    z_stream d_stream; /* decompression stream */
    d_stream.zalloc = (alloc_func)0;
    d_stream.zfree = (free_func)0;
    d_stream.opaque = (voidpf)0;

    d_stream.next_in  = (Bytef*)buffer_compr;
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
      {
	/* Decompression has failed, free ressources */
	inflateEnd(&d_stream);
	return 0;
      }
    }
    err = inflateEnd(&d_stream);
    if(err!=Z_OK)
      return 0;
    /* Probably too small to be a file */
    if(d_stream.total_out < 16)
      return 0;
#ifndef SINGLE_FORMAT
    if(file_recovery->file_stat!=NULL &&
	file_recovery->file_stat->file_hint==&file_hint_doc)
    {
      if(header_ignored_adv(file_recovery, file_recovery_new)==0)
	return 0;
    }
#endif
    if(file_recovery->file_check==&file_check_bgzf)
    {
      /*@ assert \valid_function(file_recovery->file_check); */
      header_ignored(file_recovery_new);
      return 0;
    }
    buffer_uncompr[d_stream.total_out]='\0';
    if(bgzf!=0)
    {
      return header_check_bgzf(buffer, buffer_uncompr, d_stream.total_out, file_recovery_new);
    }
    reset_file_recovery(file_recovery_new);
    file_recovery_new->min_filesize=22;
    file_recovery_new->time=le32(gz->mtime);
    file_recovery_new->file_rename=&file_rename_gz;
    if(d_stream.avail_in==0 && d_stream.total_in < comprLen && d_stream.total_out < uncomprLen)
    {
      /* an 8-byte footer, containing a CRC-32 checksum and
       * the length of the original uncompressed data, modulo 2^32
       */
      file_recovery_new->calculated_file_size=off+d_stream.total_in+8;
      file_recovery_new->data_check=&data_check_size;
      file_recovery_new->file_check=&file_check_size;
    }
    if(memcmp(buffer_uncompr, "PVP ", 4)==0)
    {
      /* php Video Pro */
      file_recovery_new->extension="pvp";
      return 1;
    }
    if(memcmp(buffer_uncompr, "<?xml version=\"1.0\" standalone=\"no\"?>\n<xournal", 46)==0)
    {
      /* Xournal, http://xournal.sourceforge.net/ */
      file_recovery_new->extension="xoj";
      return 1;
    }
    if( memcmp(buffer_uncompr, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n<Ableton", 0x30)==0 ||
	memcmp(buffer_uncompr, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Ableton", 0x2f)==0)
    {
      /* Ableton Liveset */
      file_recovery_new->extension="als";
      return 1;
    }
    if(memcmp(buffer_uncompr, "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n<PremiereData", 0x34)==0)
    {
      /* Adobe Premiere */
      file_recovery_new->extension="prproj";
      return 1;
    }
    if(memcmp(buffer_uncompr, "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n<gnc-v2", 47)==0)
    {
      /* GnuCash, http://gnucash.org/ */
      file_recovery_new->extension="gnucash";
      return 1;
    }
    if(strstr((const char*)&buffer_uncompr, "<!DOCTYPE KMYMONEY-FILE>")!=NULL)
    {
      file_recovery_new->extension="kmy";
      return 1;
    }
#ifndef DJGPP
    if(memcmp(buffer_uncompr, "RDX2", 4)==0)
    {
      /* R - language and environment for statistical computing and graphics */
      file_recovery_new->extension="RData";
      return 1;
    }
    if(memcmp(buffer_uncompr, "<?xml version=", 14) == 0)
    {
      file_recovery_new->extension="xml.gz";
      return 1;
    }
    if(memcmp(buffer_uncompr, schematic_header, sizeof(schematic_header))==0)
    {
      /* Minecraft Schematic File */
      file_recovery_new->extension="schematic";
      return 1;
    }
    {
      unsigned int i;
      for(i=0; i<d_stream.total_out && i< 256; i++)
      {
	if(buffer_uncompr[i]=='<')
	{
	  if(strncasecmp((const char*)&buffer_uncompr[i], "<html", 5)==0)
	  {
	    file_recovery_new->extension="html.gz";
	    return 1;
	  }
	}
      }
    }
#endif
    if(d_stream.total_out>0x110 &&
	memcmp(&buffer_uncompr[0x101],tar_header_posix,sizeof(tar_header_posix))==0)
    {
#ifdef DJGPP
      file_recovery_new->extension="tgz";
#else
      file_recovery_new->extension="tar.gz";
#endif
      return 1;
    }
  }
#else
#ifndef SINGLE_FORMAT
  if(file_recovery->file_stat!=NULL &&
      file_recovery->file_stat->file_hint==&file_hint_doc)
  {
    if(header_ignored_adv(file_recovery, file_recovery_new)==0)
      return 0;
  }
#endif
  reset_file_recovery(file_recovery_new);
  file_recovery_new->min_filesize=22;
  file_recovery_new->time=le32(gz->mtime);
  file_recovery_new->file_rename=&file_rename_gz;
#endif
  file_recovery_new->extension=file_hint_gz.extension;
  return 1;
}

static void register_header_check_gz(file_stat_t *file_stat)
{
  static const unsigned char gz_header_magic[3]= {0x1F, 0x8B, 0x08};
  register_header_check(0, gz_header_magic,sizeof(gz_header_magic), &header_check_gz, file_stat);
}
#endif

const char*td_zlib_version(void)
{
#if defined(HAVE_ZLIB_H) && defined(HAVE_LIBZ)
  return ZLIB_VERSION;
#else
  return "none";
#endif
}
