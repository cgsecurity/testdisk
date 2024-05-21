/*

    File: file_zip.c

    Copyright (C) 1998-2009 Christophe GRENIER <grenier@cgsecurity.org>
    Copyright (C) 2007      Christophe GISQUET <christophe.gisquet@free.fr>

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

    Information about ZIP file format: http://www.info-zip.org/doc/appnote-iz-latest.zip
 */

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_zip)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <stdio.h>
#include "types.h"
#include "filegen.h"
#include "common.h"
#include "log.h"
#if defined(__FRAMAC__)
#include "__fc_builtin.h"
#endif

/* #define DEBUG_ZIP */

#if !defined(SINGLE_FORMAT_zip)
extern const file_hint_t file_hint_doc;
#endif
static void register_header_check_zip(file_stat_t *file_stat);
static unsigned int pos_in_mem(const unsigned char *haystack, const unsigned int haystack_size, const unsigned char *needle, const unsigned int needle_size);
static char first_filename[256];
static uint64_t expected_compressed_size=0;
static int msoffice=0;
static int sh3d=0;
static const char *ext_msoffice=NULL;

const file_hint_t file_hint_zip= {
  .extension="zip",
  .description="zip archive including OpenOffice and MSOffice 2007",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_zip
};

static const char *extension_apk="apk";
static const char *extension_bbdoc="bbdoc";
static const char *extension_celtx="celtx";
static const char *extension_docx="docx";
static const char *extension_epub="epub";
static const char *extension_fcstd="FCStd";
static const char *extension_jar="jar";
static const char *extension_kmz="kmz";
static const char *extension_kra="kra";
static const char *extension_indd="indd";
static const char *extension_mctx="mctx";
static const char *extension_mmap="mmap";
static const char *extension_notebook="notebook";
static const char *extension_numbers="numbers";
static const char *extension_odg="odg";
static const char *extension_odp="odp";
static const char *extension_ods="ods";
static const char *extension_odt="odt";
static const char *extension_ora="ora";
static const char *extension_pages="pages";
static const char *extension_pptx="pptx";
static const char *extension_sh3d="sh3d";
static const char *extension_sketch="sketch";
static const char *extension_sxc="sxc";
static const char *extension_sxd="sxd";
static const char *extension_sxi="sxi";
static const char *extension_sxw="sxw";
static const char *extension_vsdx="vsdx";
static const char *extension_xd="xd";
static const char *extension_xlsx="xlsx";
static const char *extension_xpi="xpi";
static const char *extension_xrns="xrns";

static const unsigned char zip_header[4]  = { 'P', 'K', 0x03, 0x04};
#define ZIP_CENTRAL_DIR         0x02014B50
#define ZIP_FILE_ENTRY          0x04034B50
#define ZIP_SIGNATURE           0x05054B50
#define ZIP_END_CENTRAL_DIR     0x06054B50
#define ZIP_CENTRAL_DIR64       0x06064B50
#define ZIP_END_CENTRAL_DIR64   0x07064B50
#define ZIP_DATA_DESCRIPTOR     0x08074B50

struct zip_file_entry {
  uint16_t version;                 /** Version needed to extract */

  uint16_t is_encrypted:1;          /** File is encrypted? */
  uint16_t compression_info:2;      /** Info about compression method used */
  uint16_t has_descriptor:1;        /** Compressed data followed by descriptor? */
  uint16_t enhanced_deflate:1;      /** Reserved for use with method 8 */
  uint16_t is_patched:1;            /** File is compressed with patched data? */
  uint16_t strong_encrypt:1;        /** Strong encryption (version >= 50) */
  uint16_t unused2:4;               /** Unused */
  uint16_t uses_unicode:1;          /** Filename and comments are in UTF-8 */
  uint16_t unused3:1;               /** Reserved by PKWARE for enhanced compression. */
  uint16_t encrypted_central_dir:1; /** Selected data values in the Local Header are masked */
  uint16_t unused1:2;               /** Unused */

  uint16_t compression;             /** Compression method */
  uint16_t last_mod_time;           /** Last modification file time */
  uint16_t last_mod_date;           /** Last modification file date */
  uint32_t crc32;                   /** CRC32 */
  uint32_t compressed_size;         /** Compressed size */
  uint32_t uncompressed_size;       /** Uncompressed size */
  uint16_t filename_length;         /** Filename length */
  uint16_t extra_length;            /** Extra fields length */
} __attribute__ ((gcc_struct, __packed__));

struct zip64_extra_entry
{
  uint16_t tag;
  uint16_t size;
  uint64_t uncompressed_size;
  uint64_t compressed_size;
  uint64_t offset;		/* Offset of local header record */
  uint32_t disk_start_number;	/* Number of the disk on which this file starts  */
} __attribute__ ((gcc_struct, __packed__));

struct zip_desc
{
  uint32_t crc32;                  /** Checksum (CRC32) */
  uint32_t compressed_size;        /** Compressed size (bytes) */
  uint32_t uncompressed_size;      /** Uncompressed size (bytes) */
} __attribute__ ((gcc_struct, __packed__));

struct zip64_loc
{
  uint32_t disk_number;       /** Number of the disk with the start of the zip64 end of central directory */
  uint64_t relative_offset;   /** Relative offset of the zip64 end of central directory record */
  uint32_t disk_total_number; /** Total number of disks */
} __attribute__ ((gcc_struct, __packed__));

struct zip_end_central_dir
{
  uint16_t number_disk;             /** Number of this disk */
  uint16_t number_disk2;            /** Number in the central dir */
  uint16_t total_number_disk;       /** Total number of entries in this disk */
  uint16_t total_number_disk2;      /** Total number of entries in the central dir */
  uint32_t size;                    /** Size of the central directory */
  uint32_t offset;                  /** Offset of start of central directory */
  uint16_t comment_length;          /** Comment length */
} __attribute__ ((gcc_struct, __packed__));

struct zip_central_dir
{
  /* Fields common with zip_file_entry removed */
  uint16_t comment_length;          /** Comment length */
  uint16_t disk_number_start;       /** Disk number start */
  uint16_t internal_attr;           /** Internal file attributes */
  uint32_t external_attr;           /** External file attributes */
  uint32_t offset_header;           /** Relative offset of local header */
} __attribute__ ((gcc_struct, __packed__));

struct zip64_end_central_dir
{
  uint64_t end_size;                /** Size of zip64 end of central directory record */
  uint16_t version_made;            /** Version made by */
  uint16_t version_needed;          /** Version needed to extract */
  uint32_t number_disk;             /** Number of this disk */
  uint32_t number_disk2;            /** Number of the disk with the start of the central directory */
  uint64_t number_entries;          /** Total number of entries in the central directory on this disk */
  uint64_t number_entries2;         /** Total number of entries in the central directory */
  uint64_t size;                    /** Size of the central directory */
  uint64_t offset;                  /** Offset of start of central directory */
} __attribute__ ((gcc_struct, __packed__));

typedef struct zip_file_entry zip_file_entry_t;
typedef struct zip64_extra_entry zip64_extra_entry_t;

/*@
  @ requires \valid(f);
  @ requires 0 < size <= 4096;
  @ requires \valid_read((const char *)needle + (0 .. size-1));
  @ requires \separated(f, (const char *)needle+(..), &errno, &Frama_C_entropy_source);
  @ assigns *f,errno;
  @ assigns Frama_C_entropy_source;
  @*/
static int64_t file_get_pos(FILE *f, const void* needle, const unsigned int size)
{
  char     buffer[4096];
  int64_t  total   = 0;
#ifdef DEBUG_ZIP
  log_trace("zip: file_get_pos(f, needle, %u)\n", size);
#endif

  /*@
    @ loop assigns total, *f, errno, buffer[0..4096-1];
    @ loop assigns Frama_C_entropy_source;
    @*/
  while (!feof(f))
  {
    const size_t read_size=fread(&buffer, 1, 4096, f);
    if(read_size <= 0 || total > (0x7fffffffffffffff - 4096))
    {
      return -1;
    }
    /*@ assert 0 < read_size <= 4096; */
    /*@ assert total <= 0x8000000000000000 - 4096; */
#if defined(__FRAMAC__)
    Frama_C_make_unknown(&buffer, 4096);
#endif
    if(read_size >= size)
    {
      /*@ assert read_size >= size; */
      const unsigned int count_max=read_size - size;
      unsigned int count = 0;
      // TODO loop invariant 0 <= count <= count_max + 1;
      /*@
	@ loop assigns count, *f, errno;
	@ loop variant count_max - count;
	@*/
      for(count=0; count <= count_max; count++)
      {
	/*@ assert count <= count_max; */
	if (buffer[count]==*(const char *)needle && memcmp(buffer+count, needle, size)==0)
	{
	  if(my_fseek(f, (off_t)count-(off_t)read_size, SEEK_CUR)<0)
	  {
#if !defined(DISABLED_FOR_FRAMAC)
	    log_trace("zip: file_get_pos count-read failed\n");
#endif
	    return -1;
	  }
	  return total+count;
	}
      }
      total+=count_max+1;
    }
    if(feof(f) || my_fseek(f, (off_t)1-size, SEEK_CUR)<0)
    {
#if !defined(DISABLED_FOR_FRAMAC)
      log_trace("zip: file_get_pos 1-size failed\n");
#endif
      return -1;
    }
  }
  return -1;
}

/*@
  @ requires \valid_read(mime + (0 .. 127));
  @ requires \initialized(mime + (0 .. 127));
  @ ensures  \result==extension_epub ||
	\result==extension_indd ||
	\result==extension_kra ||
	\result==extension_odg ||
	\result==extension_odp ||
	\result==extension_ods ||
	\result==extension_odt ||
	\result==extension_ora ||
	\result==extension_sxc ||
	\result==extension_sxd ||
	\result==extension_sxi ||
	\result==extension_sxw ||
	\result==extension_xd;
  @ assigns \nothing;
  @*/
static const char *zip_parse_parse_entry_mimetype(const char *mime, const unsigned int len)
{
  if(len==16      && memcmp(mime,"image/openraster",16)==0)
    return extension_ora;
  else if((len==20 || len==22) && memcmp(mime,"application/epub+zip",20)==0)
    return extension_epub;
  else if(len==28 && memcmp(mime,"application/vnd.sun.xml.calc",28)==0)
    return extension_sxc;
  else if(len==28 && memcmp(mime,"application/vnd.sun.xml.draw",28)==0)
    return extension_sxd;
  else if(len==30 && memcmp(mime,"application/vnd.sun.xml.writer",30)==0)
    return extension_sxw;
  else if(len==31 && memcmp(mime,"application/vnd.sun.xml.impress",31)==0)
    return extension_sxi;
  else if(len==39 && memcmp(mime,"application/vnd.oasis.opendocument.text",39)==0)
    return extension_odt;
  else if(len==43 && memcmp(mime,"application/vnd.adobe.indesign-idml-package",43)==0)
    return extension_indd;
  else if(len==43 && memcmp(mime,"application/vnd.oasis.opendocument.graphics",43)==0)
    return extension_odg;
  else if(len==45 && memcmp(mime,"application/vnd.adobe.sparkler.project+dcxucf",45)==0)
    return extension_xd;
  else if(len==46 && memcmp(mime,"application/vnd.oasis.opendocument.spreadsheet",46)==0)
    return extension_ods;
  else if(len==47 && memcmp(mime,"application/vnd.oasis.opendocument.presentation",47)==0)
    return extension_odp;
  else if(len>=19 && memcmp(mime,"application/x-krita",19)==0)
    return extension_kra;
  /* default to writer */
  return extension_sxw;
}

/*@
  @ requires \valid(fr);
  @ requires \valid(fr->handle);
  @ requires \valid(ext);
  @ requires fr->file_size < 0x8000000000000000 - 65535;
  @ requires \valid_read(file);
  @ requires 0 < len <= 65535;
  @ requires \separated(fr, fr->handle, ext, file, &first_filename[0 .. 256], &errno, &Frama_C_entropy_source);
  @ requires *ext == \null ||
     *ext == extension_apk ||
     *ext == extension_bbdoc ||
     *ext == extension_celtx ||
     *ext == extension_docx ||
     *ext == extension_epub ||
     *ext == extension_fcstd ||
     *ext == extension_indd ||
     *ext == extension_jar ||
     *ext == extension_kmz ||
     *ext == extension_kra ||
     *ext == extension_mctx ||
     *ext == extension_mmap ||
     *ext == extension_notebook ||
     *ext == extension_numbers ||
     *ext == extension_odg  ||
     *ext == extension_odp ||
     *ext == extension_ods ||
     *ext == extension_odt ||
     *ext == extension_ora ||
     *ext == extension_pages ||
     *ext == extension_pptx ||
     *ext == extension_sh3d ||
     *ext == extension_sketch ||
     *ext == extension_sxc ||
     *ext == extension_sxd ||
     *ext == extension_sxi ||
     *ext == extension_sxw ||
     *ext == extension_vsdx ||
     *ext == extension_xd ||
     *ext == extension_xlsx ||
     *ext == extension_xpi ||
     *ext == extension_xrns ||
     *ext == file_hint_zip.extension;
  @ ensures *ext == \null ||
     *ext == extension_apk ||
     *ext == extension_bbdoc ||
     *ext == extension_celtx ||
     *ext == extension_docx ||
     *ext == extension_epub ||
     *ext == extension_fcstd ||
     *ext == extension_indd ||
     *ext == extension_jar ||
     *ext == extension_kmz ||
     *ext == extension_kra ||
     *ext == extension_mctx ||
     *ext == extension_mmap ||
     *ext == extension_notebook ||
     *ext == extension_numbers ||
     *ext == extension_odg  ||
     *ext == extension_odp ||
     *ext == extension_ods ||
     *ext == extension_odt ||
     *ext == extension_ora ||
     *ext == extension_pages ||
     *ext == extension_pptx ||
     *ext == extension_sh3d ||
     *ext == extension_sketch ||
     *ext == extension_sxc ||
     *ext == extension_sxd ||
     *ext == extension_sxi ||
     *ext == extension_sxw ||
     *ext == extension_vsdx ||
     *ext == extension_xd ||
     *ext == extension_xlsx ||
     *ext == extension_xpi ||
     *ext == extension_xrns ||
     *ext == file_hint_zip.extension;
  @ ensures fr->file_size < 0x8000000000000000;
  @ ensures \result == -1 || \result == 0;
  @ ensures \result == 0 ==> (fr->file_size > \old(fr->file_size));
  @ assigns *fr->handle, fr->file_size, *ext;
  @ assigns Frama_C_entropy_source, errno;
  @ assigns first_filename[0 .. 255];
  @ assigns msoffice, sh3d, ext_msoffice;
  @*/
static int zip_parse_file_entry_fn(file_recovery_t *fr, const char **ext, const unsigned int file_nbr, const zip_file_entry_t *file, const uint64_t len)
{
  char filename[65535+1];
  if (fread(filename, len, 1, fr->handle) != 1)
  {
#ifdef DEBUG_ZIP
    log_trace("zip: Unexpected EOF in file_entry header: %lu bytes expected\n", len);
#endif
    return -1;
  }
#if defined(__FRAMAC__)
  Frama_C_make_unknown(filename, 65535+1);
#endif
  fr->file_size += len;
  /*@ assert fr->file_size < 0x8000000000000000; */
  filename[len]='\0';
  if(first_filename[0]=='\0')
  {
    const unsigned int len_tmp=(len<255?len:255);
    /*@ assert 0 <= len_tmp <= 255; */
    strncpy(first_filename, filename, len_tmp);
    first_filename[len_tmp]='\0';
  }
#ifdef DEBUG_ZIP
  log_info("%s (len=%lu)\n", filename, len);
#endif
  if(*ext!=NULL)
    return 0;
  if(file_nbr==0)
  {
    msoffice=0;
    sh3d=0;
    ext_msoffice=NULL;
  }
  if(len==19 && memcmp(filename, "[Content_Types].xml", 19)==0)
    msoffice=1;
  else if(file_nbr==0)
  {
    if(len==8 && memcmp(filename, "mimetype", 8)==0)
    {
      char buffer[128];
      /*@ assert \valid_read(file); */
      const unsigned int compressed_size=le32(file->compressed_size);
      const int to_read=(compressed_size < 128 ? compressed_size: 128);
      const int extra_length=le16(file->extra_length);
      if (my_fseek(fr->handle, extra_length, SEEK_CUR) < 0)
      {
#ifdef DEBUG_ZIP
	log_info("fseek failed\n");
#endif
	return -1;
      }
      if( fread(buffer, to_read, 1, fr->handle)!=1)
      {
#ifdef DEBUG_ZIP
	log_trace("zip: Unexpected EOF in file_entry data: %u bytes expected\n",
	    compressed_size);
#endif
	return -1;
      }
#if defined(__FRAMAC__)
      Frama_C_make_unknown(buffer, 128);
#endif
      if (my_fseek(fr->handle, -(to_read+extra_length), SEEK_CUR) < 0)
      {
#ifdef DEBUG_ZIP
	log_info("fseek failed\n");
#endif
	return -1;
      }
      *ext=zip_parse_parse_entry_mimetype((const char *)&buffer, compressed_size);
    }
    /* Zipped Keyhole Markup Language (KML) used by Google Earth */
    else if(len==7 && memcmp(filename, "doc.kml", 7)==0)
      *ext=extension_kmz;
    else if(len==4 && memcmp(filename, "Home", 4)==0)
      sh3d=1;
    /* Celtx, Screenwriting & Media Pre-production file */
    else if(len==9 && memcmp(filename, "local.rdf", 9)==0)
      *ext=extension_celtx;
    else if(len==12 && memcmp(filename, "Document.xml", 12)==0)
      *ext=extension_fcstd;
    else if(len==13 && memcmp(filename, "document.json", 13)==0)
      *ext=extension_sketch;
    else if(len > 16 && memcmp(filename,  "atlases/atlas_ID", 16)==0)
      *ext=extension_bbdoc;
  }
  else if(file_nbr==1 && sh3d==1)
  {
    if(len==1 && filename[0]=='0')
      *ext=extension_sh3d;
  }
  if(strncmp(filename, "word/", 5)==0)
    ext_msoffice=extension_docx;
  else if(strncmp(filename, "xl/", 3)==0)
    ext_msoffice=extension_xlsx;
  else if(strncmp(filename, "ppt/", 4)==0)
    ext_msoffice=extension_pptx;
  else if(strncmp(filename, "visio/", 6)==0)
    ext_msoffice=extension_vsdx;
  if(msoffice && ext_msoffice!=NULL)
    *ext=ext_msoffice;
  if(*ext!=NULL)
    return 0;
  /* iWork */
  if(len==23 && memcmp(filename, "QuickLook/Thumbnail.jpg", 23)==0)
    *ext=extension_pages;
  else if(len==20 && strncasecmp(filename, "META-INF/MANIFEST.MF", 20)==0)
    *ext=extension_jar;
  else if(len==15 && strncasecmp(filename, "chrome.manifest", 15)==0)
    *ext=extension_xpi;
  /* SMART Notebook */
  else if(len==15 && memcmp(filename, "imsmanifest.xml", 15)==0)
    *ext=extension_notebook;
  /* Apple Numbers */
  else if(len==18 && memcmp(filename, "Index/Document.iwa", 18)==0)
    *ext=extension_numbers;
  else if(len==19 && memcmp(filename, "AndroidManifest.xml", 19)==0)
    *ext=extension_apk;
  else if(len==21 && memcmp(filename, "mathcad/worksheet.xml", 21)==0)
    *ext=extension_mctx;
  else if(len==30 && memcmp(filename, "xsd/MindManagerApplication.xsd", 30)==0)
    *ext=extension_mmap;
  return 0;
}

/*@
  @ requires \valid(fr);
  @ requires \valid(fr->handle);
  @ requires \valid(ext);
  @ requires fr->file_size < 0x8000000000000000 + 4;
  @ requires \separated(fr, fr->handle, ext, &errno, &Frama_C_entropy_source, first_filename + (..), &msoffice, &sh3d, &ext_msoffice, &expected_compressed_size);
  @ requires *ext == \null ||
     *ext == extension_apk ||
     *ext == extension_bbdoc ||
     *ext == extension_celtx ||
     *ext == extension_docx ||
     *ext == extension_epub ||
     *ext == extension_fcstd ||
     *ext == extension_indd ||
     *ext == extension_jar ||
     *ext == extension_kmz ||
     *ext == extension_kra ||
     *ext == extension_mctx ||
     *ext == extension_mmap ||
     *ext == extension_notebook ||
     *ext == extension_numbers ||
     *ext == extension_odg  ||
     *ext == extension_odp ||
     *ext == extension_ods ||
     *ext == extension_odt ||
     *ext == extension_ora ||
     *ext == extension_pages ||
     *ext == extension_pptx ||
     *ext == extension_sh3d ||
     *ext == extension_sketch ||
     *ext == extension_sxc ||
     *ext == extension_sxd ||
     *ext == extension_sxi ||
     *ext == extension_sxw ||
     *ext == extension_vsdx ||
     *ext == extension_xd ||
     *ext == extension_xlsx ||
     *ext == extension_xpi ||
     *ext == extension_xrns ||
     *ext == file_hint_zip.extension;
  @ ensures *ext == \null ||
     *ext == extension_apk ||
     *ext == extension_bbdoc ||
     *ext == extension_celtx ||
     *ext == extension_docx ||
     *ext == extension_epub ||
     *ext == extension_fcstd ||
     *ext == extension_indd ||
     *ext == extension_jar ||
     *ext == extension_kmz ||
     *ext == extension_kra ||
     *ext == extension_mctx ||
     *ext == extension_mmap ||
     *ext == extension_notebook ||
     *ext == extension_numbers ||
     *ext == extension_odg  ||
     *ext == extension_odp ||
     *ext == extension_ods ||
     *ext == extension_odt ||
     *ext == extension_ora ||
     *ext == extension_pages ||
     *ext == extension_pptx ||
     *ext == extension_sh3d ||
     *ext == extension_sketch ||
     *ext == extension_sxc ||
     *ext == extension_sxd ||
     *ext == extension_sxi ||
     *ext == extension_sxw ||
     *ext == extension_vsdx ||
     *ext == extension_xd ||
     *ext == extension_xlsx ||
     *ext == extension_xpi ||
     *ext == extension_xrns ||
     *ext == file_hint_zip.extension;
  @ ensures \result == -1 || \result == 0;
  @ ensures \result == 0 ==> fr->file_size < 0x8000000000000000;
  @ ensures \result == 0 ==> (fr->file_size > \old(fr->file_size));
  @ assigns *fr->handle, fr->file_size, *ext;
  @ assigns fr->time;
  @ assigns Frama_C_entropy_source, errno;
  @ assigns first_filename[0 .. 255];
  @ assigns msoffice, sh3d, ext_msoffice;
  @ assigns expected_compressed_size;
  @*/
static int zip_parse_file_entry(file_recovery_t *fr, const char **ext, const unsigned int file_nbr)
{
  char b_file[sizeof(zip_file_entry_t)];
  char b_extra[sizeof(zip64_extra_entry_t)];
  const zip_file_entry_t *file=(const zip_file_entry_t *)&b_file;
  const zip64_extra_entry_t *extra=(const zip64_extra_entry_t *)&b_extra;
  /*@ assert \valid_read(file); */
  /*@ assert \valid_read(extra); */
  uint64_t len;
  if (fread(b_file, sizeof(b_file), 1, fr->handle) != 1)
  {
#ifdef DEBUG_ZIP
    log_trace("zip: Unexpected EOF reading header of file_entry\n");
#endif
    return -1;
  }
#if defined(__FRAMAC__)
  Frama_C_make_unknown(&b_file, sizeof(zip_file_entry_t));
#endif
  fr->file_size += sizeof(zip_file_entry_t);
#ifdef DEBUG_ZIP
  log_info("%u Comp=%u %u CRC32=0x%08X extra_length=%u ",
      le32(file->compressed_size),
      le16(file->compression),
      le32(file->uncompressed_size),
      le32(file->crc32),
      le16(file->extra_length));
#endif
  /* Avoid Jan  1  1980 files */
  if(le16(file->last_mod_time)!=0 || le16(file->last_mod_date)!=33)
  {
    /* Use the more recent file to set the time/date of the recovered archive */
    const time_t tmp=date_dos2unix(le16(file->last_mod_time), le16(file->last_mod_date));
    if(fr->time < tmp)
      fr->time=tmp;
  }
  if(fr->file_size + 65535 >= 0x8000000000000000)
  {
    return -1;
  }
  /*@ assert fr->file_size < 0x8000000000000000 - 65535; */
  len = le16(file->filename_length);
  if (len)
  {
    /*@ assert 0 < len <= 65535; */
    if(zip_parse_file_entry_fn(fr, ext, file_nbr, file, len) < 0)
      return -1;
    /*@ assert fr->file_size < 0x8000000000000000; */
  }
  /*@ assert fr->file_size < 0x8000000000000000; */
#ifdef DEBUG_ZIP
  log_info("\n");
#endif
  len = le16(file->extra_length);
  memset(&b_extra, 0, sizeof(zip64_extra_entry_t));
  if (len>0)
  {
    /*@ assert 0 < len <= 65535; */
    if(fr->file_size + 65535 >= 0x8000000000000000)
    {
      return -1;
    }
    /*@ assert fr->file_size < 0x8000000000000000 - 65535; */
    if (fread(&b_extra, sizeof(zip64_extra_entry_t), 1, fr->handle) != 1)
    {
#ifdef DEBUG_ZIP
      log_trace("zip: Unexpected EOF in file_entry header: %lu bytes expected\n", len);
#endif
    }
#if defined(__FRAMAC__)
    Frama_C_make_unknown(&b_extra, sizeof(zip64_extra_entry_t));
#endif
    if (my_fseek(fr->handle, fr->file_size, SEEK_SET) == -1 ||
	my_fseek(fr->handle, len, SEEK_CUR) == -1)
    {
#ifdef DEBUG_ZIP
      log_trace("zip: Unexpected EOF in file_entry header: %lu bytes expected\n", len);
#endif
      return -1;
    }
    fr->file_size += len;
    /*@ assert fr->file_size < 0x8000000000000000; */
  }
  /*@ assert fr->file_size < 0x8000000000000000; */
  len = le32(file->compressed_size);
  if(len==0xffffffff && le16(extra->tag)==1)
  {
    len = le64(extra->compressed_size);
    if(len >= 0x8000000000000000)
      return -1;
    /*@ assert len < 0x8000000000000000; */
    /* Avoid endless loop */
    if( fr->file_size + len < fr->file_size)
      return -1;
  }
  /*@ assert len < 0x8000000000000000; */
  if(*ext == extension_kra && len==0x5a495343 && le32(file->uncompressed_size) == 0x5a495355)
  {
    len=19;
    /*@ assert len==19; */
  }
  if (len>0)
  {
    /*@ assert fr->file_size < 0x8000000000000000; */
    /*@ assert 0 < len < 0x8000000000000000; */
    if(fr->file_size + len >= 0x8000000000000000)
      return -1;
    /*@ assert fr->file_size + len < 0x8000000000000000; */
    if (my_fseek(fr->handle, len, SEEK_CUR) == -1)
    {
#ifdef DEBUG_ZIP
      log_trace("zip: Unexpected EOF in file_entry data: %lu bytes expected\n", len);
#endif
      return -1;
    }
#ifdef DEBUG_ZIP
    log_trace("zip: Data of length %lu\n", len);
#endif
    /*@ assert fr->file_size + len < 0x8000000000000000; */
    fr->file_size += len;
    /*@ assert fr->file_size < 0x8000000000000000; */
  }
  /*@ assert fr->file_size < 0x8000000000000000; */
  expected_compressed_size=len;
  if (file->has_descriptor && (le16(file->compression)==8 || le16(file->compression)==9))
  {
    /* The fields crc-32, compressed size and uncompressed size
       are set to zero in the local header.  The correct values
       are put in the data descriptor immediately following the
       compressed data.
       Typically used in OOO documents
       Search ZIP_DATA_DESCRIPTOR */
    static const unsigned char zip_data_desc_header[4]= {0x50, 0x4B, 0x07, 0x08};
    const int64_t pos = file_get_pos(fr->handle, zip_data_desc_header, 4);
#ifdef DEBUG_ZIP
    log_trace("Searched footer, got length %lli\n", (long long int)pos);
#endif
    if (pos < 0)
      return -1;
    if (pos > 0)
    {
      if(fr->file_size + pos > 0x7fffffffffffffff)
	return -1;
      /*@ assert fr->file_size + pos < 0x8000000000000000; */
      fr->file_size += pos;
      /*@ assert fr->file_size < 0x8000000000000000; */
      expected_compressed_size=pos;
    }
  }
  /*@ assert fr->file_size < 0x8000000000000000; */
  return 0;
}

/*@
  @ requires \valid(fr);
  @ requires \valid(fr->handle);
  @ requires fr->file_size < 0x8000000000000000;
  @ requires \separated(fr, fr->handle, &errno, &Frama_C_entropy_source);
  @ ensures \result == -1 || \result == 0;
  @ ensures \result == 0 ==> (fr->file_size > \old(fr->file_size));
  @ assigns Frama_C_entropy_source, errno;
  @ assigns *fr->handle, fr->file_size;
  @*/
static int zip_parse_central_dir(file_recovery_t *fr)
{
  char buf_file[sizeof(zip_file_entry_t)];
  char buf_dir[sizeof(struct zip_central_dir)];
  const struct zip_central_dir *dir=(const struct zip_central_dir *)&buf_dir;
  /*@ assert \valid_read(dir); */
  const zip_file_entry_t *file=(const zip_file_entry_t *)&buf_file;
  /*@ assert \valid_read(file); */
  uint32_t          len;
  if (my_fseek(fr->handle, 2, SEEK_CUR) == -1)
  {
#ifdef DEBUG_ZIP
    log_trace("Unexpected EOF skipping version from central_dir\n");
#endif
    return -1;
  }
  fr->file_size += 2;

  if (fread(&buf_file, sizeof(zip_file_entry_t), 1, fr->handle) != 1)
  {
#ifdef DEBUG_ZIP
    log_trace("Unexpected EOF reading 1st part of central_dir\n");
#endif
    return -1;
  }
#if defined(__FRAMAC__)
  Frama_C_make_unknown(&buf_file, sizeof(zip_file_entry_t));
#endif
  fr->file_size += sizeof(zip_file_entry_t);
#ifdef DEBUG_ZIP
  log_trace("zip: Central dir with CRC 0x%08X\n", file->crc32);
#endif

  if (fread(&buf_dir, sizeof(struct zip_central_dir), 1, fr->handle) != 1)
  {
#ifdef DEBUG_ZIP
    log_trace("zip: Unexpected EOF reading 2nd part of central_dir\n");
#endif
    return -1;
  }
#if defined(__FRAMAC__)
  Frama_C_make_unknown(&buf_dir, sizeof(struct zip_central_dir));
#endif
  fr->file_size += sizeof(struct zip_central_dir);

  /* Rest of the block - could attempt CRC check */
  len = le16(file->extra_length) + le16(dir->comment_length) + le16(file->filename_length);
  if (my_fseek(fr->handle, len, SEEK_CUR) == -1)
  {
#ifdef DEBUG_ZIP
    log_trace("zip: Unexpected EOF in central_dir: %u bytes expected\n", len);
#endif
    return -1;
  }
  fr->file_size += len;
#ifdef DEBUG_ZIP
  log_trace("zip: Data of total length %u\n", len);
#endif
  return 0;
}

/*@
  @ requires \valid(fr);
  @ requires \valid(fr->handle);
  @ requires \separated(fr, fr->handle, &errno, &Frama_C_entropy_source);
  @ requires fr->file_size < 0x8000000000000000;
  @ ensures  \result == -1 || \result == 0;
  @ ensures \result == 0 ==> (fr->file_size > \old(fr->file_size));
  @ assigns  Frama_C_entropy_source, errno;
  @ assigns  *fr->handle, fr->file_size;
  @*/
static int zip64_parse_end_central_dir(file_recovery_t *fr)
{
  char buffer[sizeof(struct zip64_end_central_dir)];
  const struct zip64_end_central_dir *dir=(const struct zip64_end_central_dir *)&buffer;
  /*@ assert \valid_read(dir); */
  if (fread(&buffer, sizeof(buffer), 1, fr->handle) != 1)
  {
#ifdef DEBUG_ZIP
    log_trace("zip: Unexpected EOF reading end_central_dir_64\n");
#endif
    return -1;
  }
#if defined(__FRAMAC__)
  Frama_C_make_unknown(&buffer, sizeof(buffer));
#endif
  fr->file_size += sizeof(buffer);

  if (dir->end_size > 0)
  {
    const uint64_t len = le64(dir->end_size);
    if(len >= 0x8000000000000000 - sizeof(struct zip64_end_central_dir) - 4)
      return -1;
    /* Avoid endless loop */
    if( fr->file_size + len <= fr->file_size)
      return -1;
    if (my_fseek(fr->handle, len, SEEK_CUR) == -1)
    {
#ifdef DEBUG_ZIP
      log_trace("zip: Unexpected EOF in end_central_dir_64: expected %llu bytes\n", (long long unsigned)len);
#endif
      return -1;
    }
    fr->file_size += len;
#ifdef DEBUG_ZIP
    log_trace("zip: End of 64b central dir of length %llu\n", (long long unsigned)len);
#endif
  }

  return 0;
}

/*@
  @ requires \valid(fr);
  @ requires \valid(fr->handle);
  @ requires fr->file_size < 0x8000000000000000;
  @ requires \separated(fr, fr->handle, &errno, &Frama_C_entropy_source);
  @ ensures  \result == -1 || \result == 0;
  @ ensures \result == 0 ==> (fr->file_size > \old(fr->file_size));
  @ assigns  *fr->handle, fr->file_size, errno, Frama_C_entropy_source;
  @*/
static int zip_parse_end_central_dir(file_recovery_t *fr)
{
  char buffer[sizeof(struct zip_end_central_dir)];
  const struct zip_end_central_dir *dir=(const struct zip_end_central_dir *)&buffer;

  if (fread(&buffer, sizeof(struct zip_end_central_dir), 1, fr->handle) != 1)
  {
#ifdef DEBUG_ZIP
    log_trace("zip: Unexpected EOF reading header of zip_parse_end_central_dir\n");
#endif
    return -1;
  }
#if defined(__FRAMAC__)
  Frama_C_make_unknown(buffer, sizeof(struct zip_end_central_dir));
#endif
  fr->file_size += sizeof(struct zip_end_central_dir);

  if (dir->comment_length)
  {
    const uint16_t len = le16(dir->comment_length);
    if (my_fseek(fr->handle, len, SEEK_CUR) == -1)
    {
#ifdef DEBUG_ZIP
      log_trace("zip: Unexpected EOF in end_central_dir: expected %u bytes\n", len);
#endif
      return -1;
    }
    fr->file_size += len;
#ifdef DEBUG_ZIP
    log_trace("zip: Comment of length %u\n", len);
#endif
  }
  return 0;
}

/*@
  @ requires \valid(fr);
  @ requires \valid(fr->handle);
  @ requires fr->file_size < 0x8000000000000000;
  @ requires \separated(fr, fr->handle, &errno, &Frama_C_entropy_source);
  @ ensures  \result == -1 || \result == 0;
  @ ensures \result == 0 ==> (fr->file_size > \old(fr->file_size));
  @ assigns  *fr->handle, fr->file_size, errno, Frama_C_entropy_source;
  @*/
static int zip_parse_data_desc(file_recovery_t *fr)
{
  char buffer[sizeof(struct zip_desc)];
  const struct zip_desc *desc=(const struct zip_desc *)&buffer;
  if (fread(&buffer, sizeof(buffer), 1, fr->handle) != 1)
  {
#ifdef DEBUG_ZIP
    log_trace("zip: Unexpected EOF reading header of data_desc\n");
#endif
    return -1;
  }
#if defined(__FRAMAC__)
  Frama_C_make_unknown(buffer, sizeof(buffer));
#endif
  fr->file_size += sizeof(struct zip_desc);
#ifdef DEBUG_ZIP
  log_info("compressed_size=%u/%lu uncompressed_size=%u CRC32=0x%08X\n",
      le32(desc->compressed_size),
      expected_compressed_size,
      le32(desc->uncompressed_size),
      le32(desc->crc32));
#endif
  if(le32(desc->compressed_size)!=expected_compressed_size)
    return -1;
  return 0;
}

/*@
  @ requires \valid(fr);
  @ requires \valid(fr->handle);
  @ requires fr->file_size < 0x8000000000000000;
  @ requires \separated(fr, fr->handle, &errno, &Frama_C_entropy_source);
  @ ensures  \result == -1 || \result == 0;
  @ ensures \result == 0 ==> (fr->file_size > \old(fr->file_size));
  @ assigns  *fr->handle, fr->file_size, errno, Frama_C_entropy_source;
  @*/
static int zip_parse_signature(file_recovery_t *fr)
{
  char buffer[sizeof(uint16_t)];
  const uint16_t *len_ptr=(const uint16_t *)&buffer;

  if (fread(&buffer, 2, 1, fr->handle) != 1)
  {
#ifdef DEBUG_ZIP
    log_trace("zip: Unexpected EOF reading length of signature\n");
#endif
    return -1;
  }
#if defined(__FRAMAC__)
  Frama_C_make_unknown(&buffer, 2);
#endif
  fr->file_size += 2;

  if (*len_ptr)
  {
    const uint16_t len = le16(*len_ptr);
    if (my_fseek(fr->handle, len, SEEK_CUR) == -1)
    {
#ifdef DEBUG_ZIP
      log_trace("zip: Unexpected EOF in zip_parse_signature: expected %u bytes\n", len);
#endif
      return -1;
    }
    fr->file_size += len;
  }

  return 0;
}

/*@
  @ requires \valid(fr);
  @ requires \valid(fr->handle);
  @ requires fr->file_size < 0x8000000000000000;
  @ requires \separated(fr, fr->handle, &errno);
  @ ensures \result == -1 || \result == 0;
  @ ensures \result == 0 ==> (fr->file_size > \old(fr->file_size));
  @ assigns  *fr->handle, fr->file_size, errno;
  @*/
static int zip64_parse_end_central_dir_locator(file_recovery_t *fr)
{
  char buffer[sizeof(struct zip64_loc)];
  if (fread(&buffer, sizeof(struct zip64_loc), 1, fr->handle) != 1)
  {
#ifdef DEBUG_ZIP
    log_trace("zip: Unexpected EOF reading 1st part of end_central_dir_locator\n");
#endif
    return -1;
  }
  fr->file_size += sizeof(struct zip64_loc);
  return 0;
}

/*@
  @ requires fr->file_check==&file_check_zip;
  @ requires valid_file_check_param(fr);
  @ ensures  valid_file_check_result(fr);
  @ assigns *fr->handle, fr->file_size;
  @ assigns fr->time, fr->offset_ok, fr->offset_error;
  @ assigns Frama_C_entropy_source, errno;
  @ assigns first_filename[0 .. 255];
  @ assigns msoffice, sh3d, ext_msoffice, expected_compressed_size;
  @*/
static void file_check_zip(file_recovery_t *fr)
{
  const char *ext=NULL;
  unsigned int file_nbr=0;
  fr->file_size = 0;
  fr->offset_error=0;
  fr->offset_ok=0;
  /* fr->time is already set to 0 but it helps frama-c */
  fr->time=0;
  first_filename[0]='\0';
  if(my_fseek(fr->handle, 0, SEEK_SET) < 0)
    return ;
  /*@
    @ loop invariant valid_file_recovery(fr);
    @ loop invariant fr->file_size < 0x8000000000000000 - 4;
    @ loop assigns *fr->handle, fr->file_size, ext, file_nbr;
    @ loop assigns fr->time, fr->offset_ok, fr->offset_error;
    @ loop assigns Frama_C_entropy_source, errno;
    @ loop assigns first_filename[0 .. 255];
    @ loop assigns msoffice, sh3d, ext_msoffice, expected_compressed_size;
    @ loop variant 0x8000000000000000 - fr->file_size;
    @*/
  while (1)
  {
    uint64_t file_size_old;
    char buf_header[sizeof(uint32_t)];
    const uint32_t *header_ptr=(const uint32_t *)&buf_header;
    uint32_t header;
    int      status;
    /*@ assert fr->file_size < 0x8000000000000000 - 4; */
    if (fread(&buf_header, 4, 1, fr->handle)!=1)
    {
#ifdef DEBUG_ZIP
      log_trace("Failed to read block header\n");
#endif
      fr->offset_error=fr->file_size;
      fr->file_size=0;
      return;
    }
#if defined(__FRAMAC__)
    Frama_C_make_unknown(&buf_header, 4);
#endif
    header = le32(*header_ptr);
#ifdef DEBUG_ZIP
    log_trace("Header 0x%08X at 0x%llx\n", header, (long long unsigned int)fr->file_size);
    log_flush();
#endif
    fr->file_size += 4;
    file_size_old=fr->file_size;
    /*@ assert fr->file_size < 0x8000000000000000; */

    switch (header)
    {
      case ZIP_CENTRAL_DIR: /* Central dir */
        status = zip_parse_central_dir(fr);
	/*@ assert (status >= 0) ==> (fr->file_size > file_size_old); */
        break;
      case ZIP_CENTRAL_DIR64: /* 64b end central dir */
        status = zip64_parse_end_central_dir(fr);
	/*@ assert (status >= 0) ==> (fr->file_size > file_size_old); */
        break;
      case ZIP_END_CENTRAL_DIR: /* End central dir */
        status = zip_parse_end_central_dir(fr);
	/*@ assert (status >= 0) ==> (fr->file_size > file_size_old); */
        break;
      case ZIP_END_CENTRAL_DIR64: /* 64b end central dir locator */
        status = zip64_parse_end_central_dir_locator(fr);
	/*@ assert (status >= 0) ==> (fr->file_size > file_size_old); */
        break;
      case ZIP_DATA_DESCRIPTOR: /* Data descriptor */
        status = zip_parse_data_desc(fr);
	/*@ assert (status >= 0) ==> (fr->file_size > file_size_old); */
        break;
      case ZIP_FILE_ENTRY: /* File Entry */
        status = zip_parse_file_entry(fr, &ext, file_nbr);
	/*@ assert (status >= 0) ==> (fr->file_size > file_size_old); */
	file_nbr++;
        break;
      case ZIP_SIGNATURE: /* Signature */
        status = zip_parse_signature(fr);
	/*@ assert (status >= 0) ==> (fr->file_size > file_size_old); */
        break;
      default:
#ifdef DEBUG_ZIP
        if ((header&0xFFFF) != 0x4B50)
          log_trace("Not a zip block: 0x%08X\n", header);
        else
          log_trace("Unparsable block with ID 0x%04X\n", header>>16);
#endif
        status = -1;
        break;
    }
    /*@ assert (status >= 0) ==> (fr->file_size > file_size_old); */

    /* Verify status */
    if (status<0)
    {
      fr->offset_error = fr->file_size;
      fr->file_size = 0;
      return;
    }
    /* Only end of central dir is end of archive, 64b version of it is before */
    if (header==ZIP_END_CENTRAL_DIR)
      return;
    fr->offset_ok=file_size_old;
    if(file_nbr>=0xffffffff || fr->file_size >= 0x8000000000000000 - 4)
    {
      fr->offset_error = fr->file_size;
      fr->file_size = 0;
      return;
    }
    /*@ assert fr->file_size < 0x8000000000000000 - 4; */
  }
}

/*@
  @ requires file_recovery->file_rename==&file_rename_zip;
  @ requires valid_file_rename_param(file_recovery);
  @ ensures  valid_file_rename_result(file_recovery);
  @*/
static void file_rename_zip(file_recovery_t *file_recovery)
{
  const char *ext=NULL;
  unsigned int file_nbr=0;
  file_recovery_t fr;
  reset_file_recovery(&fr);
  /*@ assert valid_read_string((char*)file_recovery->filename); */
  if((fr.handle=fopen(file_recovery->filename, "rb"))==NULL)
  {
    /*@ assert valid_read_string((char*)file_recovery->filename); */
    return;
  }
  fr.file_size = 0;
  fr.offset_error=0;
  first_filename[0]='\0';
  if(my_fseek(fr.handle, 0, SEEK_SET) < 0)
  {
    fclose(fr.handle);
    /*@ assert valid_read_string((char*)file_recovery->filename); */
    return ;
  }
  /*@ assert fr.file_size == 0; */
  /*@
    @ loop invariant valid_read_string((char*)file_recovery->filename);
    @ loop invariant strlen(&file_recovery->filename[0]) > 0;
    @ loop invariant valid_file_recovery(file_recovery);
    @ loop invariant fr.file_size < 0x8000000000000000 - 4;
    @ loop variant 0x8000000000000000 - fr.file_size;
    @*/
  while (1)
  {
    uint32_t header;
    int      status;
    if(file_nbr>=0xffffffff)
    {
      fclose(fr.handle);
      /*@ assert valid_read_string((char*)file_recovery->filename); */
      return;
    }
    /*@ assert fr.file_size < 0x8000000000000000 - 4; */
    if (fread(&header, 4, 1, fr.handle)!=1)
    {
#ifdef DEBUG_ZIP
      log_trace("Failed to read block header\n");
#endif
      fclose(fr.handle);
      /*@ assert valid_read_string((char*)file_recovery->filename); */
      return;
    }
#if defined(__FRAMAC__)
    Frama_C_make_unknown((char *)&header, 4);
#endif

    header = le32(header);
#ifdef DEBUG_ZIP
    log_trace("Header 0x%08X at 0x%llx\n", header, (long long unsigned int)fr.file_size);
    log_flush();
#endif
    fr.file_size += 4;

    switch (header)
    {
      case ZIP_CENTRAL_DIR: /* Central dir */
        status = zip_parse_central_dir(&fr);
        break;
      case ZIP_CENTRAL_DIR64: /* 64b end central dir */
        status = zip64_parse_end_central_dir(&fr);
        break;
      case ZIP_END_CENTRAL_DIR: /* End central dir */
        status = zip_parse_end_central_dir(&fr);
        break;
      case ZIP_END_CENTRAL_DIR64: /* 64b end central dir locator */
        status = zip64_parse_end_central_dir_locator(&fr);
        break;
      case ZIP_DATA_DESCRIPTOR: /* Data descriptor */
        status = zip_parse_data_desc(&fr);
        break;
      case ZIP_FILE_ENTRY: /* File Entry */
        status = zip_parse_file_entry(&fr, &ext, file_nbr);
	file_nbr++;
	if(ext!=NULL)
	{
	  fclose(fr.handle);
	  /*@ assert valid_read_string((char*)file_recovery->filename); */
	  file_rename(file_recovery, NULL, 0, 0, ext, 1);
	  /*@ assert valid_read_string((char*)file_recovery->filename); */
	  return;
	}
        break;
      case ZIP_SIGNATURE: /* Signature */
        status = zip_parse_signature(&fr);
        break;
      default:
#ifdef DEBUG_ZIP
        if ((header&0xFFFF) != 0x4B50)
          log_trace("Not a zip block: 0x%08X\n", header);
        else
          log_trace("Unparsable block with ID 0x%04X\n", header>>16);
#endif
        status = -1;
        break;
    }

    /* Verify status */
    if (status<0)
    {
      fclose(fr.handle);
      /*@ assert valid_read_string((char*)file_recovery->filename); */
      return;
    }
    /* Only end of central dir is end of archive, 64b version of it is before */
    if (header==ZIP_END_CENTRAL_DIR)
    {
      unsigned int len;
      fclose(fr.handle);
      /*@
        @ loop assigns len;
	@ loop variant 32 - len;
	@*/
      for(len=0; len<32 &&
	  first_filename[len]!='\0' &&
	  first_filename[len]!='.' &&
	  first_filename[len]!='/' &&
	  first_filename[len]!='\\';
	  len++);
      /*@ assert valid_read_string((char*)file_recovery->filename); */
      file_rename(file_recovery, first_filename, len, 0, "zip", 0);
      /*@ assert valid_read_string((char*)file_recovery->filename); */
      return;
    }
    if(file_nbr>=0xffffffff || fr.file_size >= 0x8000000000000000 - 4)
    {
      fclose(fr.handle);
      /*@ assert valid_read_string((char*)file_recovery->filename); */
      return;
    }
    /*@ assert fr.file_size < 0x8000000000000000 - 4; */
  }
}

/*@
  @ requires buffer_size >= 85;
  @ requires separation: \separated(&file_hint_zip, buffer +(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ ensures (\result == 1) ==> (file_recovery_new->time == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->min_filesize == 30);
  @ ensures (\result == 1) ==> (file_recovery_new->calculated_file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->data_check == \null);
  @ ensures (\result == 1) ==> file_recovery_new->file_check == &file_check_zip;
  @ ensures (\result == 1) ==> (file_recovery_new->file_rename == &file_rename_zip || file_recovery_new->file_rename == \null);
  @ ensures (\result == 1) ==> (file_recovery_new->extension == file_hint_zip.extension ||
      file_recovery_new->extension == extension_docx ||
      file_recovery_new->extension == extension_epub ||
      file_recovery_new->extension == extension_indd ||
      file_recovery_new->extension == extension_kra ||
      file_recovery_new->extension == extension_numbers ||
      file_recovery_new->extension == extension_odg ||
      file_recovery_new->extension == extension_odp ||
      file_recovery_new->extension == extension_ods ||
      file_recovery_new->extension == extension_odt ||
      file_recovery_new->extension == extension_ora ||
      file_recovery_new->extension == extension_pptx ||
      file_recovery_new->extension == extension_sh3d ||
      file_recovery_new->extension == extension_sxc ||
      file_recovery_new->extension == extension_sxd ||
      file_recovery_new->extension == extension_sxi ||
      file_recovery_new->extension == extension_sxw ||
      file_recovery_new->extension == extension_vsdx ||
      file_recovery_new->extension == extension_xd ||
      file_recovery_new->extension == extension_xlsx ||
      file_recovery_new->extension == extension_xrns );
  @ ensures (\result == 1) ==> (valid_read_string(file_recovery_new->extension));
  @*/
static int header_check_zip(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const zip_file_entry_t *file=(const zip_file_entry_t *)&buffer[4];
  const unsigned int len=le16(file->filename_length);
#ifdef DEBUG_ZIP
  log_trace("header_check_zip\n");
#endif
  if(len==0 || len > 4096)
    return 0;
  if(le16(file->version) < 10)
    return 0;
#if !defined(SINGLE_FORMAT_zip)
  if(file_recovery->file_stat!=NULL &&
      file_recovery->file_stat->file_hint==&file_hint_doc)
  {
    if(header_ignored_adv(file_recovery, file_recovery_new)==0)
      return 0;
  }
#endif
  /* A zip file begins by ZIP_FILE_ENTRY, this signature can also be
   * found for each compressed file */
  if(file_recovery->file_check == &file_check_zip &&
      file_recovery->file_stat!=NULL &&
//      file_recovery->file_stat->file_hint==&file_hint_zip &&
      safe_header_only==0)
  {
    /*@ assert file_recovery->file_check == file_check_zip; */
    if(header_ignored_adv(file_recovery, file_recovery_new)==0)
      return 0;
  }
  reset_file_recovery(file_recovery_new);
  file_recovery_new->min_filesize=30;	/* 4+sizeof(file) == 30 */
  file_recovery_new->file_check=&file_check_zip;
  if(len==8 && memcmp(&buffer[30],"mimetype",8)==0 && le16(file->extra_length)==0)
  {
    const unsigned int compressed_size=le32(file->compressed_size);
    file_recovery_new->extension=zip_parse_parse_entry_mimetype((const char *)&buffer[38], compressed_size);
  }
  else if(len==19 && memcmp(&buffer[30],"[Content_Types].xml",19)==0)
  {
    if(pos_in_mem(&buffer[0], buffer_size, (const unsigned char*)"word/", 5)!=0)
      file_recovery_new->extension=extension_docx;
    else if(pos_in_mem(&buffer[0], 2000, (const unsigned char*)"xl/", 3)!=0)
      file_recovery_new->extension=extension_xlsx;
    else if(pos_in_mem(&buffer[0], buffer_size, (const unsigned char*)"ppt/", 4)!=0)
      file_recovery_new->extension=extension_pptx;
    else if(pos_in_mem(&buffer[0], buffer_size, (const unsigned char*)"visio/", 6)!=0)
      file_recovery_new->extension=extension_vsdx;
    else
      file_recovery_new->extension=extension_docx;
    file_recovery_new->file_rename=&file_rename_zip;
  }
  /* Extended Renoise song file */
  else if(len==8 && memcmp(&buffer[30], "Song.xml", 8)==0)
    file_recovery_new->extension=extension_xrns;
  else if(len==4 && memcmp(&buffer[30], "Home", 4)==0)
    file_recovery_new->extension=extension_sh3d;
  /* Apple Numbers */
  else if(len==18 && memcmp(&buffer[30], "Index/Document.iwa", 18)==0)
    file_recovery_new->extension=extension_numbers;
  else
  {
    file_recovery_new->extension=file_hint_zip.extension;
    file_recovery_new->file_rename=&file_rename_zip;
  }
  return 1;
}

/*@
  @ requires buffer_size >= 85;
  @ requires separation: \separated(&file_hint_zip, buffer +(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ ensures \result == 1;
  @ ensures file_recovery_new->file_check == &file_check_zip;
  @ ensures file_recovery_new->extension == file_hint_zip.extension;
  @ assigns  *file_recovery_new;
  @*/
static int header_check_winzip(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  reset_file_recovery(file_recovery_new);
  file_recovery_new->file_check=&file_check_zip;
  file_recovery_new->extension=file_hint_zip.extension;
  /*@ assert valid_file_recovery(file_recovery_new); */
  return 1;
}

/*@
  @ requires haystack_size > 0;
  @ requires needle_size > 0;
  @ requires \valid_read(haystack + (0 .. haystack_size-1));
  @ requires \valid_read(needle + (0 .. needle_size-1));
  @ assigns \nothing;
  @ ensures \result <= haystack_size;
  @*/
static unsigned int pos_in_mem(const unsigned char *haystack, const unsigned int haystack_size, const unsigned char *needle, const unsigned int needle_size)
{
  unsigned int i;
  if(haystack_size < needle_size)
    return 0;
  /*@
    @ loop invariant 0 <= i <= haystack_size - needle_size + 1;
    @ loop assigns i;
    @ loop variant haystack_size - needle_size - i;
    @*/
  for(i=0; i <= haystack_size - needle_size; i++)
    if(memcmp(&haystack[i],needle,needle_size)==0)
      return (i+needle_size);
  return 0;
}

/*@
  @ requires valid_register_header_check(file_stat);
  @*/
static void register_header_check_zip(file_stat_t *file_stat)
{
  static const unsigned char zip_header2[8]  = { 'P', 'K', '0', '0', 'P', 'K', 0x03, 0x04}; /* WinZIPv8-compressed files. */
  register_header_check(0, zip_header,sizeof(zip_header), &header_check_zip, file_stat);
#ifndef DISABLED_FOR_FRAMAC
  register_header_check(0, zip_header2,sizeof(zip_header2), &header_check_winzip, file_stat);
#endif
}
#endif

#if defined(MAIN_zip)
#define BLOCKSIZE 65536u
int main()
{
  const char fn[] = "recup_dir.1/f0000000.zip";
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
  file_recovery_new.extension=NULL;
  file_recovery_new.file_stat=NULL;
  file_recovery_new.file_check=NULL;
  file_recovery_new.file_rename=NULL;
  file_recovery_new.calculated_file_size=0;
  file_recovery_new.file_size=0;
  file_recovery_new.location.start=0;

  file_stats.file_hint=&file_hint_zip;
  file_stats.not_recovered=0;
  file_stats.recovered=0;
  register_header_check_zip(&file_stats);
  if(header_check_zip(buffer, BLOCKSIZE, 0u, &file_recovery, &file_recovery_new)!=1)
    return 0;
  /*@ assert valid_read_string(file_recovery_new.extension); */
  /*@ assert valid_read_string((char *)&fn); */
  memcpy(file_recovery_new.filename, fn, sizeof(fn));
  file_recovery_new.file_stat=&file_stats;
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  /*@ assert file_recovery_new.min_filesize == 30;	*/
  /*@ assert file_recovery_new.file_check == &file_check_zip || file_recovery_new.file_check == \null; */
  /*@ assert file_recovery_new.file_stat->file_hint!=NULL; */
  /*@ assert file_recovery_new.time == 0; */
  {
    file_recovery_t file_recovery_new2;
    file_recovery_new2.blocksize=BLOCKSIZE;
    file_recovery_new2.file_stat=NULL;
    file_recovery_new2.file_check=NULL;
    file_recovery_new2.location.start=BLOCKSIZE;
    file_recovery_new.handle=NULL;	/* In theory should be not null */
    /*@ assert file_recovery_new.extension == file_hint_zip.extension ||
      file_recovery_new.extension == extension_docx ||
      file_recovery_new.extension == extension_epub ||
      file_recovery_new.extension == extension_kra ||
      file_recovery_new.extension == extension_numbers ||
      file_recovery_new.extension == extension_odg ||
      file_recovery_new.extension == extension_odp ||
      file_recovery_new.extension == extension_ods ||
      file_recovery_new.extension == extension_odt ||
      file_recovery_new.extension == extension_ora ||
      file_recovery_new.extension == extension_pptx ||
      file_recovery_new.extension == extension_sh3d ||
      file_recovery_new.extension == extension_sxc ||
      file_recovery_new.extension == extension_sxd ||
      file_recovery_new.extension == extension_sxi ||
      file_recovery_new.extension == extension_sxw ||
      file_recovery_new.extension == extension_vsdx ||
      file_recovery_new.extension == extension_xd ||
      file_recovery_new.extension == extension_xlsx ||
      file_recovery_new.extension == extension_xrns; */
    /*@ assert valid_read_string(file_recovery_new.extension); */
    /*@ assert valid_read_string((char *)file_recovery_new.filename); */
#if defined(__FRAMAC__)
    Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif
    /*@ assert valid_read_string((char *)file_recovery_new.filename); */
    /*@ assert valid_read_string(file_recovery_new.extension); */
    header_check_zip(buffer, BLOCKSIZE, 0, &file_recovery_new, &file_recovery_new2);
  }
  /*@ assert file_recovery_new.time == 0; */
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  /*@ assert valid_read_string(file_recovery_new.extension); */
  file_recovery_new.handle=fopen(fn, "rb");
  if(file_recovery_new.handle!=NULL && file_recovery_new.file_check !=NULL)
  {
    /*@ assert file_recovery_new.file_check == &file_check_zip; */
    /*@ assert file_recovery_new.time == 0; */
    file_check_zip(&file_recovery_new);
    fclose(file_recovery_new.handle);
  }
  if(file_recovery_new.file_rename!=NULL)
  {
    /*@ assert file_recovery_new.file_rename == &file_rename_zip; */
    /*@ assert valid_read_string((char *)file_recovery_new.filename); */
    file_rename_zip(&file_recovery_new);
  }
  return 0;
}
#endif
