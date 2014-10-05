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

/* Abolutely required for the zip64 stuff */
/* #define _FILE_OFFSET_BITS 64 */

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

/* #define DEBUG_ZIP */
extern const file_hint_t file_hint_doc;
static void register_header_check_zip(file_stat_t *file_stat);
static int header_check_zip(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);
static void file_check_zip(file_recovery_t *file_recovery);
static unsigned int pos_in_mem(const unsigned char *haystack, const unsigned int haystack_size, const unsigned char *needle, const unsigned int needle_size);
static void file_rename_zip(const char *old_filename);
static char first_filename[256];

const file_hint_t file_hint_zip= {
  .extension="zip",
  .description="zip archive including OpenOffice and MSOffice 2007",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_zip
};

static const unsigned char zip_header[4]  = { 'P', 'K', 0x03, 0x04};
static const unsigned char zip_header2[8]  = { 'P', 'K', '0', '0', 'P', 'K', 0x03, 0x04}; /* WinZIPv8-compressed files. */
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
  uint16_t last_mod_time;           /** Last moditication file time */
  uint16_t last_mod_date;           /** Last moditication file date */
  uint32_t crc32;                   /** CRC32 */
  uint32_t compressed_size;         /** Compressed size */
  uint32_t uncompressed_size;       /** Uncompressed size */
  uint16_t filename_length;         /** Filename length */
  uint16_t extra_length;            /** Extra fields length */
} __attribute__ ((__packed__));
typedef struct zip_file_entry zip_file_entry_t;

struct zip64_extra_entry
{
  uint16_t tag;
  uint16_t size;
  uint64_t uncompressed_size;
  uint64_t compressed_size;
  uint64_t offset;		/* Offset of local header record */
  uint32_t disk_start_number;	/* Number of the disk on which this file starts  */
} __attribute__ ((__packed__));
typedef struct zip64_extra_entry zip64_extra_entry_t;

static uint32_t expected_compressed_size=0;

static int64_t file_get_pos(FILE *f, const void* needle, const unsigned int size)
{
  char     *buffer =(char *)MALLOC(4096);
  int64_t  total   = 0;
#ifdef DEBUG_ZIP
  log_trace("zip: file_get_pos(f, needle, %u)\n", size);
#endif

  while (!feof(f))
  {
    int      count = 0;
    unsigned int left;
    const unsigned int read_size= fread(buffer, 1, 4096, f);
    left  = read_size;

    while (left>=size)
    {
      if (buffer[count]==*(const char *)needle && memcmp(buffer+count, needle, size)==0)
      {
	free(buffer);
#ifdef HAVE_FSEEKO
        if(fseeko(f, (long)count-read_size, SEEK_CUR)<0)
#else
        if(fseek(f, (long)count-read_size, SEEK_CUR)<0)
#endif
          return -1;
        return total;
      }
      count++;
      total++;
      left--;
    }
#ifdef HAVE_FSEEKO
    if(feof(f) || fseeko(f, (long)1-size, SEEK_CUR)<0)
#else
    if(feof(f) || fseek(f, (long)1-size, SEEK_CUR)<0)
#endif
    {
      free(buffer);
      return -1;
    }
  }
  free(buffer);
  return -1;
}

static int zip_parse_file_entry(file_recovery_t *fr, const char **ext, const unsigned int file_nbr)
{
  zip_file_entry_t  file;
  zip64_extra_entry_t extra;
  uint64_t          len;
  unsigned int krita=0;
  if (fread(&file, sizeof(file), 1, fr->handle) != 1)
  {
#ifdef DEBUG_ZIP
    log_trace("zip: Unexpected EOF reading header of file_entry\n");
#endif
    return -1;
  }
  fr->file_size += sizeof(file);
#ifdef DEBUG_ZIP
  log_info("%u Comp=%u %u CRC32=0x%08X ",
      le32(file.compressed_size),
      le16(file.compression),
      le32(file.uncompressed_size),
      le32(file.crc32));
#endif
  {
    /* Use the more recent file to set the time/date of the recovered archive */
    const time_t tmp=date_dos2unix(le16(file.last_mod_time), le16(file.last_mod_date));
    if(fr->time < tmp)
      fr->time=tmp;
  }
  len = le16(file.filename_length);
  if (len)
  {
    char *filename=(char *)MALLOC(len+1);
    if (fread(filename, len, 1, fr->handle) != 1)
    {
#ifdef DEBUG_ZIP
      log_trace("zip: Unexpected EOF in file_entry header: %lu bytes expected\n", len);
#endif
      free(filename);
      return -1;
    }
    fr->file_size += len;
    filename[len]='\0';
    if(first_filename[0]=='\0')
    {
      const unsigned int len_tmp=(len<255?len:255);
      strncpy(first_filename, filename, len_tmp);
      first_filename[len_tmp]='\0';
    }
#ifdef DEBUG_ZIP
    log_info("%s\n", filename);
#endif
    if(*ext==NULL)
    {
      static int msoffice=0;
      static int sh3d=0;
      if(file_nbr==0)
      {
	msoffice=0;
	sh3d=0;
	if(len==8 && memcmp(filename, "mimetype", 8)==0 && le16(file.extra_length)==0)
	{
	  unsigned char buffer[128];
	  const unsigned int compressed_size=le32(file.compressed_size);
	  const int to_read=(compressed_size < 128 ? compressed_size: 128);
	  if( fread(buffer, to_read, 1, fr->handle)!=1)
	  {
#ifdef DEBUG_ZIP
	    log_trace("zip: Unexpected EOF in file_entry data: %u bytes expected\n",
	    compressed_size);
#endif
	    free(filename);
	    return -1;
	  }
#ifdef HAVE_FSEEKO
	  if (fseeko(fr->handle, -to_read, SEEK_CUR) < 0)
#else
	  if (fseek(fr->handle, -to_read, SEEK_CUR) < 0)
#endif
	  {
	    log_info("fseek failed\n");
	    free(filename);
	    return -1;
	  }
	  if(compressed_size==16      && memcmp(buffer,"image/openraster",16)==0)
	    *ext="ora";
	  else if(compressed_size==28 && memcmp(buffer,"application/vnd.sun.xml.calc",28)==0)
	    *ext="sxc";
	  else if(compressed_size==28 && memcmp(buffer,"application/vnd.sun.xml.draw",28)==0)
	    *ext="sxd";
	  else if(compressed_size==31 && memcmp(buffer,"application/vnd.sun.xml.impress",31)==0)
	    *ext="sxi";
	  else if(compressed_size==30 && memcmp(buffer,"application/vnd.sun.xml.writer",30)==0)
	    *ext="sxw";
	  else if(compressed_size==39 && memcmp(buffer,"application/vnd.oasis.opendocument.text",39)==0)
	    *ext="odt";
	  else if(compressed_size==43 && memcmp(buffer,"application/vnd.oasis.opendocument.graphics",43)==0)
	    *ext="odg";
	  else if(compressed_size==46 && memcmp(buffer,"application/vnd.oasis.opendocument.spreadsheet",46)==0)
	    *ext="ods";
	  else if(compressed_size==47 && memcmp(buffer,"application/vnd.oasis.opendocument.presentation",47)==0)
	    *ext="odp";
	  else if(memcmp(buffer,"application/x-krita",19)==0)
	  {
	    *ext="kra";
	    krita=19;
	  }
	  else
	  { /* default to writer */
	    *ext="sxw";
	  }
	}
	else if(len==19 && memcmp(filename, "[Content_Types].xml", 19)==0)
	  msoffice=1;
	/* Zipped Keyhole Markup Language (KML) used by Google Earth */
	else if(len==7 && memcmp(filename, "doc.kml", 7)==0)
	  *ext="kmz";
	else if(len==4 && memcmp(filename, "Home", 4)==0)
	  sh3d=1;
      }
      else if(file_nbr==1 && sh3d==1)
      {
	if(len==1 && filename[0]=='0')
	  *ext="sh3d";
      }
      else if(file_nbr==2 && msoffice!=0)
      {
	if(strncmp(filename, "word/", 5)==0)
	  *ext="docx";
	else if(strncmp(filename, "xl/", 3)==0)
	  *ext="xlsx";
	else if(strncmp(filename, "ppt/", 4)==0)
	  *ext="pptx";
	else
	  *ext="docx";
      }
    }
    if(*ext==NULL)
    {
	/* iWork */
      if(len==23 && memcmp(filename, "QuickLook/Thumbnail.jpg", 23)==0)
	*ext="pages";
      else if(len==20 && strncasecmp(filename, "META-INF/MANIFEST.MF", 20)==0)
	*ext="jar";
      else if(len==15 && strncasecmp(filename, "chrome.manifest", 15)==0)
	*ext="xpi";
      /* SMART Notebook */
      else if(len==15 && memcmp(filename, "imsmanifest.xml", 15)==0)
	*ext="notebook";
      else if(len==30 && memcmp(filename, "xsd/MindManagerApplication.xsd", 30)==0)
	*ext="mmap";
    }
    free(filename);
  }
#ifdef DEBUG_ZIP
  log_info("\n");
#endif
  len = le16(file.extra_length);
  memset(&extra, 0, sizeof(extra));
  if (len>0)
  {
    if (fread(&extra, sizeof(extra), 1, fr->handle) != 1)
    {
#ifdef DEBUG_ZIP
      log_trace("zip: Unexpected EOF in file_entry header: %lu bytes expected\n", len);
#endif
    }
#ifdef HAVE_FSEEKO
    if (fseeko(fr->handle, fr->file_size, SEEK_SET) == -1 ||
	fseeko(fr->handle, len, SEEK_CUR) == -1)
#else
    if (fseek(fr->handle, fr->file_size, SEEK_SET) == -1 ||
	fseek(fr->handle, len, SEEK_CUR) == -1)
#endif
    {
#ifdef DEBUG_ZIP
      log_trace("zip: Unexpected EOF in file_entry header: %lu bytes expected\n", len);
#endif
      return -1;
    }
    fr->file_size += len;
  }
  len = le32(file.compressed_size);
  if(len==0xffffffff && le16(extra.tag)==1)
  {
    len = le64(extra.compressed_size);
  }
  if(krita>0)
    len=krita;
  if (len>0)
  {
#ifdef HAVE_FSEEKO
    if (fseeko(fr->handle, len, SEEK_CUR) == -1)
#else
    if (fseek(fr->handle, len, SEEK_CUR) == -1)
#endif
    {
#ifdef DEBUG_ZIP
      log_trace("zip: Unexpected EOF in file_entry data: %lu bytes expected\n", len);
#endif
      return -1;
    }
#ifdef DEBUG_ZIP
    log_trace("zip: Data of length %lu\n", len);
#endif
    fr->file_size += len;
  }

  expected_compressed_size=0;
  if (file.has_descriptor && (le16(file.compression)==8 || le16(file.compression)==9))
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
      fr->file_size += pos;
      expected_compressed_size=pos;
    }
  }
  return 0;
}

static int zip_parse_central_dir(file_recovery_t *fr)
{
  zip_file_entry_t  file;
  uint32_t          len;
  struct {
    /* Fields common with zip_file_entry removed */
    uint16_t comment_length;          /** Comment length */
    uint16_t disk_number_start;       /** Disk number start */
    uint16_t internal_attr;           /** Internal file attributes */
    uint32_t external_attr;           /** External file attributes */
    uint32_t offset_header;           /** Relative offset of local header */
  } __attribute__ ((__packed__)) dir;
#ifdef HAVE_FSEEKO
  if (fseeko(fr->handle, 2, SEEK_CUR) == -1)
#else
  if (fseek(fr->handle, 2, SEEK_CUR) == -1)
#endif
  {
#ifdef DEBUG_ZIP
    log_trace("Unexpected EOF skipping version from central_dir\n");
#endif
    return -1;
  }
  fr->file_size += 2;

  if (fread(&file, sizeof(file), 1, fr->handle) != 1)
  {
#ifdef DEBUG_ZIP
    log_trace("Unexpected EOF reading 1st part of central_dir\n");
#endif
    return -1;
  }
  fr->file_size += sizeof(file);
#ifdef DEBUG_ZIP
  log_trace("zip: Central dir with CRC 0x%08X\n", file.crc32);
#endif

  if (fread(&dir, sizeof(dir), 1, fr->handle) != 1)
  {
#ifdef DEBUG_ZIP
    log_trace("zip: Unexpected EOF reading 2nd part of central_dir\n");
#endif
    return -1;
  }
  fr->file_size += sizeof(dir);

  /* Rest of the block - could attempt CRC check */
  len = le16(file.extra_length) + le16(dir.comment_length) + le16(file.filename_length);
#ifdef HAVE_FSEEKO
  if (fseeko(fr->handle, len, SEEK_CUR) == -1)
#else
  if (fseek(fr->handle, len, SEEK_CUR) == -1)
#endif
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

static int zip64_parse_end_central_dir(file_recovery_t *fr)
{
  struct {
    uint64_t end_size;                /** Size of zip64 end of central directory record */
    uint16_t version_made;            /** Version made by */
    uint16_t version_needed;          /** Version needed to extract */
    uint32_t number_disk;             /** Number of this disk */
    uint32_t number_disk2;            /** Number of the disk with the start of the central directory */
    uint64_t number_entries;          /** Total number of entries in the central directory on this disk */
    uint64_t number_entries2;         /** Total number of entries in the central directory */
    uint64_t size;                    /** Size of the central directory */
    uint64_t offset;                  /** Offset of start of central directory */
  } __attribute__ ((__packed__)) dir;

  if (fread(&dir, sizeof(dir), 1, fr->handle) != 1)
  {
#ifdef DEBUG_ZIP
    log_trace("zip: Unexpected EOF reading end_central_dir_64\n");
#endif
    return -1;
  }
  fr->file_size += sizeof(dir);

  if (dir.end_size > 0)
  {
    const uint64_t len = le64(dir.end_size);
#ifdef HAVE_FSEEKO
    if (fseeko(fr->handle, len, SEEK_CUR) == -1)
#else
    if (fseek(fr->handle, len, SEEK_CUR) == -1)
#endif
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

static int zip_parse_end_central_dir(file_recovery_t *fr)
{
  struct {
    uint16_t number_disk;             /** Number of this disk */
    uint16_t number_disk2;            /** Number in the central dir */
    uint16_t total_number_disk;       /** Total number of entries in this disk */
    uint16_t total_number_disk2;      /** Total number of entries in the central dir */
    uint32_t size;                    /** Size of the central directory */
    uint32_t offset;                  /** Offset of start of central directory */
    uint16_t comment_length;          /** Comment length */
  } __attribute__ ((__packed__)) dir;

  if (fread(&dir, sizeof(dir), 1, fr->handle) != 1)
  {
#ifdef DEBUG_ZIP
    log_trace("zip: Unexpected EOF reading header of zip_parse_end_central_dir\n");
#endif
    return -1;
  }
  fr->file_size += sizeof(dir);

  if (dir.comment_length)
  {
    const uint16_t len = le16(dir.comment_length);
#ifdef HAVE_FSEEKO
    if (fseeko(fr->handle, len, SEEK_CUR) == -1)
#else
    if (fseek(fr->handle, len, SEEK_CUR) == -1)
#endif
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

static int zip_parse_data_desc(file_recovery_t *fr)
{
  struct {
    uint32_t crc32;                  /** Checksum (CRC32) */
    uint32_t compressed_size;        /** Compressed size (bytes) */
    uint32_t uncompressed_size;      /** Uncompressed size (bytes) */
  } __attribute__ ((__packed__)) desc;

  if (fread(&desc, sizeof(desc), 1, fr->handle) != 1)
  {
#ifdef DEBUG_ZIP
    log_trace("zip: Unexpected EOF reading header of data_desc\n");
#endif
    return -1;
  }
  fr->file_size += sizeof(desc);
#ifdef DEBUG_ZIP
  log_info("%u %u CRC32=0x%08X\n",
      le32(desc.compressed_size),
      le32(desc.uncompressed_size),
      le32(desc.crc32));
#endif
  if(le32(desc.compressed_size)!=expected_compressed_size)
    return -1;
  return 0;
}

static int zip_parse_signature(file_recovery_t *fr)
{
  uint16_t len;

  if (fread(&len, 2, 1, fr->handle) != 1)
  {
#ifdef DEBUG_ZIP
    log_trace("zip: Unexpected EOF reading length of signature\n");
#endif
    return -1;
  }
  fr->file_size += 2;

  if (len)
  {
    len = le16(len);
#ifdef HAVE_FSEEKO
    if (fseeko(fr->handle, len, SEEK_CUR) == -1)
#else
    if (fseek(fr->handle, len, SEEK_CUR) == -1)
#endif
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

static int zip64_parse_end_central_dir_locator(file_recovery_t *fr)
{
  struct {
    uint32_t disk_number;       /** Number of the disk with the start of the zip64 end of central directory */
    uint64_t relative_offset;   /** Relative offset of the zip64 end of central directory record */
    uint32_t disk_total_number; /** Total number of disks */
  } __attribute__ ((__packed__)) loc;

  if (fread(&loc, sizeof(loc), 1, fr->handle) != 1)
  {
#ifdef DEBUG_ZIP
    log_trace("zip: Unexpected EOF reading 1st part of end_central_dir_locator\n");
#endif
    return -1;
  }
  fr->file_size += sizeof(loc);
  return 0;
}

static void file_check_zip(file_recovery_t *fr)
{
  const char *ext=NULL;
  unsigned int file_nbr=0;
  fr->file_size = 0;
  fr->offset_error=0;
  fr->offset_ok=0;
  first_filename[0]='\0';
#ifdef HAVE_FSEEKO
  if(fseeko(fr->handle, 0, SEEK_SET) < 0)
#else
  if(fseek(fr->handle, 0, SEEK_SET) < 0)
#endif
    return ;
  while (1)
  {
    uint64_t file_size_old;
    uint32_t header;
    int      status;

    if (fread(&header, 4, 1, fr->handle)!=1)
    {
#ifdef DEBUG_ZIP
      log_trace("Failed to read block header\n");
#endif
      fr->offset_error=fr->file_size;
      fr->file_size=0;
      return;
    }

    header = le32(header);
#ifdef DEBUG_ZIP
    log_trace("Header 0x%08X at 0x%llx\n", header, (long long unsigned int)fr->file_size);
    log_flush();
#endif
    fr->file_size += 4;
    file_size_old=fr->file_size;

    switch (header)
    {
      case ZIP_CENTRAL_DIR: /* Central dir */
        status = zip_parse_central_dir(fr);
        break;
      case ZIP_CENTRAL_DIR64: /* 64b end central dir */
        status = zip64_parse_end_central_dir(fr);
        break;
      case ZIP_END_CENTRAL_DIR: /* End central dir */
        status = zip_parse_end_central_dir(fr);
        break;
      case ZIP_END_CENTRAL_DIR64: /* 64b end central dir locator */
        status = zip64_parse_end_central_dir_locator(fr);
        break;
      case ZIP_DATA_DESCRIPTOR: /* Data descriptor */
        status = zip_parse_data_desc(fr);
        break;
      case ZIP_FILE_ENTRY: /* File Entry */
        status = zip_parse_file_entry(fr, &ext, file_nbr);
	file_nbr++;
        break;
      case ZIP_SIGNATURE: /* Signature */
        status = zip_parse_signature(fr);
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
      fr->offset_error = fr->file_size;
      fr->file_size = 0;
      return;
    }
    /* Only end of central dir is end of archive, 64b version of it is before */
    if (header==ZIP_END_CENTRAL_DIR)
      return;
    fr->offset_ok=file_size_old;
  }
}

static void file_rename_zip(const char *old_filename)
{
  const char *ext=NULL;
  unsigned int file_nbr=0;
  file_recovery_t fr;
  reset_file_recovery(&fr);
  if((fr.handle=fopen(old_filename, "rb"))==NULL)
    return;
  fr.file_size = 0;
  fr.offset_error=0;
  first_filename[0]='\0';
#ifdef HAVE_FSEEKO
  if(fseeko(fr.handle, 0, SEEK_SET) < 0)
#else
  if(fseek(fr.handle, 0, SEEK_SET) < 0)
#endif
  {
    fclose(fr.handle);
    return ;
  }
  while (1)
  {
    uint32_t header;
    int      status;

    if (fread(&header, 4, 1, fr.handle)!=1)
    {
#ifdef DEBUG_ZIP
      log_trace("Failed to read block header\n");
#endif
      fclose(fr.handle);
      return;
    }

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
	  file_rename(old_filename, NULL, 0, 0, ext, 1);
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
      return;
    }
    /* Only end of central dir is end of archive, 64b version of it is before */
    if (header==ZIP_END_CENTRAL_DIR)
    {
      unsigned int len;
      fclose(fr.handle);
      for(len=0; len<32 &&
	  first_filename[len]!='\0' &&
	  first_filename[len]!='.' &&
	  first_filename[len]!='/' &&
	  first_filename[len]!='\\';
	  len++);
      file_rename(old_filename, first_filename, len, 0, "zip", 0);
      return;
    }
  }
}

static void register_header_check_zip(file_stat_t *file_stat)
{
  register_header_check(0, zip_header,sizeof(zip_header), &header_check_zip, file_stat);
  register_header_check(0, zip_header2,sizeof(zip_header2), &header_check_zip, file_stat);
}

static int header_check_zip(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
#ifdef DEBUG_ZIP
  log_trace("header_check_zip\n");
#endif
  if(memcmp(buffer,zip_header,sizeof(zip_header))==0)
  {
    const zip_file_entry_t *file=(const zip_file_entry_t *)&buffer[4];
    const unsigned int len=le16(file->filename_length);
    if(file_recovery->file_stat!=NULL &&
	file_recovery->file_stat->file_hint==&file_hint_doc &&
	(strcmp(file_recovery->extension,"doc")==0 ||
	 strcmp(file_recovery->extension,"psmodel")==0)
	&& memcmp(&buffer[30], "macrolog_1.mac", 14)==0)
      return 0;
    /* A zip file begins by ZIP_FILE_ENTRY, this signature can also be
     * found for each compressed file */
    if(file_recovery->file_stat!=NULL &&
	file_recovery->file_stat->file_hint==&file_hint_zip &&
	safe_header_only==0)
      return 0;
    reset_file_recovery(file_recovery_new);
    file_recovery_new->min_filesize=21;
    file_recovery_new->file_check=&file_check_zip;
    if(len==8 && memcmp(&buffer[30],"mimetype",8)==0)
    {
      const unsigned int compressed_size=le32(file->compressed_size);
      /* Mypaint .ora */
      if(compressed_size==16 && memcmp(&buffer[38],"image/openraster",16)==0)
	file_recovery_new->extension="ora";
      else if(compressed_size==28 && memcmp(&buffer[38],"application/vnd.sun.xml.calc",28)==0)
	file_recovery_new->extension="sxc";
      else if(compressed_size==28 && memcmp(&buffer[38],"application/vnd.sun.xml.draw",28)==0)
	file_recovery_new->extension="sxd";
      else if(compressed_size==31 && memcmp(&buffer[38],"application/vnd.sun.xml.impress",31)==0)
	file_recovery_new->extension="sxi";
      else if(compressed_size==30 && memcmp(&buffer[38],"application/vnd.sun.xml.writer",30)==0)
	file_recovery_new->extension="sxw";
      else if(compressed_size==39 && memcmp(&buffer[38],"application/vnd.oasis.opendocument.text",39)==0)
	file_recovery_new->extension="odt";
      else if(compressed_size==43 && memcmp(&buffer[38],"application/vnd.oasis.opendocument.graphics",43)==0)
	file_recovery_new->extension="odg";
      else if(compressed_size==46 && memcmp(&buffer[38],"application/vnd.oasis.opendocument.spreadsheet",46)==0)
	file_recovery_new->extension="ods";
      else if(compressed_size==47 && memcmp(&buffer[38],"application/vnd.oasis.opendocument.presentation",47)==0)
	file_recovery_new->extension="odp";
      else if(memcmp(&buffer[38],"application/x-krita",19)==0)
	file_recovery_new->extension="kra";
      else
      { /* default to writer */
	file_recovery_new->extension="sxw";
      }
    }
    else if(len==19 && memcmp(&buffer[30],"[Content_Types].xml",19)==0)
    {
      if(pos_in_mem(&buffer[0], buffer_size, (const unsigned char*)"word/", 5)!=0)
	file_recovery_new->extension="docx";
      else if(pos_in_mem(&buffer[0], 2000, (const unsigned char*)"xl/", 3)!=0)
	file_recovery_new->extension="xlsx";
      else if(pos_in_mem(&buffer[0], buffer_size, (const unsigned char*)"ppt/", 4)!=0)
	file_recovery_new->extension="pptx";
      else
	file_recovery_new->extension="docx";
      file_recovery_new->file_rename=&file_rename_zip;
    }
    /* Extended Renoise song file */
    else if(len==8 && memcmp(&buffer[30], "Song.xml", 8)==0)
      file_recovery_new->extension="xrns";
    else if(len==4 && memcmp(&buffer[30], "Home", 4)==0)
      file_recovery_new->extension="sh3d";
    else
    {
      file_recovery_new->extension=file_hint_zip.extension;
      file_recovery_new->file_rename=&file_rename_zip;
    }
    return 1;
  }
  else if(memcmp(buffer,zip_header2,sizeof(zip_header2))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->file_check=&file_check_zip;
    file_recovery_new->extension=file_hint_zip.extension;
    return 1;
  }
  return 0;
}

static unsigned int pos_in_mem(const unsigned char *haystack, const unsigned int haystack_size, const unsigned char *needle, const unsigned int needle_size)
{
  unsigned int i;
  for(i=0;i<haystack_size;i++)
    if(memcmp(&haystack[i],needle,needle_size)==0)
      return (i+needle_size);
  return 0;
}

