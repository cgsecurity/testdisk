/*

    File: file_zip.c

    Copyright (C) 1998-2007 Christophe GRENIER <grenier@cgsecurity.org>
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
static void register_header_check_zip(file_stat_t *file_stat);
static int header_check_zip(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);
static void file_check_zip(file_recovery_t *file_recovery);
static unsigned int pos_in_mem(const unsigned char *haystack, const unsigned int haystack_size, const unsigned char *needle, const unsigned int needle_size);

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
  uint32_t last_mod;                /** Last moditication file time */
  uint32_t crc32;                   /** CRC32 */
  uint32_t compressed_size;         /** Compressed size */
  uint32_t uncompressed_size;       /** Uncompressed size */
  uint16_t filename_length;         /** Filename length */
  uint16_t extra_length;            /** Extra fields length */
} __attribute__ ((__packed__));
typedef struct zip_file_entry zip_file_entry_t;

static uint32_t expected_compressed_size=0;

static int64_t file_get_pos(FILE *f, const void* needle, const unsigned int size)
{
  char     *buffer = MALLOC(4096);
  int64_t  total   = 0;
#ifdef DEBUG_ZIP
  log_trace("zip: file_get_pos(f, needle, %u)\n", size);
#endif

  while (!feof(f))
  {
    int      count = 0;
    unsigned int left;
    unsigned int read_size= fread(buffer, 1, 4096, f);
    left  = read_size;

    while (left>=size)
    {
      if (memcmp(buffer+count, needle, size)==0)
      {
	free(buffer);
        if(fseek(f, (long)count-read_size, SEEK_CUR)<0)
          return -1;
        return total;
      }
      count++;
      total++;
      left--;
    }
    if(feof(f) || fseek(f, (long)1-size, SEEK_CUR)<0)
    {
      free(buffer);
      return -1;
    }
  }
  free(buffer);
  return -1;
}

static int zip_parse_file_entry(file_recovery_t *fr)
{
  zip_file_entry_t  file;
  uint32_t          len;

  fr->file_size += sizeof(file);
  if (fread(&file, sizeof(file), 1, fr->handle) != 1)
  {
#ifdef DEBUG_ZIP
    log_trace("zip: Unexpected EOF reading header of file_entry\n");
#endif
    return -1;
  }
#ifdef DEBUG_ZIP
  log_info("%u Comp=%u %u CRC32=0x%08X ",
      le32(file.compressed_size),
      le16(file.compression),
      le32(file.uncompressed_size),
      le32(file.crc32));
#endif
  len = le16(file.filename_length);
  if (len)
  {
    char *filename=MALLOC(len+1);
    fr->file_size += len;
    if (fread(filename, len, 1, fr->handle) != 1)
    {
#ifdef DEBUG_ZIP
      log_trace("zip: Unexpected EOF in file_entry header: %u bytes expected\n", len);
#endif
      return -1;
    }
    filename[len]='\0';
#ifdef DEBUG_ZIP
    log_info("%s", filename);
#endif
    free(filename);
  }
#ifdef DEBUG_ZIP
  log_info("\n");
#endif
  len = le16(file.extra_length);
  if (len>0)
  {
    fr->file_size += len;
    if (fseek(fr->handle, len, SEEK_CUR) == -1)
    {
#ifdef DEBUG_ZIP
      log_trace("zip: Unexpected EOF in file_entry header: %u bytes expected\n", len);
#endif
      return -1;
    }
  }
  len = le32(file.compressed_size);
  if (len>0)
  {
    fr->file_size += len;
    if (fseek(fr->handle, len, SEEK_CUR) == -1)
    {
#ifdef DEBUG_ZIP
      log_trace("zip: Unexpected EOF in file_entry data: %u bytes expected\n", len);
#endif
      return -1;
    }
#ifdef DEBUG_ZIP
    log_trace("zip: Data of length %u\n", len);
#endif
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
    int64_t pos = file_get_pos(fr->handle, zip_data_desc_header, 4);
#ifdef DEBUG_ZIP
    log_trace("Searched footer, got length %lli\n", (long long int)pos);
#endif
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

  fr->file_size += 2;
  if (fseek(fr->handle, 2, SEEK_CUR) == -1)
  {
#ifdef DEBUG_ZIP
    log_trace("Unexpected EOF skipping version from central_dir\n");
#endif
    return -1;
  }

  fr->file_size += sizeof(file);
  if (fread(&file, sizeof(file), 1, fr->handle) != 1)
  {
#ifdef DEBUG_ZIP
    log_trace("Unexpected EOF reading 1st part of central_dir\n");
#endif
    return -1;
  }
#ifdef DEBUG_ZIP
  log_trace("zip: Central dir with CRC 0x%08X\n", file.crc32);
#endif

  fr->file_size += sizeof(dir);
  if (fread(&dir, sizeof(dir), 1, fr->handle) != 1)
  {
#ifdef DEBUG_ZIP
    log_trace("zip: Unexpected EOF reading 2nd part of central_dir\n");
#endif
    return -1;
  }

  /* Rest of the block - could attempt CRC check */
  len = le16(file.extra_length) + le16(dir.comment_length) + le16(file.filename_length);
  fr->file_size += len;
  if (fseek(fr->handle, len, SEEK_CUR) == -1)
  {
#ifdef DEBUG_ZIP
    log_trace("zip: Unexpected EOF in central_dir: %u bytes expected\n", len);
#endif
    return -1;
  }
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

  fr->file_size += sizeof(dir);
  if (fread(&dir, sizeof(dir), 1, fr->handle) != 1)
  {
#ifdef DEBUG_ZIP
    log_trace("zip: Unexpected EOF reading end_central_dir_64\n");
#endif
    return -1;
  }

  if (dir.end_size > 0)
  {
    uint64_t len = le64(dir.end_size);
    fr->file_size += len;
    if (fseek(fr->handle, len, SEEK_CUR) == -1)
    {
#ifdef DEBUG_ZIP
      log_trace("zip: Unexpected EOF in end_central_dir_64: expected %llu bytes\n", (long long unsigned)len);
#endif
      return -1;
    }
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

  fr->file_size += sizeof(dir);
  if (fread(&dir, sizeof(dir), 1, fr->handle) != 1)
  {
#ifdef DEBUG_ZIP
    log_trace("zip: Unexpected EOF reading header of zip_parse_end_central_dir\n");
#endif
    return -1;
  }

  if (dir.comment_length)
  {
    uint16_t len = le16(dir.comment_length);
    fr->file_size += len;
    if (fseek(fr->handle, len, SEEK_CUR) == -1)
    {
#ifdef DEBUG_ZIP
      log_trace("zip: Unexpected EOF in end_central_dir: expected %u bytes\n", len);
#endif
      return -1;
    }
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

  fr->file_size += sizeof(desc);
  if (fread(&desc, sizeof(desc), 1, fr->handle) != 1)
  {
#ifdef DEBUG_ZIP
    log_trace("zip: Unexpected EOF reading header of data_desc\n");
#endif
    return -1;
  }
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

  fr->file_size += 2;
  if (fread(&len, 2, 1, fr->handle) != 1)
  {
#ifdef DEBUG_ZIP
    log_trace("zip: Unexpected EOF reading length of signature\n");
#endif
    return -1;
  }

  if (len)
  {
    len = le16(len);
    fr->file_size += len;
    if (fseek(fr->handle, len, SEEK_CUR) == -1)
    {
#ifdef DEBUG_ZIP
      log_trace("zip: Unexpected EOF in zip_parse_signature: expected %u bytes\n", len);
#endif
      return -1;
    }
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

  fr->file_size += sizeof(loc);
  if (fread(&loc, sizeof(loc), 1, fr->handle) != 1)
  {
#ifdef DEBUG_ZIP
    log_trace("zip: Unexpected EOF reading 1st part of end_central_dir_locator\n");
#endif
    return -1;
  }
  return 0;
}

static void file_check_zip(file_recovery_t *fr)
{
  fseek(fr->handle, 0, SEEK_SET);
  fr->file_size = 0;
  fr->offset_error=0;

  while (1)
  {
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
        status = zip_parse_file_entry(fr);
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
        status=-1;
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
    reset_file_recovery(file_recovery_new);
    file_recovery_new->min_filesize=21;
    file_recovery_new->file_check=&file_check_zip;
    if(memcmp(&buffer[30],"mimetypeapplication/vnd.sun.xml.",32)==0)
     {
       if(memcmp(&buffer[62],"calc",4)==0)
       {
         file_recovery_new->extension="sxc";
       }
       else if(memcmp(&buffer[62],"draw",4)==0)
       {
         file_recovery_new->extension="sxd";
       }
       else if(memcmp(&buffer[62],"impress",7)==0)
       {
         file_recovery_new->extension="sxi";
       }
       else if(memcmp(&buffer[62],"writer",6)==0)
       {
         file_recovery_new->extension="sxw";
       }
       else
       { /* default to writer */
         file_recovery_new->extension="sxw";
       }
     }
     else if(memcmp(&buffer[30],"mimetypeapplication/vnd.oasis.opendocument.graphics",51)==0)
       file_recovery_new->extension="odg";
     else if(memcmp(&buffer[30],"mimetypeapplication/vnd.oasis.opendocument.presentation",55)==0)
       file_recovery_new->extension="odp";
     else if(memcmp(&buffer[30],"mimetypeapplication/vnd.oasis.opendocument.spreadsheet",54)==0)
       file_recovery_new->extension="ods";
     else if(memcmp(&buffer[30],"mimetypeapplication/vnd.oasis.opendocument.text",47)==0)
       file_recovery_new->extension="odt";
     else if(memcmp(&buffer[30],"[Content_Types].xml",19)==0)
     {
       if(pos_in_mem(&buffer[0],2000,"word",4)!=0)
         file_recovery_new->extension="docx";
       else if(pos_in_mem(&buffer[0],2000,"xl",2)!=0)
         file_recovery_new->extension="xlsx";
       else if(pos_in_mem(&buffer[0],2000,"ppt",3)!=0)
         file_recovery_new->extension="pptx";
       else
         file_recovery_new->extension="docx";
     }
    else
      file_recovery_new->extension=file_hint_zip.extension;
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

