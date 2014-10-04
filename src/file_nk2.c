/*

    File: file_nk2.c

    Copyright (C) 2009 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include "filegen.h"
#include "common.h"
#include "log.h"

static void register_header_check_nk2(file_stat_t *file_stat);
static int header_check_nk2(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);
static void file_check_nk2(file_recovery_t *file_recovery);

const file_hint_t file_hint_nk2= {
  .extension="nk2",
  .description="Outlook Nickfile",
  .min_header_distance=0,
  .max_filesize=100*1024*1024,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_nk2
};

static const unsigned char nk2_header[8]=  { 0x0d, 0xf0, 0xad, 0xba, 0x0a, 0x00, 0x00, 0x00 };

typedef struct {
  uint32_t magic;
  uint32_t magic2;
  uint32_t magic3;
  uint32_t items_count;
} nk2Header;

typedef struct {
  uint32_t entries_count;
} itemHeader;

typedef struct {
  uint16_t value_type;
  uint16_t entry_type;
  uint32_t unk1;
  uint32_t unk2;
  uint32_t unk3;
} entryHeader;

static void register_header_check_nk2(file_stat_t *file_stat)
{
  register_header_check(0, nk2_header,  sizeof(nk2_header),  &header_check_nk2, file_stat);
}

static int header_check_nk2(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(buffer, nk2_header, sizeof(nk2_header))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_nk2.extension;
    file_recovery_new->file_check=&file_check_nk2;
    return 1;
  }
  return 0;
}

#define	PT_UNSPECIFIED	0x0000
#define	PT_NULL		0x0001
#define	PT_I2		0x0002
#define	PT_LONG		0x0003
#define	PT_R4		0x0004
#define	PT_DOUBLE	0x0005
#define	PT_CURRENCY	0x0006
#define	PT_APPTIME	0x0007
#define	PT_ERROR	0x000a /* means the given attr contains no value */
#define	PT_BOOLEAN	0x000b
#define	PT_OBJECT	0x000d
#define	PT_I8		0x0014
#define	PT_STRING8	0x001e
#define	PT_UNICODE	0x001f
#define	PT_SYSTIME	0x0040
#define	PT_CLSID       	0x0048
#define PT_SRVEID	0x00fb
#define PT_SRESTRICT	0x00fd
#define PT_ACTIONS	0x00fe
#define	PT_BINARY	0x0102

static void file_check_nk2(file_recovery_t *fr)
{
  nk2Header nk2h;
  unsigned int i;
  fr->file_size = 0;
  fr->offset_error=0;
  fr->offset_ok=0;
  if(
#ifdef HAVE_FSEEKO
      fseeko(fr->handle, 0, SEEK_SET) < 0 ||
#else
      fseek(fr->handle, 0, SEEK_SET) < 0 ||
#endif
      fread(&nk2h, sizeof(nk2h), 1, fr->handle)!=1)
    return;
  fr->file_size+=sizeof(nk2h);
#ifdef DEBUG_NK2
  log_info("nk2 item_count=%u\n", (unsigned int)le32(nk2h.items_count));
#endif
  for(i=0; i<le32(nk2h.items_count); i++)
  {
    unsigned int j;
    itemHeader itemh;
    if (fread(&itemh, sizeof(itemh), 1, fr->handle)!=1)
    {
      fr->offset_error=fr->file_size;
      fr->file_size=0;
      return;
    }
    fr->file_size+=sizeof(itemh);
#ifdef DEBUG_NK2
    log_info("nk2  entries_count=%u\n", (unsigned int)le32(itemh.entries_count));
#endif
    for(j=0; j<le32(itemh.entries_count); j++)
    {
      uint32_t size;
      entryHeader entryh;
      if (fread(&entryh, sizeof(entryh), 1, fr->handle)!=1)
      {
	fr->offset_error=fr->file_size;
	fr->file_size=0;
	return;
      }
      switch(le16(entryh.value_type))
      {
	case PT_LONG:
	case PT_BOOLEAN:
	case PT_ERROR:
	case PT_NULL:
	  size=0;
	  break;
	case PT_UNICODE:
	case PT_BINARY:
	  {
	    uint32_t entry_size;
	    if (fread(&entry_size, sizeof(entry_size), 1, fr->handle)!=1)
	    {
	      fr->offset_error=fr->file_size;
	      fr->file_size=0;
	      return;
	    }
	    size=4+le32(entry_size);
	  }
	  break;
	default:
	  log_info("nk2   entry %04x size=? at 0x%llx\n",
	      le16(entryh.value_type),
	      (long long unsigned)fr->file_size);
	  fr->offset_error=fr->file_size;
	  fr->file_size=0;
	  return;
      }
#ifdef DEBUG_NK2
      {
	log_info("nk2   entry %04x size=%u at 0x%llx\n",
	    le16(entryh.value_type),
	    (unsigned int)size,
	    (long long unsigned)fr->file_size);
	char buffer[2048];
	unsigned int size_to_log=size;
	if(size_to_log>2048)
	  size_to_log=2048;
	fread(&buffer, size_to_log, 1, fr->handle);
	dump_log(&buffer, size_to_log);
      }
#endif
      fr->file_size+=sizeof(entryh);
#ifdef HAVE_FSEEKO
      if (fseeko(fr->handle, fr->file_size+size, SEEK_SET) < 0)
#else
      if (fseek(fr->handle, fr->file_size+size, SEEK_SET) < 0)
#endif
      {
	fr->offset_error=fr->file_size;
	fr->file_size=0;
	return;
      }
      fr->file_size+=size;
    }
  }
  fr->file_size+=12;
}

