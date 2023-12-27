/*

    File: file_lnk.c

    Copyright (C) 2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_lnk)
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
#ifdef DEBUG_LNK
#include "log.h"
#endif

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_lnk(file_stat_t *file_stat);

const file_hint_t file_hint_lnk= {
  .extension="lnk",
  .description="MS Windows Link",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_lnk
};


static const unsigned char lnk_reserved[10]= {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

struct lnk_header_s {
  uint32_t magic; 		/* 0h Always 0000004Ch ‘L’ */
  char     guid[16]; 		/* 4h GUID of shortcut files */
  uint32_t flags; 		/* 14h  */
  uint32_t file_attributes; 	/* 18h  */
  uint64_t ctime; 		/* 1Ch */
  uint64_t atime; 		/* 24h */
  uint64_t mtime; 		/* 2Ch */
  uint32_t file_length; 	/* 34h */
  uint32_t icon_number; 	/* 38h */
  uint32_t showWnd_value; 	/* 3Ch */
  uint32_t hot_key; 		/* 40h */
  uint64_t always_zero; 	/* 44h */
} __attribute__ ((gcc_struct, __packed__));

/* These constants comes from winedump/lnk.c */
#define SLDF_HAS_ID_LIST 	1
#define SLDF_HAS_LINK_INFO	2
#define SLDF_HAS_NAME	4
#define SLDF_HAS_RELPATH	8
#define SLDF_HAS_WORKINGDIR	0x10
#define SLDF_HAS_ARGS	0x20
#define SLDF_HAS_ICONLOCATION	0x40
#define SLDF_UNICODE 	0x80
#define SLDF_HAS_LOGO3ID 	0x800
#define SLDF_HAS_DARWINID 	0x1000

/*@
  @ requires buffer_size > 0x4c;
  @ requires \valid_read(buffer + (0 .. buffer_size-1));
  @ terminates \true;
  @ assigns \nothing;
  @*/
static unsigned int lnk_get_size(const unsigned char *buffer, const unsigned int buffer_size)
{
  const struct lnk_header_s* lnk_head=(const struct lnk_header_s*)buffer;
  const uint32_t flags=le32(lnk_head->flags);
  unsigned int i=0x4c;		/* .LNK File Header */
  /* avoid out of bound read access */
  if(i >= buffer_size - 4)
    return 0;
  if((flags&SLDF_HAS_ID_LIST)!=0)
  { /* The Shell Item Id List */
    const uint16_t *ptr=(const uint16_t *)&buffer[i];
    const unsigned int len=le16(*ptr);
#ifdef DEBUG_LNK
    log_debug("LNK Shell Item Id List at 0x%04x=%04x\n",
	i, len);
#endif
    i+=2;
    i+=len;
  }
  /* avoid out of bound read access */
  if(i >= buffer_size - 4)
    return 0;
  if((flags&SLDF_HAS_LINK_INFO)!=0)
  { /* File location info */
    const uint32_t *ptr=(const uint32_t *)&buffer[i];
    const unsigned int len=le32(*ptr);
#ifdef DEBUG_LNK
    log_debug("LNK File location info at 0x%04x %u bytes\n", i, len);
#endif
    /* Discard too big files, avoid overflow */
    if(len >= 0x10000000)
      return 0;
    i+=len;
  }
  /* avoid out of bound read access */
  if(i >= buffer_size - 2)
    return 0;
  if((flags&SLDF_HAS_NAME)!=0)
  { /* Description string */
    const uint16_t *ptr=(const uint16_t *)&buffer[i];
    unsigned int len=le16(*ptr);
    if((flags& SLDF_UNICODE)!=0)
      len*=2;
    i+=2;
#ifdef DEBUG_LNK
    log_debug("LNK description string at 0x%04x %u bytes\n", i, len);
#endif
    i+=len;
  }
  /* avoid out of bound read access */
  if(i >= buffer_size - 2)
    return 0;
  if((flags&SLDF_HAS_RELPATH)!=0)
  { /* Relative path */
    const uint16_t *ptr=(const uint16_t *)&buffer[i];
    unsigned int len=le16(*ptr);
    if((flags& SLDF_UNICODE)!=0)
      len*=2;
    i+=2;
#ifdef DEBUG_LNK
    log_debug("LNK relative path at 0x%04x=%04x\n", i, len);
#endif
    i+=len;
  }
  /* avoid out of bound read access */
  if(i >= buffer_size - 2)
    return 0;
  if((flags&SLDF_HAS_WORKINGDIR)!=0)
  { /* Working directory */
    const uint16_t *ptr=(const uint16_t *)&buffer[i];
    unsigned int len=le16(*ptr);
    if((flags& SLDF_UNICODE)!=0)
      len*=2;
    i+=2;
#ifdef DEBUG_LNK
    log_debug("LNK Working directory at 0x%04x %u bytes\n", i, len);
#endif
    i+=len;
  }
  /* avoid out of bound read access */
  if(i >= buffer_size - 2)
    return 0;
  if((flags&SLDF_HAS_ARGS)!=0)
  { /* Command line string */
    const uint16_t *ptr=(const uint16_t *)&buffer[i];
    unsigned int len=le16(*ptr);
    if((flags& SLDF_UNICODE)!=0)
      len*=2;
    i+=2;
#ifdef DEBUG_LNK
    log_debug("LNK Command line string at 0x%04x %u bytes\n", i, len);
#endif
    i+=len;
  }
  /* avoid out of bound read access */
  if(i >= buffer_size - 2)
    return 0;
  if((flags&SLDF_HAS_ICONLOCATION)!=0)
  { /* Icon filename string */
    const uint16_t *ptr=(const uint16_t *)&buffer[i];
    unsigned int len=le16(*ptr);
    if((flags& SLDF_UNICODE)!=0)
      len*=2;
    i+=2;
#ifdef DEBUG_LNK
    log_debug("LNK Icon filename string at 0x%04x=%04x\n", i, len);
#endif
    i+=len;
  }
  /* avoid out of bound read access */
  if(i >= buffer_size - 2)
    return 0;
  /*@
    @ loop invariant i < buffer_size-2;
    @ loop assigns i;
    @ loop variant buffer_size-2 - i;
    @*/
  while(1)
  {
    /* avoid out of bound read access */
    const uint16_t *ptr;
    unsigned int len;
    ptr=(const uint16_t *)&buffer[i];
    /*@ assert \valid_read(ptr); */
    len=le16(*ptr);
#ifdef DEBUG_LNK
    log_debug("LNK 0x%04x - %u bytes\n", i, len);
#endif
    if(len == 0)
    {
#ifdef DEBUG_LNK
      log_debug("LNK size %u (0x%04x)\n", i, i);
#endif
      return i;
    }
    i+=2;
    if(i >= buffer_size - 2)
      return 0;
  }
}

/*@
  @ requires buffer_size >= 0x4c;
  @ requires separation: \separated(&file_hint_lnk, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_lnk(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  unsigned int len;
  if(memcmp(&buffer[0x42], lnk_reserved, sizeof(lnk_reserved))!=0)
    return 0;
  len=lnk_get_size(buffer, buffer_size);
  if(len < 0x4c || len > 1048576)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_lnk.extension;
  file_recovery_new->calculated_file_size=len;
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  //    file_recovery_new->time=td_ntfs2utc(le64(lnk_head->ctime));
  return 1;
}

static void register_header_check_lnk(file_stat_t *file_stat)
{
  static const unsigned char lnk_header[20]= {
    'L', 0x00, 0x00, 0x00,				/* magic */
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46	/* GUID */
  };
  register_header_check(0, lnk_header,sizeof(lnk_header), &header_check_lnk, file_stat);
}
#endif
