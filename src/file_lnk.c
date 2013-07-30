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

static void register_header_check_lnk(file_stat_t *file_stat);
static int header_check_lnk(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_lnk= {
  .extension="lnk",
  .description="MS Windows Link",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_lnk
};

static const unsigned char lnk_header[20]= {
  'L', 0x00, 0x00, 0x00,				/* magic */
  0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46	/* GUID */
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
} __attribute__ ((__packed__));

/* These constants comes from winedump/lnk.c */
#define SCF_PIDL 	1
#define SCF_LOCATION	2
#define SCF_DESCRIPTION	4
#define SCF_RELATIVE	8
#define SCF_WORKDIR	0x10
#define SCF_ARGS	0x20
#define SCF_CUSTOMICON	0x40
#define SCF_UNICODE 	0x80
#define SCF_PRODUCT 	0x800
#define SCF_COMPONENT 	0x1000
/* */

static void register_header_check_lnk(file_stat_t *file_stat)
{
  register_header_check(0, lnk_header,sizeof(lnk_header), &header_check_lnk, file_stat);
}

static int header_check_lnk(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(buffer, lnk_header, sizeof(lnk_header))==0 &&
      memcmp(&buffer[0x42], lnk_reserved, sizeof(lnk_reserved))==0)
  {
    const struct lnk_header_s* lnk_head=(const struct lnk_header_s*)buffer;
    const uint32_t flags=le32(lnk_head->flags);
    unsigned int i=0x4c;		/* .LNK File Header */
    unsigned int len;
    if((flags&SCF_PIDL)!=0)
    { /* The Shell Item Id List */
      len=buffer[i]+(buffer[i+1]<<8);
#ifdef DEBUG_LNK
      log_debug("LNK Shell Item Id List at 0x%04x=%04x\n",
	  i, len);
#endif
      i+=2;
      i+=len;
    }
    /* avoid out of bound read access */
    if(i+4>=buffer_size)
      return 0;
    if((flags&SCF_LOCATION)!=0)
    { /* File location info */
      len=buffer[i] + (buffer[i+1]<<8) + (buffer[i+2]<<16) + (buffer[i+3]<<24);
#ifdef DEBUG_LNK
      log_debug("LNK File location info at 0x%04x=%04x\n", i, len);
#endif
      i+=2;
      i+=len;
    }
    /* avoid out of bound read access */
    if(i+2>=buffer_size)
      return 0;
    if((flags&SCF_DESCRIPTION)!=0)
    { /* Description string */
      len=buffer[i]+(buffer[i+1]<<8);
#ifdef DEBUG_LNK
      log_debug("LNK description string at 0x%04x=%04x\n", i, len);
#endif
      i+=2;
      if((flags& SCF_UNICODE)!=0)
	len*=2;
      i+=len;
    }
    /* avoid out of bound read access */
    if(i+2>=buffer_size)
      return 0;
    if((flags&SCF_RELATIVE)!=0)
    { /* Relative path */
      len=buffer[i]+(buffer[i+1]<<8);
#ifdef DEBUG_LNK
      log_debug("LNK relative path at 0x%04x=%04x\n", i, len);
#endif
      i+=2;
      if((flags& SCF_UNICODE)!=0)
	len*=2;
      i+=len;
    }
    /* avoid out of bound read access */
    if(i+2>=buffer_size)
      return 0;
    if((flags&SCF_WORKDIR)!=0)
    { /* Working directory */
      len=buffer[i]+(buffer[i+1]<<8);
#ifdef DEBUG_LNK
      log_debug("LNK Working directory at 0x%04x=%04x\n", i, len);
#endif
      i+=2;
      if((flags& SCF_UNICODE)!=0)
	len*=2;
      i+=len;
    }
    /* avoid out of bound read access */
    if(i+2>=buffer_size)
      return 0;
    if((flags&SCF_ARGS)!=0)
    { /* Command line string */
      len=buffer[i]+(buffer[i+1]<<8);
#ifdef DEBUG_LNK
      log_debug("LNK Command line string at 0x%04x=%04x\n", i, len);
#endif
      i+=2;
      if((flags& SCF_UNICODE)!=0)
	len*=2;
      i+=len;
    }
    /* avoid out of bound read access */
    if(i+2>=buffer_size)
      return 0;
    if((flags&SCF_CUSTOMICON)!=0)
    { /* Icon filename string */
      len=buffer[i]+(buffer[i+1]<<8);
#ifdef DEBUG_LNK
      log_debug("LNK Icon filename string at 0x%04x=%04x\n", i, len);
#endif
      i+=2;
      if((flags& SCF_UNICODE)!=0)
	len*=2;
      i+=len;
    }
    /* avoid out of bound read access */
    if(i+2>=buffer_size)
      return 0;
    if((flags&SCF_PRODUCT)!=0)
    {
      len=buffer[i]+(buffer[i+1]<<8);
#ifdef DEBUG_LNK
      log_debug("LNK Icon product at 0x%04x=%04x\n", i, len);
#endif
      i+=2;
      i+=len;
    }
    /* avoid out of bound read access */
    if(i+2>=buffer_size)
      return 0;
    if((flags&SCF_COMPONENT)!=0)
    {
      len=buffer[i]+(buffer[i+1]<<8);
#ifdef DEBUG_LNK
      log_debug("LNK Icon component at 0x%04x=%04x\n", i, len);
#endif
      i+=2;
      i+=len;
    }
    /* avoid out of bound read access */
    if(i+4>=buffer_size)
      return 0;
    /* Extra stuff */
    len=buffer[i] + (buffer[i+1]<<8) + (buffer[i+2]<<16) + (buffer[i+3]<<24);
#ifdef DEBUG_LNK
    log_debug("LNK extra stuff at 0x%04x=%04x\n", i, len);
#endif
    i+=4;
    i+=len;
#ifdef DEBUG_LNK
    log_debug("LNK size %u (0x%04x)\n", i, i);
#endif
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_lnk.extension;
    file_recovery_new->calculated_file_size=i;
    file_recovery_new->data_check=&data_check_size;
    file_recovery_new->file_check=&file_check_size;
//    file_recovery_new->time=td_ntfs2utc(le64(lnk_head->ctime));
    return 1;
  }
  return 0;
}
