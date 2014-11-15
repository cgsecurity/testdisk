/*

    File: file_ace.c

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
#include "filegen.h"
#include "common.h"
#include "log.h"
#include "crc.h"

/* #define DEBUG_ACE */

static void register_header_check_ace(file_stat_t *file_stat);

const file_hint_t file_hint_ace= {
  .extension="ace",
  .description="ACE archive",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_ace
};

struct header_ace {
  uint16_t crc16;      /** Lower 16bits of CRC32 over block up from HEAD_TYPE */
  uint16_t size;       /** Size of the block from HEAD_TYPE
                           up to the beginning of the ADDSIZE block */
  uint8_t  type;       /** indicates type of block */
  uint16_t flags;      /** flags related to the block and its content
                           for all blocks these flags are valid.
                           bit 0 indicates if field add size is preset */
  uint32_t addsize;    /** an optional field which represents the size of
                           an additional block without specified structure */
} __attribute__ ((__packed__));
typedef struct header_ace ace_header_t;

static void file_check_ace(file_recovery_t *file_recovery)
{
  file_recovery->offset_error = 0;
  file_recovery->offset_ok = 0;
  file_recovery->file_size = 0;
#ifdef HAVE_FSEEKO
  if(fseeko(file_recovery->handle, 0, SEEK_SET)<0)
#else
  if(fseek(file_recovery->handle, 0, SEEK_SET)<0)
#endif
    return ;
#ifdef DEBUG_ACE
  log_trace("file_check_ace\n");
#endif
  while (!feof(file_recovery->handle))
  {
    ace_header_t h;
    size_t res;
    memset(&h, 0, sizeof(h));
    res=fread(&h, 1, sizeof(h), file_recovery->handle);
    if(res==0)
      return ;
    if(res != sizeof(h))
    {
      file_recovery->offset_error=file_recovery->file_size;
      file_recovery->file_size=0;
      return ;
    }
#ifdef HAVE_FSEEKO
    if(fseeko(file_recovery->handle, -sizeof(h)+4, SEEK_CUR)<0)
#else
    if(fseek(file_recovery->handle, -sizeof(h)+4, SEEK_CUR)<0)
#endif
    {
      file_recovery->offset_error=file_recovery->file_size;
      file_recovery->file_size=0;
      return ;
    }

#ifdef DEBUG_ACE
    log_trace("file_ace: Block header at 0x%08lx: CRC16=0x%04X size=%u type=%u"
        " flags=0x%04X addsize=%u\n",
        (long unsigned) file_recovery->file_size,
        le16(h.crc16), le16(h.size), h.type, le16(h.flags),
        (le16(h.flags)&1) ? le32(h.addsize):0);
#endif
    /* Type 0=Archive header, 1=File block, 2=Recovery Record, 5 new_recovery ? */
    if (h.type==0 && le16(h.size)==0)
    {
      return ;
    }
    if (h.type!=0 && h.type!=1 && h.type!=2 && h.type!=5)
    {
#ifdef DEBUG_ACE
      log_trace("file_ace: Invalid block type %u\n", h.type);
#endif
      file_recovery->offset_error=file_recovery->file_size;
      file_recovery->file_size=0;
      return ;
    }

    /* Minimal size is type+flags */
    if (le16(h.size) < 1U + 2U)
    {
#ifdef DEBUG_ACE
      log_trace("file_ace: Invalid block size %u\n", le16(h.size));
#endif
      file_recovery->offset_error=file_recovery->file_size;
      file_recovery->file_size=0;
      return ;
    }

    {
      /* Header hardly ever bigger than a filename */
#define BUF_SIZE 4096
      unsigned char buffer[BUF_SIZE];
      unsigned int len=le16(h.size);
      uint32_t crc32=0xFFFFFFFF;
      while (len>0)
      {
        const unsigned int count = ((len>BUF_SIZE) ? BUF_SIZE : len);
        if(fread(buffer, 1, count, file_recovery->handle) != count)
        {
#ifdef DEBUG_ACE
          log_trace("file_ace: truncated file\n");
#endif
	  file_recovery->offset_error=file_recovery->file_size;
	  file_recovery->file_size=0;
          return ;
        }
        crc32=get_crc32(buffer, count, crc32);
	len -= count;
      }
      if (le16(h.crc16) != (crc32&0xFFFF))
      {
#ifdef DEBUG_ACE
        log_trace("file_ace: bad CRC32: %04X vs %04X\n", le16(h.crc16), crc32);
#endif
	file_recovery->offset_error=file_recovery->file_size;
	file_recovery->file_size=0;
        return ;
      }
    }
    /* Add its header size */
    file_recovery->file_size += 2U + 2 + le16(h.size);	/* +2: CRC16, +2: size */
    /* If addsize flag, add complementary size */
    if (le16(h.flags)&1)
    {
      file_recovery->file_size += le32(h.addsize);
#ifdef HAVE_FSEEKO
      if(fseeko(file_recovery->handle, file_recovery->file_size, SEEK_SET)<0)
#else
      if(fseek(file_recovery->handle, file_recovery->file_size, SEEK_SET)<0)
#endif
      {
	file_recovery->offset_error=file_recovery->file_size;
	file_recovery->file_size=0;
	return;
      }
    }
  }
}

static int header_check_ace(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const ace_header_t *h=(const ace_header_t *)buffer;
  if(le16(h->size) < 1+2 || h->type!=0)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_ace.extension;
  file_recovery_new->min_filesize=
    2 + /* CRC16 */
    2 + /* Head size */
    1 + /* Head type */
    2 + /* Flags */
    7 + /* Signature */
    16; /* Minimal size for marker header */
  file_recovery_new->file_check=&file_check_ace;
  return 1;
}

static void register_header_check_ace(file_stat_t *file_stat)
{
  static const unsigned char ace_header[7] = { '*','*','A','C','E','*','*'};
  register_header_check(7, ace_header,sizeof(ace_header), &header_check_ace, file_stat);
}
