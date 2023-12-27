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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ace)
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
#if defined(__FRAMAC__)
#include "__fc_builtin.h"
#endif

/* #define DEBUG_ACE */

/*@
  @ requires valid_register_header_check(file_stat);
  @*/
static void register_header_check_ace(file_stat_t *file_stat);

const file_hint_t file_hint_ace= {
  .extension="ace",
  .description="ACE archive",
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
} __attribute__ ((gcc_struct, __packed__));

typedef struct header_ace ace_header_t;
#define BUF_SIZE 4096

/*@
  @ requires \valid(handle);
  @ requires \separated(handle, &errno, &Frama_C_entropy_source);
  @ assigns *handle, errno;
  @ assigns Frama_C_entropy_source;
  @*/
static int check_ace_crc(FILE *handle, const unsigned int len, const unsigned int crc32_low)
{
  char buffer[BUF_SIZE];
  uint32_t crc32=0xFFFFFFFF;
  unsigned int remaining=len;
  /*@
    @ loop assigns *handle, errno;
    @ loop assigns Frama_C_entropy_source;
    @ loop assigns buffer[0 .. BUF_SIZE-1], crc32, remaining;
    @ loop variant remaining;
    @*/
  while (remaining>0)
  {
    const unsigned int count = ((remaining>BUF_SIZE) ? BUF_SIZE : remaining);
    if(fread(buffer, 1, count, handle) != count)
    {
#ifdef DEBUG_ACE
      log_info("file_ace: truncated file\n");
#endif
      return 1;
    }
#ifdef __FRAMAC__
    Frama_C_make_unknown(&buffer, sizeof(buffer));
#endif
    crc32=get_crc32(buffer, count, crc32);
    remaining -= count;
  }
  if (crc32_low != (crc32&0xFFFF))
  {
#ifdef DEBUG_ACE
    log_info("file_ace: bad CRC: %04X vs %04X\n", crc32_low, crc32&0xFFFF);
#endif
    return 1;
  }
  return 0;
}

/*@
  @ requires file_recovery->file_check == &file_check_ace;
  @ requires valid_file_check_param(file_recovery);
  @ ensures  valid_file_check_result(file_recovery);
  @ assigns *file_recovery->handle, errno, file_recovery->file_size, file_recovery->offset_error, file_recovery->offset_ok;
  @ assigns Frama_C_entropy_source;
  @*/
static void file_check_ace(file_recovery_t *file_recovery)
{
  file_recovery->offset_error = 0;
  file_recovery->offset_ok = 0;
  file_recovery->file_size = 0;
  if(my_fseek(file_recovery->handle, 0, SEEK_SET)<0)
    return ;
  /*@
    @ loop assigns *file_recovery->handle, errno, file_recovery->file_size, file_recovery->offset_error;
    @ loop assigns Frama_C_entropy_source;
    @ loop variant 0x8000000000000000-0x100000000 - file_recovery->file_size;
    @*/
  while (!feof(file_recovery->handle))
  {
    char buffer[sizeof(ace_header_t)];
    const ace_header_t *h=(const ace_header_t *)&buffer;
    if(fread(&buffer, sizeof(buffer), 1, file_recovery->handle)!= 1)
    {
      return ;
    }
    /*@ assert \initialized(&buffer + (0 .. sizeof(buffer)-1)); */
#ifdef DEBUG_ACE
    log_info("file_ace: Block header at 0x%08lx: CRC16=0x%04X size=%u type=%u"
        " flags=0x%04X addsize=%u\n",
        (long unsigned) file_recovery->file_size,
        le16(h->crc16), le16(h->size), h->type, le16(h->flags),
        (le16(h->flags)&1) ? le32(h->addsize):0);
#endif
    /* Type 0=Archive header, 1=File block, 2=Recovery Record, 5 new_recovery ? */
    if (h->type==0 && le16(h->size)==0)
    {
      return ;
    }
    if (h->type!=0 && h->type!=1 && h->type!=2 && h->type!=5)
    {
#ifdef DEBUG_ACE
      log_info("file_ace: Invalid block type %u\n", h->type);
#endif
      return ;
    }

    /* Minimal size is type+flags */
    if (le16(h->size) < 1U + 2U)
    {
#ifdef DEBUG_ACE
      log_info("file_ace: Invalid block size %u\n", le16(h->size));
#endif
      return ;
    }

    if(my_fseek(file_recovery->handle, -(off_t)sizeof(ace_header_t)+(off_t)4, SEEK_CUR)<0 ||
	check_ace_crc(file_recovery->handle, le16(h->size), le16(h->crc16)) != 0)
    {
      file_recovery->offset_error=file_recovery->file_size;
      file_recovery->file_size=0;
      return ;
    }

    /* Add its header size */
    file_recovery->file_size += (uint64_t)4 + le16(h->size);	/* +2: CRC16, +2: size */

    if(file_recovery->file_size >= 0x8000000000000000-0x100000000)
    {
      file_recovery->file_size=0;
      return ;
    }
    /* If addsize flag, add complementary size */
    if (le16(h->flags)&1)
    {
      file_recovery->file_size += le32(h->addsize);
      if(my_fseek(file_recovery->handle, file_recovery->file_size, SEEK_SET)<0)
      {
	file_recovery->offset_error=file_recovery->file_size;
	file_recovery->file_size=0;
	return;
      }
    }
  }
}

/*@
  @ requires buffer_size >= sizeof(ace_header_t);
  @ requires separation: \separated(&file_hint_ace, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ ensures (\result == 1) ==> file_recovery_new->file_size == 0;
  @ ensures (\result == 1) ==> (file_recovery_new->time == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->calculated_file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->extension == file_hint_ace.extension);
  @ ensures (\result == 1) ==> (file_recovery_new->file_check == &file_check_ace);
  @ assigns  *file_recovery_new;
  @*/
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
#endif
