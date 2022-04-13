/*

    File: file_ibd.c

    Copyright (C) 2015 Christophe GRENIER <grenier@cgsecurity.org>

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ibd)
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

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_ibd(file_stat_t *file_stat);

const file_hint_t file_hint_ibd= {
  .extension="ibd",
  .description="InnoDB database file",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_ibd
};

#define FSP_HEADER_OFFSET       38
#define FSP_SPACE_FLAGS         16      /* fsp_space_t.flags, similar to dict_table_t::flags */
#define FIL_PAGE_TYPE_FSP_HDR	8	/* File space header */
#define DICT_TF_BITS            6       /* number of flag bits */
#define DICT_TF_FORMAT_SHIFT    5       /* file format */
#ifdef DISABLED_FOR_FRAMAC
#define DICT_TF_FORMAT_MASK     0x20
#else
#define DICT_TF_FORMAT_MASK     \
  ((~(~0U << (DICT_TF_BITS - DICT_TF_FORMAT_SHIFT))) << DICT_TF_FORMAT_SHIFT)
#endif
#define DICT_TF_FORMAT_ZIP      1       /* InnoDB plugin for 5.1: compressed tables */

struct innodb_fil_header
{
  uint32_t space_or_chksum;
  uint32_t offset;
  uint32_t prev;
  uint32_t next;
  uint64_t lsn;
  uint16_t type;
  uint64_t file_flush_lsn;
  uint32_t arch_log_no_or_space_id;
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires buffer_size >= sizeof(struct innodb_fil_header);
  @ requires buffer_size >  FSP_HEADER_OFFSET + FSP_SPACE_FLAGS;
  @ requires separation: \separated(&file_hint_ibd, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_ibd(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct innodb_fil_header *hdr=(const struct innodb_fil_header *)buffer;
  const uint32_t *flags_ptr=(const uint32_t *)&buffer[FSP_HEADER_OFFSET + FSP_SPACE_FLAGS];
  const uint32_t flags=be32(*flags_ptr);
  if(be16(hdr->type)==0)
  {
    /* Antelope (pre-5.1.7) */
    if(flags==0)
      return 0;
  }
  else if(be16(hdr->type)==FIL_PAGE_TYPE_FSP_HDR)
  {
    const unsigned int format = (flags & DICT_TF_FORMAT_MASK) >> DICT_TF_FORMAT_SHIFT;
    if(flags==0)
    {
      /* Antelope (5.1.7 or newer) */
    }
    else if(format==DICT_TF_FORMAT_ZIP)
    {
      /* Barracuda */
    }
    else
      return 0;
  }
  else
    return 0;
  if(buffer_size >= 0xc078 && memcmp(&buffer[0xc070], "supremum", 8)!=0)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_ibd.extension;
  file_recovery_new->min_filesize=0xc078;
  return 1;
}

static void register_header_check_ibd(file_stat_t *file_stat)
{
  register_header_check(0xc063, "infimum", 7, &header_check_ibd, file_stat);
}
#endif
