/*

    File: file_indd.c

    Copyright (C) 2007 Christophe GRENIER <grenier@cgsecurity.org>
    Copyright (C) 2007 Peter Turczak <pnospamt@netconsequence.de>
  
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
#include "common.h"
#include "filegen.h"
#include "log.h"

struct indd_header_s {
  unsigned char   id[24];
  unsigned char   unknown[256];
  uint32_t 	  blocks;    /* Little Endian block count, one block is 4096 byte, note that headblocks need to be added in order to have the actual file length */
  char           headblocks;
} __attribute__ ((__packed__));
typedef struct indd_header_s indd_header_t;


static void register_header_check_indd(file_stat_t *file_stat);
static int header_check_indd(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);
static void file_check_indd(file_recovery_t *file_recovery);

const file_hint_t file_hint_indd= {
  .extension="indd",
  .description="InDesign File",
  .min_header_distance=8192,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_indd
};

static const unsigned char indd_header[24]={
  0x06, 0x06, 0xed, 0xf5, 0xd8, 0x1d, 0x46, 0xe5,
  0xbd, 0x31, 0xef, 0xe7, 0xfe, 0x74, 0xb7, 0x1d,
  0x44, 0x4f, 0x43, 0x55, 0x4d, 0x45, 0x4e, 0x54 };

static void register_header_check_indd(file_stat_t *file_stat)
{
  register_header_check(0, indd_header,sizeof(indd_header), &header_check_indd, file_stat);
}

static int header_check_indd(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const indd_header_t *hdr = (const indd_header_t *)buffer;
  if (memcmp(hdr->id,indd_header,sizeof(indd_header))==0)
  {
    reset_file_recovery(file_recovery_new);
#ifdef DJGPP
    file_recovery_new->extension="ind";
#else
    file_recovery_new->extension=file_hint_indd.extension;
#endif
    file_recovery_new->calculated_file_size=(uint64_t)(1+le32(hdr->blocks))*4096;
    file_recovery_new->file_check=&file_check_indd;
//    log_debug("header_check_indd: Guessed length: %lu.\n", indd_file_size);
    return 1;
  }
  return 0;
}

static void file_check_indd(file_recovery_t *file_recovery)
{
  if(file_recovery->file_size<file_recovery->calculated_file_size)
    file_recovery->file_size=0;
  else if(file_recovery->file_size>file_recovery->calculated_file_size+10*4096)
    file_recovery->file_size=file_recovery->calculated_file_size+10*4096;
}
