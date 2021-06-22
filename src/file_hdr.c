/*

    File: file_hdr.c

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_hdr)
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

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_hdr(file_stat_t *file_stat);

const file_hint_t file_hint_hdr= {
  .extension="hdr",
  .description="InstallShield",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_hdr
};

struct hdr_header {
  uint32_t magic;
  uint16_t unk1;
  uint16_t val0100;
  uint32_t val00000000;
  uint16_t val0200;
  uint16_t val0000;
  uint16_t unk2;	/* 0 if cab */
  uint16_t val0000_bis;
  uint32_t filesize;	/* 0x200 if cab */
  uint32_t val00000000_bis;
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires buffer_size >= sizeof(struct hdr_header);
  @ requires separation: \separated(&file_hint_hdr, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_hdr(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct hdr_header *hdr=(const struct hdr_header*)buffer;
  const unsigned int filesize=le32(hdr->filesize);
  if(le16(hdr->val0100)!=0x100)
    return 0;
  if(le32(hdr->val00000000)!=0)
    return 0;
  reset_file_recovery(file_recovery_new);
  if(le16(hdr->unk2)==0 && filesize==0x200)
  {
    file_recovery_new->extension="cab";
    file_recovery_new->min_filesize=0x200;
    return 1;
  }
  file_recovery_new->extension=file_hint_hdr.extension;
  file_recovery_new->calculated_file_size=filesize;
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static void register_header_check_hdr(file_stat_t *file_stat)
{
  register_header_check(0, "ISc(", 4, &header_check_hdr, file_stat);
}
#endif
