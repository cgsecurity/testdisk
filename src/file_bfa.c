/*

    File: file_bfa.c

    Copyright (C) 2019 Christophe GRENIER <grenier@cgsecurity.org>

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_bfa)
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

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_bfa(file_stat_t *file_stat);

const file_hint_t file_hint_bfa= {
  .extension="bfa",
  .description="Blowfish Advanced CS",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_bfa
};

struct bfa_header
{
  uint32_t	lMagic;
  uint16_t	wSizeOfHeader;
  uint16_t	wVersion;
  uint64_t	lLength;
  uint16_t	wCipherInitDataSize;
  uint16_t	wCipherBlockSize;
  uint8_t	salt[11];
  uint32_t	lKeyHash;
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires buffer_size >= sizeof(struct bfa_header);
  @ requires separation: \separated(&file_hint_bfa, buffer, file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_bfa(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct bfa_header *header=(const struct bfa_header*)buffer;
  uint64_t size=le64(header->lLength);
  if(size > PHOTOREC_MAX_FILE_SIZE)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_bfa.extension;
  file_recovery_new->calculated_file_size=size + le16(header->wSizeOfHeader);
  file_recovery_new->file_check=&file_check_size_min;
  return 1;
}

static void register_header_check_bfa(file_stat_t *file_stat)
{
  static const unsigned char bfa_header[8]=  {
    0x24, 0x08, 0x19, 0x92, 0x23, 0x00, 0x15, 0x01
  };
  register_header_check(0, bfa_header, sizeof(bfa_header), &header_check_bfa, file_stat);
}
#endif
