/*

    File: file_berkeley.c

    Copyright (C) 2013 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_berkeley)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "filegen.h"

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_berkeley_le(file_stat_t *file_stat);

const file_hint_t file_hint_berkeley= {
  .extension="db",
  .description="Berkeley DB (Little Endian)",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_berkeley_le
};

/*@
  @ requires separation: \separated(&file_hint_berkeley, buffer, file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_berkeley_le(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_berkeley.extension;
  file_recovery_new->min_filesize=0xC+8;
  return 1;
}

static void register_header_check_berkeley_le(file_stat_t *file_stat)
{
#if 0
  static unsigned char berkeley_db_hash_4[8]={0x61, 0x15, 0x06, 0x00, 0x04, 0x00, 0x00, 0x00};
  static unsigned char berkeley_db_hash_5[8]={0x61, 0x15, 0x06, 0x00, 0x05, 0x00, 0x00, 0x00};
  static unsigned char berkeley_db_hash_6[8]={0x61, 0x15, 0x06, 0x00, 0x06, 0x00, 0x00, 0x00};
  static unsigned char berkeley_db_hash_7[8]={0x61, 0x15, 0x06, 0x00, 0x07, 0x00, 0x00, 0x00};
#endif
  static unsigned char berkeley_db_hash_8[8]={0x61, 0x15, 0x06, 0x00, 0x08, 0x00, 0x00, 0x00};
  static unsigned char berkeley_db_hash_9[8]={0x61, 0x15, 0x06, 0x00, 0x09, 0x00, 0x00, 0x00};
#if 0
  static unsigned char berkeley_db_btree_4[8]={0x62, 0x31, 0x05, 0x00, 0x04, 0x00, 0x00, 0x00};
  static unsigned char berkeley_db_btree_5[8]={0x62, 0x31, 0x05, 0x00, 0x05, 0x00, 0x00, 0x00};
  static unsigned char berkeley_db_btree_6[8]={0x62, 0x31, 0x05, 0x00, 0x06, 0x00, 0x00, 0x00};
  static unsigned char berkeley_db_btree_7[8]={0x62, 0x31, 0x05, 0x00, 0x07, 0x00, 0x00, 0x00};
#endif
  static unsigned char berkeley_db_btree_8[8]={0x62, 0x31, 0x05, 0x00, 0x08, 0x00, 0x00, 0x00};
  static unsigned char berkeley_db_btree_9[8]={0x62, 0x31, 0x05, 0x00, 0x09, 0x00, 0x00, 0x00};
  register_header_check(0xC, berkeley_db_hash_8, 8, &header_check_berkeley_le, file_stat);
#ifndef DISABLED_FOR_FRAMAC
  register_header_check(0xC, berkeley_db_hash_9, 8, &header_check_berkeley_le, file_stat);
  register_header_check(0xC, berkeley_db_btree_8, 8, &header_check_berkeley_le, file_stat);
  register_header_check(0xC, berkeley_db_btree_9, 8, &header_check_berkeley_le, file_stat);
#endif
}
#endif
