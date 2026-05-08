/*

    File: file_pt.c

    Copyright (C) 2024 Christophe GRENIER <grenier@cgsecurity.org>

    This software is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc., 51
    Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

 */

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pt)
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
static void register_header_check_pt(file_stat_t *file_stat);

const file_hint_t file_hint_pt= {
  .extension="pt",
  .description="PyTorch Model",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_pt
};

/*@
  @ requires buffer_size >= 512;
  @ requires separation: \separated(&file_hint_pt, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_pt(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /* PyTorch models saved via torch.save() use Python pickle format.
   * They start with pickle protocol opcode: \x80 followed by protocol version (2-5).
   * To distinguish from generic pickles, search for "torch" in the first 512 bytes.
   */
  unsigned int i;
  const unsigned int search_len = buffer_size < 512 ? buffer_size : 512;
  for(i=0; i < search_len - 4; i++)
  {
    if(buffer[i]=='t' && buffer[i+1]=='o' && buffer[i+2]=='r' && buffer[i+3]=='c' && buffer[i+4]=='h')
    {
      reset_file_recovery(file_recovery_new);
      file_recovery_new->extension=file_hint_pt.extension;
      return 1;
    }
  }
  return 0;
}

static void register_header_check_pt(file_stat_t *file_stat)
{
  /* Pickle protocol 2-5 all start with \x80 followed by version byte */
  static const unsigned char pickle_proto2[2]= { 0x80, 0x02 };
  static const unsigned char pickle_proto3[2]= { 0x80, 0x03 };
  static const unsigned char pickle_proto4[2]= { 0x80, 0x04 };
  static const unsigned char pickle_proto5[2]= { 0x80, 0x05 };
  register_header_check(0, pickle_proto2, sizeof(pickle_proto2), &header_check_pt, file_stat);
  register_header_check(0, pickle_proto3, sizeof(pickle_proto3), &header_check_pt, file_stat);
  register_header_check(0, pickle_proto4, sizeof(pickle_proto4), &header_check_pt, file_stat);
  register_header_check(0, pickle_proto5, sizeof(pickle_proto5), &header_check_pt, file_stat);
}
#endif
