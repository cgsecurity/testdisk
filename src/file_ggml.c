/*

    File: file_ggml.c

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
    with this program; if not, write the Free Software Foundation, Inc., 51
    Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

 */

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ggml)
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
static void register_header_check_ggml(file_stat_t *file_stat);

const file_hint_t file_hint_ggml= {
  .extension="ggml",
  .description="GGML LLM Model",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_ggml
};

/*@
  @ requires buffer_size >= 8;
  @ requires separation: \separated(&file_hint_ggml, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_ggml(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /* https://github.com/ggerganov/ggml
   * Original GGML: magic stored as LE uint32
   * GGMF (v1): versioned format, version at offset 4
   * GGJT: aligned tensors, version at offset 4
   */
  const uint32_t magic=le32(*(const uint32_t *)buffer);
  if(magic == 0x67676d66)	/* GGMF */
  {
    const uint32_t version=le32(*(const uint32_t *)&buffer[4]);
    if(version != 1)
      return 0;
  }
  else if(magic == 0x746a6767)	/* GGJT */
  {
    const uint32_t version=le32(*(const uint32_t *)&buffer[4]);
    if(version < 1 || version > 3)
      return 0;
  }
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_ggml.extension;
  return 1;
}

static void register_header_check_ggml(file_stat_t *file_stat)
{
  /* Original GGML: bytes are 'l','m','g','g' (LE uint32 0x67676d6c) */
  static const unsigned char ggml_header[4]= { 0x6c, 0x6d, 0x67, 0x67 };
  /* GGMF: bytes are 'f','m','g','g' (LE uint32 0x67676d66) */
  static const unsigned char ggmf_header[4]= { 0x66, 0x6d, 0x67, 0x67 };
  /* GGJT: bytes are 'g','g','j','t' (LE uint32 0x746a6767) */
  static const unsigned char ggjt_header[4]= { 0x67, 0x67, 0x6a, 0x74 };
  register_header_check(0, ggml_header, sizeof(ggml_header), &header_check_ggml, file_stat);
  register_header_check(0, ggmf_header, sizeof(ggmf_header), &header_check_ggml, file_stat);
  register_header_check(0, ggjt_header, sizeof(ggjt_header), &header_check_ggml, file_stat);
}
#endif
