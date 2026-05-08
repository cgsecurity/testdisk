/*

    File: file_safetensors.c

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_safetensors)
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
static void register_header_check_safetensors(file_stat_t *file_stat);

const file_hint_t file_hint_safetensors= {
  .extension="safetensors",
  .description="HuggingFace SafeTensors",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_safetensors
};

/*@
  @ requires buffer_size >= 10;
  @ requires separation: \separated(&file_hint_safetensors, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_safetensors(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /* https://github.com/huggingface/safetensors
   * Offset 0: header_length (uint64 LE)
   * Offset 8: JSON header (header_length bytes), must start with '{'
   * The JSON header contains tensor metadata.
   * LoRA adapters are also stored as safetensors.
   */
  const uint64_t header_length=le64(*(const uint64_t *)buffer);
  /* Header must be reasonable: at least 2 bytes (for '{}'), at most 100MB */
  if(header_length < 2 || header_length > 100*1024*1024)
    return 0;
  /* First byte of JSON must be '{' */
  if(buffer[8] != '{')
    return 0;
  /* If the full header is within buffer, check it ends with '}' */
  if(8 + header_length <= buffer_size)
  {
    if(buffer[8 + header_length - 1] != '}')
      return 0;
  }
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_safetensors.extension;
  file_recovery_new->min_filesize=(uint64_t)8 + header_length;
  return 1;
}

static void register_header_check_safetensors(file_stat_t *file_stat)
{
  /* SafeTensors has no fixed magic. The first 8 bytes are a LE uint64
   * header length. We register a 1-byte check for '{' at offset 8,
   * which is the start of the JSON metadata header. */
  static const unsigned char safetensors_json_start[1]= { '{' };
  register_header_check(8, safetensors_json_start, sizeof(safetensors_json_start), &header_check_safetensors, file_stat);
}
#endif
