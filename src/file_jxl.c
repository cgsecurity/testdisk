/*

    File: file_jxl.c

    Copyright (C) 2024 Christophe GRENIER <grenier@cgsecurity.org>

    JPEG XL specification:
    https://jpeg.org/jpegxl/

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_jxl)
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
static void register_header_check_jxl(file_stat_t *file_stat);

const file_hint_t file_hint_jxl= {
  .extension="jxl",
  .description="JPEG XL image",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_jxl
};

/*@
  @ requires buffer_size >= 2;
  @ requires separation: \separated(&file_hint_jxl, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_jxl_bare(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /* Bare codestream: starts with 0xFF 0x0A */
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_jxl.extension;
  return 1;
}

/*@
  @ requires buffer_size >= 12;
  @ requires separation: \separated(&file_hint_jxl, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_jxl_container(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /* ISOBMFF container: 12-byte signature */
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_jxl.extension;
  return 1;
}

static void register_header_check_jxl(file_stat_t *file_stat)
{
  /* Bare JPEG XL codestream */
  static const unsigned char jxl_bare[2]= { 0xFF, 0x0A };
  /* JPEG XL container (ISOBMFF-based) */
  static const unsigned char jxl_container[12]= {
    0x00, 0x00, 0x00, 0x0C,
    0x4A, 0x58, 0x4C, 0x20,
    0x0D, 0x0A, 0x87, 0x0A
  };
  register_header_check(0, jxl_bare, sizeof(jxl_bare), &header_check_jxl_bare, file_stat);
  register_header_check(0, jxl_container, sizeof(jxl_container), &header_check_jxl_container, file_stat);
}
#endif
