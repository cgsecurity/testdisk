/*

    File: file_npy.c

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_npy)
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
static void register_header_check_npy(file_stat_t *file_stat);

const file_hint_t file_hint_npy= {
  .extension="npy",
  .description="NumPy Array",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_npy
};

/*@
  @ requires buffer_size >= 12;
  @ requires separation: \separated(&file_hint_npy, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_npy(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /* https://numpy.org/doc/stable/reference/generated/numpy.lib.format.html
   * Offset 0: magic \x93NUMPY (6 bytes)
   * Offset 6: major version (1, 2, or 3)
   * Offset 7: minor version (0)
   * Offset 8: HEADER_LEN (2 bytes LE for v1, 4 bytes LE for v2/v3)
   * After: Python dict literal with 'descr', 'fortran_order', 'shape'
   */
  const unsigned char major=buffer[6];
  const unsigned char minor=buffer[7];
  if(major < 1 || major > 3)
    return 0;
  if(minor != 0)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_npy.extension;
  if(major == 1)
  {
    /* v1: 10 bytes fixed header + HEADER_LEN */
    const uint16_t header_len=le16(*(const uint16_t *)&buffer[8]);
    file_recovery_new->min_filesize=(uint64_t)10 + header_len;
  }
  else
  {
    /* v2/v3: 12 bytes fixed header + HEADER_LEN */
    const uint32_t header_len=le32(*(const uint32_t *)&buffer[8]);
    file_recovery_new->min_filesize=(uint64_t)12 + header_len;
  }
  return 1;
}

static void register_header_check_npy(file_stat_t *file_stat)
{
  static const unsigned char npy_header[6]= { 0x93, 'N', 'U', 'M', 'P', 'Y' };
  register_header_check(0, npy_header, sizeof(npy_header), &header_check_npy, file_stat);
}
#endif
