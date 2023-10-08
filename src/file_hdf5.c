/*

    File: file_hdf5.c

    Copyright (C) 2022 Christophe GRENIER <grenier@cgsecurity.org>

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_hdf5)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "filegen.h"
#include "common.h"
#ifdef DEBUG_HDF
#include "log.h"
#endif

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_hdf5(file_stat_t *file_stat);

const file_hint_t file_hint_hdf5= {
  .extension="hdf",
  .description="Hierarchical Data Format 5",
  .max_filesize=PHOTOREC_MAX_SIZE_32,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_hdf5
};

struct hdf5_superblock
{
  uint8_t signature[8];
  uint8_t version;
};

/*@
  @ requires buffer_size >= sizeof(struct hdf5_superblock);
  @ requires separation: \separated(&file_hint_hdf5, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_hdf5(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct hdf5_superblock *sb=(const struct hdf5_superblock*)&buffer[0];
  /*@ assert \valid_read(sb); */
  if(sb->version > 2)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_hdf5.extension;
  return 1;
}

static void register_header_check_hdf5(file_stat_t *file_stat)
{
  static const unsigned char hdf5_header[8]=  { 0x89, 'H', 'D', 'F', '\r', '\n', 0x1a, '\n'};
  register_header_check(0, hdf5_header, sizeof(hdf5_header), &header_check_hdf5, file_stat);
}
#endif
