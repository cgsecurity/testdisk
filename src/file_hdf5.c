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
#ifdef DEBUG_HDF5
#include "log.h"
#endif

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_hdf5(file_stat_t *file_stat);

const file_hint_t file_hint_hdf5= {
  .extension="h5",
  .description="Hierarchical Data Format 5",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_hdf5
};

struct hdf5_superblock
{
  uint8_t signature[8];
  uint8_t version;
  uint8_t version_global_free_space_storage;
  uint8_t version_root_group_symbol_table_entry;
  uint8_t reserved;
  uint8_t version_shared_header_message_format;
  uint8_t offsets_size;
  uint8_t lengths_size;
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires \separated(file_recovery, file_recovery->handle, &errno, &Frama_C_entropy_source, &__fc_heap_status);
  @ requires valid_file_check_param(file_recovery);
  @ ensures  valid_file_check_result(file_recovery);
  @*/
static void file_check_hdf5_0(file_recovery_t *file_recovery)
{
  const uint8_t eof_address_offset = 0x18 + 2*8;
  FILE *handle = file_recovery->handle;
  uint64_t eof_address = 0;
  /* Get EOF Address */
  if (my_fseek(handle, eof_address_offset, SEEK_SET) < 0 ||
      fread(&eof_address, sizeof(eof_address), 1, handle) != 1)
  {
#ifdef DEBUG_HDF5
    log_error("file_check_hdf5_0: Couldn't read HDF End of File Address");
#endif
    file_recovery->file_size=0;
    return;
  }
  eof_address = le64(eof_address);
#ifdef DEBUG_HDF5
  log_info("file_check_hdf5_0: dec eof_address = %lu\n", (long unsigned)eof_address);
  log_info("file_check_hdf5_0: hex eof_address = 0x%02lX\n", eof_address);
#endif
  if(eof_address < eof_address_offset || eof_address < file_recovery->file_size)
  {
    file_recovery->file_size=0;
    return;
  }
  file_recovery->file_size=eof_address;
}

/*@
  @ requires \separated(file_recovery, file_recovery->handle, &errno, &Frama_C_entropy_source, &__fc_heap_status);
  @ requires valid_file_check_param(file_recovery);
  @ ensures  valid_file_check_result(file_recovery);
  @*/
static void file_check_hdf5_1(file_recovery_t *file_recovery)
{
  const uint8_t eof_address_offset = 0x1C + 2*0x8;
  FILE *handle = file_recovery->handle;
  uint64_t eof_address = 0;
  /* Get EOF Address */
  if (my_fseek(handle, eof_address_offset, SEEK_SET) < 0 ||
      fread(&eof_address, sizeof(eof_address), 1, handle) != 1)
  {
#ifdef DEBUG_HDF5
    log_error("file_check_hdf5_1: Couldn't read HDF End of File Address");
#endif
    file_recovery->file_size=0;
    return;
  }
  eof_address = le64(eof_address);
#ifdef DEBUG_HDF5
  log_info("file_check_hdf5_1: dec eof_address = %lu\n", (long unsigned)eof_address);
  log_info("file_check_hdf5_1: hex eof_address = 0x%02lX\n", eof_address);
#endif
  if(eof_address < eof_address_offset || eof_address < file_recovery->file_size)
  {
    file_recovery->file_size=0;
    return;
  }
  file_recovery->file_size=eof_address;
}

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
  if(sb->offsets_size != 8)
    return 1;
  /* Currently only handle 64-bits offsets */
  if(sb->version == 0)
    file_recovery_new->file_check=&file_check_hdf5_0;
  else
    file_recovery_new->file_check=&file_check_hdf5_1;
  return 1;
}

static void register_header_check_hdf5(file_stat_t *file_stat)
{
  static const unsigned char hdf5_header[8]=  { 0x89, 'H', 'D', 'F', '\r', '\n', 0x1a, '\n'};
  register_header_check(0, hdf5_header, sizeof(hdf5_header), &header_check_hdf5, file_stat);
}
#endif
