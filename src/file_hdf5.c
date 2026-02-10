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
  // if version == 0, Base Address etc start at offset 24, if version >1 at offset 28
  // Offset Base Address = (bool)version*4 + 24 + 0*offsets_size
  // Offset Address of Global Free-Space Heap = (bool)version*4 + 24 + 1*offset_size
  // Offset End of File Address = (bool)version*4 + 24 + 2*offset_size
  // Size of End of File Address = offset_size
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires \separated(file_recovery, file_recovery->handle, &errno, &Frama_C_entropy_source, &__fc_heap_status);
  @ requires valid_file_check_param(file_recovery);
  @ ensures  valid_file_check_result(file_recovery);
  @*/
static void file_check_hdf5(file_recovery_t *file_recovery)
{
#ifdef DEBUG_HDF5
  log_info("HDF5: file_check_hdf5\n");
#endif
  FILE *handle = file_recovery->handle;

  uint8_t sb_version_offset = 8;
  uint8_t sb_offset_size_offset = 0x0D;
  uint8_t sb_meta_base_address_offset = 0x1C;
  /* Get superblock version */
  my_fseek(handle, sb_version_offset, SEEK_SET);
  uint8_t sb_version = 0;
  fread(&sb_version, 1, 1, handle);
#ifdef DEBUG_HDF5
  log_info("HDF5: file_check_hdf5: superblock version = %u\n", sb_version);
#endif
  /* Adjust sb_meta_base_address_offset if necessary */
  if (!sb_version)
    sb_meta_base_address_offset = 0x18;
#ifdef DEBUG_HDF5
  log_info("HDF5: file_check_hdf5: dec sb_meta_base_address_offset = %u\n", sb_meta_base_address_offset);
  log_info("HDF5: file_check_hdf5: hex sb_meta_base_address_offset = 0x%02X\n", sb_meta_base_address_offset);
#endif
  /* Get size of offsets */
  my_fseek(handle, sb_offset_size_offset, SEEK_SET);
  uint8_t sb_offset_size = 0;
  fread(&sb_offset_size, 1, 1, handle);
#ifdef DEBUG_HDF5
  log_info("HDF5: file_check_hdf5: sb_offset_size = %u\n", sb_offset_size);
#endif
  /* Get EOF Address */
  uint8_t eof_address_offset = sb_meta_base_address_offset + 2*sb_offset_size;
  my_fseek(handle, eof_address_offset, SEEK_SET);
  uint64_t eof_address = 0;
  fread(&eof_address, sb_offset_size, 1, handle);
#ifdef DEBUG_HDF5
  log_info("HDF5: file_check_hdf5: dec eof_address = %lu\n", (long unsigned)eof_address);
  log_info("HDF5: file_check_hdf5: hex eof_address = 0x%02lX\n", eof_address);
#endif
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
#ifdef DEBUG_HDF5
  log_info("HDF5: header_check_hdf5\n");
#endif
  const struct hdf5_superblock *sb=(const struct hdf5_superblock*)&buffer[0];
  const uint8_t sb_version=sb->version;
  const uint8_t offsets_size=sb->offsets_size;
#ifdef DEBUG_HDF5
  log_info("HDF5: header_check_hdf5: size of offsets = %i\n", (int)offsets_size);
  log_info("HDF5: header_check_hdf5: superblock version = %i\n", (int)sb_version);
#endif
  uint8_t meta_base = 24;
  if (sb_version)
    meta_base = 28;
  const uint8_t eof_address_offset = meta_base + 2*offsets_size;
#ifdef DEBUG_HDF5
  log_info("HDF5: header_check_hdf5: eof_address_offset = 0x%02X\n", (int)eof_address_offset);
#endif
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_hdf5.extension;
  file_recovery_new->file_check=&file_check_hdf5;
  return 1;
}


static void register_header_check_hdf5(file_stat_t *file_stat)
{
  static const unsigned char hdf5_header[8]=  { 0x89, 'H', 'D', 'F', '\r', '\n', 0x1a, '\n'};
  register_header_check(0, hdf5_header, sizeof(hdf5_header), &header_check_hdf5, file_stat);
}
#endif
