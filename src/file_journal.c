/*

    File: file_journal.c

    Copyright (C) 2025 Christophe GRENIER <grenier@cgsecurity.org>

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_journal)
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
static void register_header_check_journal(file_stat_t *file_stat);

const file_hint_t file_hint_journal= {
  .extension="journal",
  .description="Systemd journal",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_journal
};

typedef union sd_id128 {
  uint8_t bytes[16];
  uint64_t qwords[2];
} sd_id128_t;

struct header_journal
{
  uint8_t signature[8];
  uint32_t compatible_flags;
  uint32_t incompatible_flags;
  uint8_t state;
  uint8_t reserved[7];
  sd_id128_t file_id;
  sd_id128_t machine_id;
  sd_id128_t tail_entry_boot_id;
  sd_id128_t seqnum_id;
  uint64_t header_size;
  uint64_t arena_size;
  uint64_t data_hash_table_offset;
  uint64_t data_hash_table_size;
  uint64_t field_hash_table_offset;
  uint64_t field_hash_table_size;
  uint64_t tail_object_offset;
  uint64_t n_objects;
  uint64_t n_entries;
  uint64_t tail_entry_seqnum;
  uint64_t head_entry_seqnum;
  uint64_t entry_array_offset;
  uint64_t head_entry_realtime;
  uint64_t tail_entry_realtime;
  uint64_t tail_entry_monotonic;
  /* Added in 187 */
  uint64_t n_data;
  uint64_t n_fields;
  /* Added in 189 */
  uint64_t n_tags;
  uint64_t n_entry_arrays;
  /* Added in 246 */
  uint64_t data_hash_chain_depth;
  uint64_t field_hash_chain_depth;
  /* Added in 252 */
  uint32_t tail_entry_array_offset;
  uint32_t tail_entry_array_n_entries;
  /* Added in 254 */
  uint64_t tail_entry_offset;
};

/*@
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @*/
static int header_check_journal(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct header_journal *h=(const struct header_journal *)buffer;
  const uint64_t header_size=le64(h->header_size);
  const uint64_t arena_size=le64(h->arena_size);
  if(header_size < 272 || header_size > PHOTOREC_MAX_FILE_SIZE)
    return 0;
  if(arena_size > PHOTOREC_MAX_FILE_SIZE)
    return 0;
  if(buffer[9]!=0 || buffer[10]!=0 || buffer[11]!=0)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_journal.extension;
  file_recovery_new->min_filesize=header_size;
  file_recovery_new->calculated_file_size=header_size + arena_size;
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  file_recovery_new->time=le64(h->head_entry_realtime/1000000);
  return 1;
}

static void register_header_check_journal(file_stat_t *file_stat)
{
  static const unsigned char journal_header[8]=  {
    'L' , 'P' , 'K' , 'S' , 'H' , 'H' , 'R' , 'H' ,
  };
  register_header_check(0, journal_header, sizeof(journal_header), &header_check_journal, file_stat);
}
#endif
