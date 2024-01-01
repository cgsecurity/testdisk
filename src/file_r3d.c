/*

    File: file_r3d.c

    Copyright (C) 2009,2014 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_r3d)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include <ctype.h>
#include "types.h"
#include "filegen.h"
#include "common.h"
#include "log.h"

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_r3d(file_stat_t *file_stat);

const file_hint_t file_hint_r3d = {
  .extension = "r3d",
  .description = "RED r3d camera",
  .max_filesize = PHOTOREC_MAX_FILE_SIZE,
  .recover = 1,
  .enable_by_default = 1,
  .register_header_check = &register_header_check_r3d
};

struct atom_struct
{
  uint32_t size;
  uint32_t type;
} __attribute__((gcc_struct, __packed__));

/*@
  @ requires file_recovery->data_check==&data_check_r3d;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ terminates \true;
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ assigns file_recovery->calculated_file_size, file_recovery->data_check;
  @*/
static data_check_t data_check_r3d(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@
    @ loop assigns file_recovery->calculated_file_size;
    @ loop variant file_recovery->file_size + buffer_size / 2 - (file_recovery->calculated_file_size + 8);
    @*/
  while(file_recovery->calculated_file_size + buffer_size / 2 >= file_recovery->file_size && file_recovery->calculated_file_size + 8 <= file_recovery->file_size + buffer_size / 2)
  {
    const unsigned int i = file_recovery->calculated_file_size + buffer_size / 2 - file_recovery->file_size;
    /*@ assert 0 <= i <= buffer_size-8; */
    const struct atom_struct *atom = (const struct atom_struct *)&buffer[i];
    uint64_t atom_size = be32(atom->size);
    if(atom_size < 8)
      return DC_STOP;
#ifdef DEBUG_R3D
    log_trace("file_r3d.c: %s atom %c%c%c%c (0x%02x%02x%02x%02x) size %llu, calculated_file_size %llu\n",
              file_recovery->filename,
              buffer[i + 4], buffer[i + 5], buffer[i + 6], buffer[i + 7],
              buffer[i + 4], buffer[i + 5], buffer[i + 6], buffer[i + 7],
              (long long unsigned)atom_size,
              (long long unsigned)file_recovery->calculated_file_size);
#endif
    if(buffer[i + 4] == 'R' && buffer[i + 5] == 'E' && buffer[i + 6] == 'O')
    {
      /* End of file */
      file_recovery->calculated_file_size += atom_size;
      file_recovery->data_check = NULL;
      return DC_CONTINUE;
    }
    if(buffer[i + 4] != 'R')
    {
      return DC_STOP;
    }
    /* REDV1 REDV RPAD RDVO RDVS RDAO RDAS REOB */
    file_recovery->calculated_file_size += atom_size;
  }
#ifdef DEBUG_R3D
  log_trace("file_r3d.c: new calculated_file_size %llu\n",
            (long long unsigned)file_recovery->calculated_file_size);
#endif
  return DC_CONTINUE;
}

/*@
  @ requires file_recovery->file_rename==&file_rename_r3d;
  @ requires valid_file_rename_param(file_recovery);
  @ ensures  valid_file_rename_result(file_recovery);
  @*/
static void file_rename_r3d(file_recovery_t *file_recovery)
{
  unsigned char buffer[512];
  FILE *file;
  size_t buffer_size;
  unsigned int i;
  if((file = fopen(file_recovery->filename, "rb")) == NULL)
    return;
  buffer_size = fread(buffer, 1, sizeof(buffer), file);
  fclose(file);
  if(buffer_size < 0x44)
    return;
  /*@
    @ loop assigns i;
    @ loop variant buffer_size - i;
    @*/
  for(i = 0x43; i < buffer_size && buffer[i] != 0 && buffer[i] != '.'; i++)
  {
    if(!isalnum(buffer[i]) && buffer[i] != '_')
      return;
  }
  file_rename(file_recovery, buffer, i, 0x43, NULL, 1);
}

/*@
  @ requires buffer_size >= sizeof(struct atom_struct);
  @ requires separation: \separated(&file_hint_r3d, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_r3d(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct atom_struct *atom = (const struct atom_struct *)buffer;
  if(be32(atom->size) < 8)
    return 0;
  if(buffer[0xa] == 'R' && buffer[0xb] == '1')
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension = file_hint_r3d.extension;
    file_recovery_new->file_rename = &file_rename_r3d;
    if(file_recovery_new->blocksize < 8)
      return 1;
    file_recovery_new->data_check = &data_check_r3d;
    file_recovery_new->file_check = &file_check_size;
    return 1;
  }
  return 0;
}

/*@
  @ requires buffer_size >= 0xc;
  @ requires separation: \separated(&file_hint_r3d, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_r3d_v2(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(buffer[0xa] == 'R' && buffer[0xb] == '2')
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension = file_hint_r3d.extension;
    return 1;
  }
  return 0;
}

static void register_header_check_r3d(file_stat_t *file_stat)
{
  static const unsigned char r3d_header1[4] = { 'R', 'E', 'D', '1' };
  static const unsigned char r3d_header2[4] = { 'R', 'E', 'D', '2' };
  register_header_check(4, r3d_header1, sizeof(r3d_header1), &header_check_r3d, file_stat);
  register_header_check(4, r3d_header2, sizeof(r3d_header2), &header_check_r3d_v2, file_stat);
}
#endif
