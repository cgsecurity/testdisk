/*

    File: file_pdb.c

    Copyright (C) 2018 Christophe GRENIER <grenier@cgsecurity.org>

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pdb)
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
static void register_header_check_pdb(file_stat_t *file_stat);

const file_hint_t file_hint_pdb= {
  .extension="pdb",
  .description="Protein Data Bank data",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_pdb
};

/*@
  @ requires file_recovery->data_check==&data_check_pdb;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ terminates \true;
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ assigns  file_recovery->calculated_file_size;
  @*/
static data_check_t data_check_pdb(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  unsigned int i;
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@
    @ loop assigns i;
    @ loop variant buffer_size - i;
    @*/
  for(i=buffer_size/2; i<buffer_size; i++)
    if(buffer[i]==0)
    {
      file_recovery->calculated_file_size+=i;
      return DC_STOP;
    }
  file_recovery->calculated_file_size+=buffer_size/2;
  return DC_CONTINUE;
}

/*@
  @ requires file_recovery->file_check == &file_check_pdb;
  @ requires valid_file_check_param(file_recovery);
  @ ensures  valid_file_check_result(file_recovery);
  @ assigns  *file_recovery->handle, errno, file_recovery->file_size;
  @ assigns  Frama_C_entropy_source;
  @*/
static void file_check_pdb(file_recovery_t *file_recovery)
{
  char buffer[512];
  if(my_fseek(file_recovery->handle, 0, SEEK_SET) < 0 ||
      fread(&buffer, 1, sizeof(buffer), file_recovery->handle) < 82)
    return ;
#if defined(__FRAMAC__)
  Frama_C_make_unknown(buffer, sizeof(buffer));
#endif
  if(buffer[80]=='\r' && buffer[81]=='\n')
    file_recovery->file_size=file_recovery->calculated_file_size/82*82;
  else if(buffer[80]=='\n')
    file_recovery->file_size=file_recovery->calculated_file_size/81*81;
  else
    file_recovery->file_size=0;
}

/*@
  @ requires buffer_size >= 70;
  @ requires separation: \separated(&file_hint_pdb, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_pdb(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /* Check date */
  if(buffer[0x32] < '0' || buffer[0x32] > '9' || buffer[0x33] < '0' || buffer[0x33] > '9')
    return 0;
  if(buffer[0x34]!='-')
    return 0;
  if(buffer[0x35] < 'A' || buffer[0x35] > 'Z' || buffer[0x36] < 'A' || buffer[0x36] > 'Z' || buffer[0x37] < 'A' || buffer[0x37] > 'Z')
    return 0;
  if(buffer[0x38]!='-')
    return 0;
  if(buffer[0x39] < '0' || buffer[0x39] > '9' || buffer[0x3a] < '0' || buffer[0x3a] > '9')
    return 0;
  /* Check space */
  if(buffer[59]!=' ' || buffer[60]!=' ' || buffer[61]!=' ' || buffer[66]!=' ' || buffer[67]!=' ' || buffer[68]!=' ' || buffer[69]!=' ')
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_pdb.extension;
  file_recovery_new->data_check=&data_check_pdb;
  file_recovery_new->file_check=&file_check_pdb;
  file_recovery_new->min_filesize=80;
  return 1;
}

static void register_header_check_pdb(file_stat_t *file_stat)
{
  register_header_check(0, "HEADER    ", 10, &header_check_pdb, file_stat);
}
#endif
