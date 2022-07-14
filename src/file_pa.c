/*

    File: file_pa.c

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pa)
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
static void register_header_check_pa(file_stat_t *file_stat);

const file_hint_t file_hint_pa= {
  .extension="pa",
  .description="PowerArchiver",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_pa
};

struct pa_header
{
  char magic[8];
  uint32_t unk;
  uint64_t size;
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @*/
static int header_check_pa(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct pa_header *hdr=(const struct pa_header *)buffer;
  const uint64_t size=le64(hdr->size);
  if(size > PHOTOREC_MAX_FILE_SIZE)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_pa.extension;
  file_recovery_new->calculated_file_size=70+size;
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static void register_header_check_pa(file_stat_t *file_stat)
{
  static const unsigned char pa_header[8]=  {
    'P' , 'a' , 'F' , 'i' , 'L' , 'e' , 0x00, 0x04
  };
  register_header_check(0, pa_header, sizeof(pa_header), &header_check_pa, file_stat);
}
#endif
