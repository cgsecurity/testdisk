/*

    File: file_dad.c

    Copyright (C) 2014 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include "log.h"

static void register_header_check_dad(file_stat_t *file_stat);

const file_hint_t file_hint_dad= {
  .extension="dad",
  .description="Micae DVR",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_dad
};

struct dad_header
{
  uint32_t magic;
  uint32_t unk1;
  uint32_t unk2;
  uint32_t size;
} __attribute__ ((__packed__));

static data_check_t data_check_dad(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 16 <= file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size - file_recovery->file_size + buffer_size/2;
    const struct dad_header *dad=(const struct dad_header *)&buffer[i];
#ifdef DEBUG_DAD
    log_info("%llu magic %08x => %llu\n",
	(long long unsigned)file_recovery->calculated_file_size, le32(dad->magic),
	(long long unsigned)file_recovery->calculated_file_size + le32(dad->size));
#endif
    if(dad->magic!=le32(0x56414844) || le32(dad->size)<16)
      return DC_STOP;
    file_recovery->calculated_file_size+=le32(dad->size);
  }
  return DC_CONTINUE;
}

static int header_check_dad(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct dad_header *dad=(const struct dad_header *)buffer;
  if(file_recovery->file_stat!=NULL &&
      file_recovery->file_stat->file_hint==&file_hint_dad &&
      (file_recovery->calculated_file_size==file_recovery->file_size ||
       file_recovery->blocksize < 16))
    return 0;
  if(le32(dad->size)<16)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_dad.extension;
  file_recovery_new->min_filesize=le32(dad->size);
  if(file_recovery_new->blocksize >= 16)
  {
    file_recovery_new->data_check=&data_check_dad;
    file_recovery_new->file_check=&file_check_size;
  }
  return 1;
}

static void register_header_check_dad(file_stat_t *file_stat)
{
  register_header_check(0, "DHAV", 4, &header_check_dad, file_stat);
}
