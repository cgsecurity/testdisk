/*

    File: file_lxo.c

    Copyright (C) 2011 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include "common.h"
#include "filegen.h"

static void register_header_check_lxo(file_stat_t *file_stat);

const file_hint_t file_hint_lxo= {
  .extension="lxo",
  .description="lxo/lwo 3d model",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_lxo
};

struct lxo_header
{
  char magic[4];
  uint32_t size;
  char type[3];
} __attribute__ ((__packed__));

static int header_check_lxo(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct lxo_header *header=(const struct lxo_header *)buffer;
  const uint64_t size=be32(header->size) + 8;
  if(size < sizeof(struct lxo_header))
    return 0;
  if(buffer[8]=='L' && buffer[9]=='X' && buffer[10]=='O')
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_lxo.extension;
    file_recovery_new->calculated_file_size=size;
    file_recovery_new->file_check=&file_check_size;
    file_recovery_new->data_check=&data_check_size;
    return 1;
  }
  if(buffer[8]=='L' && buffer[9]=='W' && buffer[10]=='O')
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension="lwo";
    file_recovery_new->calculated_file_size=size;
    file_recovery_new->file_check=&file_check_size;
    file_recovery_new->data_check=&data_check_size;
    return 1;
  }
  return 0;
}

static void register_header_check_lxo(file_stat_t *file_stat)
{
  static const unsigned char lxo_header[4]=  {
    'F' , 'O' , 'R' , 'M' 
  };
  register_header_check(0, lxo_header, sizeof(lxo_header), &header_check_lxo, file_stat);
}
