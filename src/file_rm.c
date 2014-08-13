/*

    File: file_rm.c

    Copyright (C) 2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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

static void register_header_check_rm(file_stat_t *file_stat);
static int header_check_rm(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_rm= {
  .extension="rm",
  .description="Real Audio",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_rm
};

struct rm_header
{
  uint32_t type;
  uint32_t size;
  uint16_t version;
  uint32_t file_version;
  uint32_t header_nbr;
} __attribute__ ((__packed__));

static int header_check_rm(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct rm_header *hdr=(const struct rm_header *)buffer;
  if(be32(hdr->header_nbr) < 3)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_rm.extension;
  return 1;
}

static void register_header_check_rm(file_stat_t *file_stat)
{
  static const unsigned char rm_header[9]  = { '.', 'R', 'M', 'F', 0x00, 0x00, 0x00, 0x12, 0x00};
  register_header_check(0, rm_header,sizeof(rm_header), &header_check_rm, file_stat);
}
