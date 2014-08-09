/*

    File: file_7z.c

    Copyright (C) 2005-2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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

static void register_header_check_7z(file_stat_t *file_stat);

const file_hint_t file_hint_7z= {
  .extension="7z",
  .description="7zip archive file",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_7z
};

struct header_7z {
  unsigned char signature[6];
  uint8_t majorversion;
  uint8_t minorversion;
  uint32_t crcFromArchive;
  uint64_t nextHeaderOffset;
  uint64_t nextHeaderSize;
  uint64_t nextHeaderCRC;
} __attribute__ ((__packed__));


static int header_check_7z(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery,  file_recovery_t *file_recovery_new)
{
  const struct header_7z *buffer_7z=(const struct header_7z *)buffer;
  if(buffer_7z->majorversion!=0 ||
      le64(buffer_7z->nextHeaderSize)==0)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_7z.extension;
  file_recovery_new->min_filesize=31;
  /* Signature size 12 + Start header size 20 */
  file_recovery_new->calculated_file_size=(uint64_t)le64(buffer_7z->nextHeaderOffset)+
    le64(buffer_7z->nextHeaderSize) + 12 + 20;
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static void register_header_check_7z(file_stat_t *file_stat)
{
  static const unsigned char header_7z[6]  = {'7','z', 0xbc, 0xaf, 0x27, 0x1c};
  register_header_check(0, header_7z, sizeof(header_7z), &header_check_7z, file_stat);
}
