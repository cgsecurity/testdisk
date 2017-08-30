/*

    File: file_fit.c

    Copyright (C) 1998-2005,2007 Christophe GRENIER <grenier@cgsecurity.org>

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
#include <ctype.h>
#include "types.h"
#include "filegen.h"
#include "common.h"

static void register_header_check_fit(file_stat_t *file_stat);

const file_hint_t file_hint_fit = {
  .extension="fit",
  .description="garmin track file",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_fit
};

struct fits_header
{
    unsigned char len;
    unsigned char ver;
    unsigned short version;
    unsigned int filelen;
    char signature[4];
} __attribute__ ((gcc_struct, __packed__));

int header_check_fit(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct fits_header* h = (const struct posix_header *)buffer;
  const char* sig = h->signature;
  if (sig[0] == '.' && sig[1] == 'F' && sig[2] == 'I' && sig[3] == 'T')
  {
      reset_file_recovery(file_recovery_new);
      file_recovery_new->extension = file_hint_fit.extension;
      file_recovery_new->min_filesize = 8;
      file_recovery_new->calculated_file_size=(uint64_t)le32(h->filelen);
      file_recovery_new->data_check=&data_check_size;
      file_recovery_new->file_check=&file_check_size;
      return 1;
  }
  return 0;
}

static void register_header_check_fit(file_stat_t *file_stat)
{
  static const unsigned char fits_header[4]= { '.', 'F', 'I', 'T' };
  register_header_check(8, fits_header, sizeof(fits_header), &header_check_fit, file_stat);
}
