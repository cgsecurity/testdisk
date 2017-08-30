/*

    File: file_fit.c

    Copyright (C) 2017 Christophe GRENIER <grenier@cgsecurity.org>

    This software is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either profile_version 2 of the License, or
    (at your option) any later profile_version.

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
  .description="Flexible & Interoperable Data Transfer / Garmin track file",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_fit
};

struct fits_header
{
    unsigned char header_size;
    unsigned char protocol_version;
    uint16_t profile_version;
    uint32_t data_size;
    char signature[4];
} __attribute__ ((gcc_struct, __packed__));

static int header_check_fit(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct fits_header* h = (const struct fits_header *)buffer;
  if (h->header_size < 12)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension = file_hint_fit.extension;
  file_recovery_new->min_filesize = 12;
  file_recovery_new->calculated_file_size=(uint64_t)le32(h->data_size) + h->header_size;
  if(h->header_size >= 14)
    file_recovery_new->calculated_file_size+=2;	/* CRC at the end of the file */
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static void register_header_check_fit(file_stat_t *file_stat)
{
  static const unsigned char fits_header[4]= { '.', 'F', 'I', 'T' };
  register_header_check(8, fits_header, sizeof(fits_header), &header_check_fit, file_stat);
}
