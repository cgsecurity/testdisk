/*

    File: file_orf.c

    Copyright (C) 1998-2005,2007-2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include "file_tiff.h"

static void register_header_check_orf(file_stat_t *file_stat);

const file_hint_t file_hint_orf= {
  .extension="orf",
  .description="Olympus Raw Format picture",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_orf
};

static int header_check_orf_IIRS(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_orf.extension;
  return 1;
}

static int header_check_orf_IIRO(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_orf.extension;
  file_recovery_new->time=get_date_from_tiff_header((const TIFFHeader *)buffer, buffer_size);
  file_recovery_new->file_check=&file_check_tiff;
  return 1;
}

static void register_header_check_orf(file_stat_t *file_stat)
{
  static const unsigned char orf_header_IIRS[8]= { 0x49, 0x49, 0x52, 0x53, 0x08, 0x00, 0x00, 0x00};
  static const unsigned char orf_header_IIRO[8]= { 'I', 'I', 'R', 'O', 0x08, 0x00, 0x00, 0x00};
  register_header_check(0, orf_header_IIRS, sizeof(orf_header_IIRS), &header_check_orf_IIRS, file_stat);
  register_header_check(0, orf_header_IIRO, sizeof(orf_header_IIRO), &header_check_orf_IIRO, file_stat);
}
