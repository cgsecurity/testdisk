/*

    File: file_rw2.c

    Copyright (C) 1998-2009 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_rw2)
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
#include "common.h"

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_rw2(file_stat_t *file_stat);

const file_hint_t file_hint_rw2= {
  .extension="rw2",
  .description="Panasonic/Leica RAW",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_rw2
};

/*@
  @ requires buffer_size >= sizeof(TIFFHeader);
  @ requires separation: \separated(&file_hint_rw2, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_rw2(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const TIFFHeader *header=(const TIFFHeader *)buffer;
  if(le32(header->tiff_diroff) < sizeof(TIFFHeader))
    return 0;
  /* Panasonic/Leica */
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension="rw2";
  file_recovery_new->time=get_date_from_tiff_header(buffer, buffer_size);
  file_recovery_new->file_check=&file_check_tiff_le;
  return 1;
}

static void register_header_check_rw2(file_stat_t *file_stat)
{
  static const unsigned char rw2_header_panasonic[4]= {'I','I','U','\0'};
  register_header_check(0, rw2_header_panasonic, sizeof(rw2_header_panasonic), &header_check_rw2, file_stat);
}
#endif
