/*

    File: file_qdf.c

    Copyright (C) 2006 Christophe GRENIER <grenier@cgsecurity.org>
  
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

extern const file_hint_t file_hint_doc;
static void register_header_check_qdf(file_stat_t *file_stat);

const file_hint_t file_hint_qdf= {
  .extension="qdf",
  .description="Quicken",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_qdf
};

static int header_check_qdf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(file_recovery->file_stat != NULL &&
      file_recovery->file_stat->file_hint==&file_hint_doc &&
      strstr(file_recovery->filename, ".qdf-backup")!=NULL)
  {
    if(header_ignored_adv(file_recovery, file_recovery_new)==0)
      return 0;
  }
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_qdf.extension;
  return 1;
}

static void register_header_check_qdf(file_stat_t *file_stat)
{
  static const unsigned char qdf_header[6]  = { 0xAC, 0x9E, 0xBD, 0x8F, 0x00, 0x00};
  register_header_check(0, qdf_header, sizeof(qdf_header), &header_check_qdf, file_stat);
}
