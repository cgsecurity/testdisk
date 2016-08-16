/*

    File: file_plr.c

    Copyright (C) 2016 Christophe GRENIER <grenier@cgsecurity.org>

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

static void register_header_check_plr(file_stat_t *file_stat);

const file_hint_t file_hint_plr= {
  .extension="plr",
  .description="Terraria Player File",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_plr
};

static int header_check_plr(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_plr.extension;
  file_recovery_new->calculated_file_size=1856;
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static void register_header_check_plr(file_stat_t *file_stat)
{
  static const unsigned char plr_header[16]=  {
    0x0f, 'w' , 'g' , 0xfe, 0xb1, 'J' , 0xb2, 0xef,
    0xfc, 'j' , 0x9b, 'K' , 'x' , 0x5b, 0xf4, 'V' 
  };
  register_header_check(0, plr_header, sizeof(plr_header), &header_check_plr, file_stat);
}
