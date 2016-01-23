/*

    File: file_pcb.c

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

static void register_header_check_pcb(file_stat_t *file_stat);

const file_hint_t file_hint_pcb= {
  .extension="pcb",
  .description="PCB Wizard",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_pcb
};

static int header_check_pcb(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_pcb.extension;
  file_recovery_new->min_filesize=8;
  return 1;
}

static void register_header_check_pcb(file_stat_t *file_stat)
{
  static const unsigned char pcb_header[8]=  {
    'D' , 's' , 'g' , 0x00, 0x0a, 'd' , 0x0a, 0x00,
  };
  register_header_check(0, pcb_header, sizeof(pcb_header), &header_check_pcb, file_stat);
}
