/*

    File: file_apa.c

    Copyright (C) 2009 Christophe GRENIER <grenier@cgsecurity.org>

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

static void register_header_check_apa(file_stat_t *file_stat);
static int header_check_apa(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_apa= {
  .extension="apa",
  .description="APA Style Helper",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_apa
};

static const unsigned char apa_magic[16]= {
  'c', 'o', 'm', '.', 'a', 'p', 'a', '.',
  'D', 'o', 'c', 'u', 'm', 'e', 'n', 't'};

static void register_header_check_apa(file_stat_t *file_stat)
{
  register_header_check(8, apa_magic, sizeof(apa_magic), &header_check_apa, file_stat);
}

static int header_check_apa(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(&buffer[8], apa_magic, sizeof(apa_magic))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_apa.extension;
    return 1;
  }
  return 0;
}
