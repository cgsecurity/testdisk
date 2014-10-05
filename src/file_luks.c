/*

    File: file_luks.c

    Copyright (C) 2014 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include "luks.h"

static void register_header_check_luks(file_stat_t *file_stat);

const file_hint_t file_hint_luks= {
  .extension="luks",
  .description="LUKS encrypted file",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_luks
};

static const unsigned char luks_header[6]=  {
  'L' , 'U' , 'K' , 'S' , 0xba, 0xbe
};

static int header_check_luks(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct luks_phdr *hdr=(const struct luks_phdr *)buffer;
  if(be16(hdr->version)<1 || be16(hdr->version)>2)
    return 0;
  if(!isalpha(hdr->cipherName[0]))
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_luks.extension;
  file_recovery_new->min_filesize=512;
  return 1;
}

static void register_header_check_luks(file_stat_t *file_stat)
{
  register_header_check(0, luks_header, sizeof(luks_header), &header_check_luks, file_stat);
}
