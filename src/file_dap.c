/*

    File: file_dap.c

    Copyright (C) 2017 Gaetan CARLIER <gcembed@gmail.com>
  
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
#include "log.h"

static void register_header_check_dap(file_stat_t *file_stat);

const file_hint_t file_hint_dap= {
  .extension="dap",
  .description="Domintell2 application",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=0,
  .register_header_check=&register_header_check_dap
};

static int header_check_dap(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /* Search for "Version Fichier\r\n*******" string */
  const char dap_hdr_str[24] = {
    0x56, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x20,
    0x46, 0x69, 0x63, 0x68, 0x69, 0x65, 0x72, 0x0D,
    0x0A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A
  };
  if(buffer_size<24)
    return 0;
  if(memcmp(buffer, dap_hdr_str, 24)!=0)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_dap.extension;
  return 1;
}

static void register_header_check_dap(file_stat_t *file_stat)
{
  register_header_check(0, "Version Fichier", 15, &header_check_dap, file_stat);
}
