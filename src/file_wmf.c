/*

    File: file_wmf.c

    Copyright (C) 2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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


static void register_header_check_wmf(file_stat_t *file_stat);
static int header_check_wmf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_wmf= {
  .extension="wmf",
  .description="Microsoft Windows Metafile",
  .min_header_distance=0,
  .max_filesize=50*1024*1024,
  .recover=1,
  .enable_by_default=1,
	.register_header_check=&register_header_check_wmf
};

static int header_check_wmf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(buffer[0x10]!=0 || buffer[0x11]!=0)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_wmf.extension;
  return 1;
}

static void register_header_check_wmf(file_stat_t *file_stat)
{
  static const unsigned char apm_header[6] = { 0xd7, 0xcd, 0xc6, 0x9a, 0x00, 0x00 };
  static const unsigned char emf_header[6] = { 0x20, 0x45, 0x4D, 0x46, 0x00, 0x00 };
  /* WMF: file_type=disk, header size=9, version=3.0 */
  static const unsigned char wmf_header[6] = { 0x01, 0x00, 0x09, 0x00, 0x00, 0x03 };
  register_header_check(0, apm_header,sizeof(apm_header), &header_check_wmf, file_stat);
  register_header_check(0, emf_header,sizeof(emf_header), &header_check_wmf, file_stat);
  register_header_check(0, wmf_header,sizeof(wmf_header), &header_check_wmf, file_stat);
}
