/*

    File: file_rar.c

    Copyright (C) 1998-2005,2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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


static void register_header_check_rar(file_stat_t *file_stat);

const file_hint_t file_hint_rar= {
  .extension="rar",
  .description="Rar archive",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_rar
};

#define  MHD_PASSWORD       0x0080U

static void file_check_rar15fmt(file_recovery_t *file_recovery)
{
  static const unsigned char rar15fmt_footer[7]={0xc4, 0x3d, 0x7b, 0x00, 0x40, 0x07, 0x00 };
  file_search_footer(file_recovery, rar15fmt_footer, sizeof(rar15fmt_footer), 0);
}

static int header_check_rar15fmt(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  reset_file_recovery(file_recovery_new);
  file_recovery_new->min_filesize=70;
  if((buffer[0xa] & MHD_PASSWORD)==0)
    file_recovery_new->file_check=&file_check_rar15fmt;
  file_recovery_new->extension=file_hint_rar.extension;
  return 1;
}

static void file_check_rar50fmt(file_recovery_t *file_recovery)
{
  static const unsigned char rar50fmt_footer[8]={0x1d, 0x77, 0x56, 0x51, 0x03, 0x05, 0x04, 0x00 };
  file_search_footer(file_recovery, rar50fmt_footer, sizeof(rar50fmt_footer), 0);
}

static int header_check_rar50fmt(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  reset_file_recovery(file_recovery_new);
  file_recovery_new->min_filesize=60;
  if((buffer[0xa] & MHD_PASSWORD)==0)
    file_recovery_new->file_check=&file_check_rar50fmt;
  file_recovery_new->extension=file_hint_rar.extension;
  return 1;
}

static void register_header_check_rar(file_stat_t *file_stat)
{
  static const unsigned char rar15fmt_header[7]={0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00 };
  static const unsigned char rar50fmt_header[8]={0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00 };
  register_header_check(0, rar15fmt_header,sizeof(rar15fmt_header), &header_check_rar15fmt, file_stat);
  register_header_check(0, rar50fmt_header,sizeof(rar50fmt_header), &header_check_rar50fmt, file_stat);
}
