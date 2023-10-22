/*

    File: file_xcf.c

    Copyright (C) 2006-2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_xcf)
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

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_xcf(file_stat_t *file_stat);

const file_hint_t file_hint_xcf = {
  .extension = "xcf",
  .description = "Gimp XCF File",
  .max_filesize = 1024 * 1024 * 1024,
  .recover = 1,
  .enable_by_default = 1,
  .register_header_check = &register_header_check_xcf
};

// https://git.gnome.org/browse/gimp/tree/devel-docs/xcf.txt
struct xcf_header
{
  unsigned char magic[9];
  unsigned char version[4];
  unsigned char zero;
  uint32_t width;
  uint32_t heigth;
  uint32_t base_type;
} __attribute__((gcc_struct, __packed__));

/*@
  @ requires buffer_size >= sizeof(struct xcf_header);
  @ requires separation: \separated(&file_hint_xcf, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_xcf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct xcf_header *hdr = (const struct xcf_header *)buffer;
  if(hdr->zero != 0)
    return 0;
  if(be32(hdr->width) == 0 || be32(hdr->heigth) == 0)
    return 0;
  if(be32(hdr->base_type) > 2)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension = file_hint_xcf.extension;
  return 1;
}

static void register_header_check_xcf(file_stat_t *file_stat)
{
  register_header_check(0, "gimp xcf file", 13, &header_check_xcf, file_stat);
#ifndef DISABLED_FOR_FRAMAC
  register_header_check(0, "gimp xcf v00", 12, &header_check_xcf, file_stat);
  register_header_check(0, "gimp xcf v01", 12, &header_check_xcf, file_stat);
#endif
}
#endif
