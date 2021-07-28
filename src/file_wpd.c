/*

    File: file_wpd.c

    Copyright (C) 1998-2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_wpd)
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
static void register_header_check_wpd(file_stat_t *file_stat);

const file_hint_t file_hint_wpd = {
  .extension = "wpd",
  .description = "Corel Documents",
  .max_filesize = PHOTOREC_MAX_FILE_SIZE,
  .recover = 1,
  .enable_by_default = 1,
  .register_header_check = &register_header_check_wpd
};

struct wpd_hdr
{
  unsigned char magic[4];
  uint32_t documentOffset;
  uint8_t productType;
  uint8_t fileType;
  uint8_t majorVersion;
  uint8_t minorVersion;
  uint16_t documentEncryption;
  uint16_t indexHeaderOffset; /* 14 */
  uint32_t unk;
  uint32_t documentSize; /* 20: WP 6.1 or later ? */
} __attribute__((gcc_struct, __packed__));

/*@
  @ requires buffer_size >= sizeof(struct wpd_hdr);
  @ requires separation: \separated(&file_hint_wpd, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_wpd(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct wpd_hdr *hdr = (const struct wpd_hdr *)buffer;
  const unsigned int documentOffset = le32(hdr->documentOffset);
  if(hdr->fileType == 0x0a && hdr->majorVersion == 0x02)
  {
    const unsigned int documentSize = le32(hdr->documentSize);
    /* WP 6 */
    if(hdr->minorVersion == 0)
    {
      if(documentOffset < 20)
        return 0;
      reset_file_recovery(file_recovery_new);
      file_recovery_new->extension = file_hint_wpd.extension;
      file_recovery_new->min_filesize = documentOffset;
      return 1;
    }
    if(documentOffset < sizeof(struct wpd_hdr) || documentSize < documentOffset)
      return 0;
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension = file_hint_wpd.extension;
    file_recovery_new->calculated_file_size = documentSize;
    file_recovery_new->data_check = &data_check_size;
    file_recovery_new->file_check = &file_check_size;
    return 1;
  }
  if(/* WP5 */
     (hdr->fileType == 0x0a && hdr->majorVersion == 0x00) ||
     /* WP MAC 2.x, 3.0-3.5, 3.5e */
     (hdr->fileType == 0x2c && (hdr->majorVersion >= 0x02 && hdr->majorVersion <= 0x04)))
  {
    if(documentOffset < 20)
      return 0;
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension = file_hint_wpd.extension;
    file_recovery_new->min_filesize = documentOffset;
    return 1;
  }
  return 0;
}

static void register_header_check_wpd(file_stat_t *file_stat)
{
  static const unsigned char wpd_header[4] = { 0xff, 'W', 'P', 'C' };
  register_header_check(0, wpd_header, sizeof(wpd_header), &header_check_wpd, file_stat);
}
#endif
