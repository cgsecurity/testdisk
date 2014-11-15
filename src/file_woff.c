/*

    File: file_woff.c

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
#include "types.h"
#include "filegen.h"
#include "common.h"

static void register_header_check_woff(file_stat_t *file_stat);

const file_hint_t file_hint_woff= {
  .extension="woff",
  .description="Web Open Font Format",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_woff
};

struct WOFFHeader
{
  uint32_t	signature;
  uint32_t	flavor;
  uint32_t	length;
  uint16_t	numTables;
  uint16_t	reserved;
  uint32_t	totalSfntSize;
  uint16_t	majorVersion;
  uint16_t	minorVersion;
  uint32_t	metaOffset;
  uint32_t	metaLength;
  uint32_t	metaOrigLength;
  uint32_t	privOffset;
  uint32_t	privLength;
} __attribute__ ((__packed__));

static int header_check_woff(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct WOFFHeader *woff=(const struct WOFFHeader *)buffer;
  const uint64_t length=(uint64_t)be32(woff->length);
  if((uint32_t)be32(woff->length) < sizeof(struct WOFFHeader))
    return 0;
  if((uint32_t)be32(woff->metaOffset) > 0 && (uint32_t)be32(woff->metaOffset) < sizeof(struct WOFFHeader))
    return 0;
  if((uint32_t)be32(woff->privOffset) > 0 && (uint32_t)be32(woff->privOffset) < sizeof(struct WOFFHeader))
    return 0;
  if((uint64_t)be32(woff->metaOffset) + (uint64_t)be32(woff->metaLength) > length ||
      (uint64_t)be32(woff->privOffset) + (uint64_t)be32(woff->privLength) > length)
    return 0;
  if(woff->reserved!=0)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_woff.extension;
  file_recovery_new->calculated_file_size=length;
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static void register_header_check_woff(file_stat_t *file_stat)
{
  register_header_check(0, "wOFF", 4, &header_check_woff, file_stat);
}
