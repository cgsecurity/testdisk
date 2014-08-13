/*

    File: file_flp.c

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
#include "filegen.h"
#include "common.h"

static void register_header_check_flp(file_stat_t *file_stat);
static int header_check_flp(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_flp= {
  .extension="flp",
  .description="Fruity Loop",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_flp
};

struct flp_header
{
  char magic[4];
  uint32_t len;		/* = 6 */
  uint16_t format;
  uint16_t tracks;
  int16_t time_division;
  char magic2[4];
  uint32_t len2;
} __attribute__ ((__packed__));

static int header_check_flp(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct flp_header *hdr=(const struct flp_header *)buffer;
  if(strncmp(hdr->magic2, "FLdt", 4)!=0)
    return 0;
  if(le32(hdr->len2)==0)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_flp.extension;
  file_recovery_new->calculated_file_size=le32(hdr->len2) + 0x16;
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

/* File format is similar to a midi file.
 * It begins by a header chunk and is followed by a single track chunk */
static void register_header_check_flp(file_stat_t *file_stat)
{
  static const unsigned char flp_header[8]= {'F', 'L', 'h', 'd', 0x06, 0x00, 0x00, 0x00};
  register_header_check(0, flp_header,sizeof(flp_header), &header_check_flp, file_stat);
}
