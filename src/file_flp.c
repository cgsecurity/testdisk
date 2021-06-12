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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_flp)
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
static void register_header_check_flp(file_stat_t *file_stat);

const file_hint_t file_hint_flp= {
  .extension="flp",
  .description="Fruity Loop",
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
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires buffer_size >=sizeof(struct flp_header);
  @ requires separation: \separated(&file_hint_flp, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_flp(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct flp_header *hdr=(const struct flp_header *)buffer;
  const unsigned int len2=le32(hdr->len2);
  if(strncmp(hdr->magic2, "FLdt", 4)!=0)
    return 0;
  if(len2==0)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_flp.extension;
  file_recovery_new->calculated_file_size=(uint64_t)len2 + 0x16;
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
#endif
