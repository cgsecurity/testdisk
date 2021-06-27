/*

    File: file_iso.c

    Copyright (C) 2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_iso)
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
#include "iso9660.h"

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_iso(file_stat_t *file_stat);

const file_hint_t file_hint_iso= {
  .extension="iso",
  .description="ISO",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_iso
};

/*@
  @ requires separation: \separated(&file_hint_iso, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_iso(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(buffer_size<0x8000+512)	/* +2048 for the full mapping */
    return 0;
  {
    const struct iso_primary_descriptor *iso1=(const struct iso_primary_descriptor*)&buffer[0x8000];
    const unsigned int volume_space_size_le=le32(iso1->volume_space_size_le);
    const unsigned int volume_space_size_be=be32(iso1->volume_space_size_be);
    const unsigned int logical_block_size_le=le16(iso1->logical_block_size_le);
    const unsigned int logical_block_size_be=be16(iso1->logical_block_size_be);
    if(volume_space_size_le==volume_space_size_be && logical_block_size_le==logical_block_size_be)
    {	/* ISO 9660 */
      const uint64_t size=(uint64_t)volume_space_size_le * logical_block_size_le;
      if(size < 0x8000+512)
	return 0;
      reset_file_recovery(file_recovery_new);
      file_recovery_new->extension=file_hint_iso.extension;
      file_recovery_new->calculated_file_size=size;
      file_recovery_new->data_check=&data_check_size;
      file_recovery_new->file_check=&file_check_size;
      file_recovery_new->min_filesize=0x8000+512;
      return 1;
    }
  }
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_iso.extension;
  file_recovery_new->min_filesize=0x8000+512;
  return 1;
}

static void register_header_check_iso(file_stat_t *file_stat)
{
  static const unsigned char iso_header[6]= { 0x01, 'C', 'D', '0', '0', '1'};
  register_header_check(0x8000, iso_header,sizeof(iso_header), &header_check_iso, file_stat);
}
#endif
