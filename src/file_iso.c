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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "filegen.h"
#include "iso9660.h"

static void register_header_check_iso(file_stat_t *file_stat);
static int header_check_db(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_iso= {
  .extension="iso",
  .description="ISO",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_iso
};

static const unsigned char iso_header[6]= { 0x01, 'C', 'D', '0', '0', '1'};

static void register_header_check_iso(file_stat_t *file_stat)
{
  register_header_check(0x8000, iso_header,sizeof(iso_header), &header_check_db, file_stat);
}

static int header_check_db(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(buffer_size<0x8000+512)	/* +2048 for the full mapping */
    return 0;
  if(memcmp (&buffer[0x8000], iso_header, sizeof(iso_header))==0)
  {
    const struct iso_primary_descriptor *iso1=(const struct iso_primary_descriptor*)&buffer[0x8000];
    const unsigned int volume_space_size=iso1->volume_space_size[0] | (iso1->volume_space_size[1]<<8) | (iso1->volume_space_size[2]<<16) | (iso1->volume_space_size[3]<<24);
    const unsigned int volume_space_size2=iso1->volume_space_size[7] | (iso1->volume_space_size[6]<<8) | (iso1->volume_space_size[5]<<16) | (iso1->volume_space_size[4]<<24);
    const unsigned int logical_block_size=iso1->logical_block_size[0] | (iso1->logical_block_size[1]<<8);
    const unsigned int logical_block_size2=iso1->logical_block_size[3] | (iso1->logical_block_size[2]<<8);
    if(volume_space_size==volume_space_size2 && logical_block_size==logical_block_size2)
    {	/* ISO 9660 */
      const uint64_t size=(uint64_t)volume_space_size * logical_block_size;
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
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_iso.extension;
      file_recovery_new->min_filesize=0x8000+512;
    return 1;
  }
  return 0;
}
