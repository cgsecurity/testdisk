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


static void register_header_check_iso(file_stat_t *file_stat);
static int header_check_db(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_iso= {
  .extension="iso",
  .description="ISO (Only detected if block size >= 64k)",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_iso
};


static const unsigned char iso_header[6]= { 0x01, 'C', 'D', '0', '0', '1'};
/* ISO 9660
   0x00 Volume Descriptor Type		0x01
   0x01 Standard Identifier 		CD001
   0x07 Volume Descriptor Version	0x01
   0x08 Unused Field			0x00
   0x09 System Identifier
   0x41 Volume Identifier
   0x73 Unused Field
*/
static void register_header_check_iso(file_stat_t *file_stat)
{
  register_header_check(0x8000, iso_header,sizeof(iso_header), &header_check_db, file_stat);
}

static int header_check_db(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(buffer_size<0x8000+sizeof(iso_header))
    return 0;
  if(memcmp (&buffer[0x8000], iso_header, sizeof(iso_header))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_iso.extension;
    return 1;
  }
  return 0;
}


