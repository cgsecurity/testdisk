/*

    File: file_oci.c

    Copyright (C) 2011 Christophe GRENIER <grenier@cgsecurity.org>
  
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

static void register_header_check_oci(file_stat_t *file_stat);

const file_hint_t file_hint_oci= {
  .extension="oci",
  .description="OpenCanvas Image",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_oci
};

struct oci_header
{
  unsigned char type[4];
  uint32_t	size;
} __attribute__ ((__packed__));

static data_check_t data_check_oci(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 8 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size - file_recovery->file_size + buffer_size/2;
    const struct oci_header *hdr=(const struct oci_header *)&buffer[i];
    const unsigned int atom_size=le32(hdr->size);
#ifdef DEBUG_MOV
    log_trace("file_oci.c: %s atom %c%c%c%c (0x%02x%02x%02x%02x) size %llu, calculated_file_size %llu\n",
	file_recovery->filename,
        buffer[i],buffer[i+1],buffer[i+2],buffer[i+3], 
        buffer[i],buffer[i+1],buffer[i+2],buffer[i+3], 
        (long long unsigned)atom_size,
        (long long unsigned)file_recovery->calculated_file_size);
#endif
    if(buffer[i+0]=='O' &&
      (buffer[i+1]>='A' && buffer[i+1]<='Z') &&
      (buffer[i+2]>='A' && buffer[i+2]<='Z') &&
      (buffer[i+3]>='A' && buffer[i+3]<='Z'))
    {
      file_recovery->calculated_file_size+=atom_size+8;
    }
    else
    {
      return DC_STOP;
    }
  }
#ifdef DEBUG_MOV
  log_trace("file_oci.c: new calculated_file_size %llu\n",
      (long long unsigned)file_recovery->calculated_file_size);
#endif
  return DC_CONTINUE;
}

static int header_check_oci(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct oci_header *hdr=(const struct oci_header *)buffer;
  if(8+le32(hdr->size)+8 <= buffer_size)
  {
    const struct oci_header *hdr2=(const struct oci_header *)&buffer[8+le32(hdr->size)];
    if(!(hdr2->type[0]=='O' &&
	  (hdr2->type[1]>='A' && hdr2->type[1]<='Z') &&
	  (hdr2->type[2]>='A' && hdr2->type[2]<='Z') &&
	  (hdr2->type[3]>='A' && hdr2->type[3]<='Z')))
      return 0;
  }
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_oci.extension;
  if(file_recovery_new->blocksize < 8)
    return 1;
  file_recovery_new->data_check=&data_check_oci;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static void register_header_check_oci(file_stat_t *file_stat)
{
  static const unsigned char oci_header[8]=  {
    'O' , 'P' , 'I' , 'M' , '0' , 0x00, 0x00, 0x00
  };
  register_header_check(0, oci_header, sizeof(oci_header), &header_check_oci, file_stat);
}
