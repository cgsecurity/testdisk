/*

    File: file_e01.c

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

static void register_header_check_e01(file_stat_t *file_stat);

const file_hint_t file_hint_e01= {
  .extension="e01",
  .description="Encase",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_e01
};

struct ewf_file_header
{
        /* The EWF file signature (magic header)
         * consists of 8 bytes containing
         * EVF 0x09 0x0d 0x0a 0xff 0x00
         */
        uint8_t signature[ 8 ];
        /* The fields start
         * consists of 1 byte (8 bit) containing
         * 0x01
         */
        uint8_t fields_start;
        /* The fields segment number
         * consists of 2 bytes (16 bits) containing
         */
        uint16_t fields_segment;
        /* The fields end
         * consists of 2 bytes (16 bits) containing
         * 0x00 0x00
         */
        uint16_t fields_end;
} __attribute__ ((__packed__));

static void file_check_e01(file_recovery_t *file_recovery)
{
  const uint64_t tmp=file_recovery->file_size;
  const unsigned char sig_done[16]={
    'd', 'o', 'n', 'e', 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
  const unsigned char sig_next[16]={
    'n', 'e', 'x', 't', 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
  file_search_footer(file_recovery, sig_next, sizeof(sig_next), 60);
  if(file_recovery->file_size!=0)
    return ;
  file_recovery->file_size=tmp;
  file_search_footer(file_recovery, sig_done, sizeof(sig_done), 60);
}

static int header_check_e01(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct ewf_file_header *ewf=(const struct ewf_file_header *)buffer;
  static char ext[4];
  reset_file_recovery(file_recovery_new);
  ext[0]='E'+le16(ewf->fields_segment)/100;
  ext[1]='0'+(le16(ewf->fields_segment)%100)/10;
  ext[2]='0'+(le16(ewf->fields_segment)%10);
  ext[3]='\0';
  file_recovery_new->extension=(const char*)&ext;
  file_recovery_new->file_check=&file_check_e01;
  return 1;
}

static void register_header_check_e01(file_stat_t *file_stat)
{
  static const unsigned char e01_header[9]=  {
    'E' , 'V' , 'F' , 0x09, 0x0d, 0x0a, 0xff, 0x00,
    0x01
  };
  register_header_check(0, e01_header, sizeof(e01_header), &header_check_e01, file_stat);
}
