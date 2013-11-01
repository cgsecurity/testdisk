/*

    File: file_ra.c

    Copyright (C) 2007 Christophe GRENIER <grenier@cgsecurity.org>
  
    This software is free software; you can redistribute it and/or modify
    it under the teras of the GNU General Public License as published by
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
#include "common.h"
#include "filegen.h"

static void register_header_check_ra(file_stat_t *file_stat);

const file_hint_t file_hint_ra= {
  .extension="ra",
  .description="Real Audio",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_ra
};

struct ra3_header {
  char magic[4];
  uint16_t version;	/* 3 */
  uint16_t header_size;	/* not including first 8 bytes */
  char unk1[10];
  uint32_t data_size;
  uint8_t title_length;
  char title[0];
} __attribute__ ((__packed__));

struct ra4_header {
  char magic[4];
  uint16_t version;	/* 4 */
  uint16_t unused;	/* always 0 */
  char sign[4];		/* .ra4 */
  uint32_t data_size;
  uint16_t version2;
  uint16_t header_size;	/* not including the first 20 bytes ? */
  uint16_t codec_flavor;
  uint32_t codec_frame_size;
  char     unk1[12];
  uint16_t sub_packet_h;
  uint16_t frame_size;
  uint16_t subpacket_size;
  uint16_t unk2;
  uint16_t samplerate;
  uint16_t unk3;
  uint16_t sample_size;
  uint16_t channels;
  char     interleaver_ID_length; /* always 4 */
  char     interleaver_ID[4];
  char     FourCC_length; 	/* always 4 */
  char	   FourCC_string[4];
  char     unk4[3];
  uint8_t  title_length;
  char     title[0];
} __attribute__ ((__packed__));


static int header_check_ra(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(buffer[4]==0x00 && buffer[5]==0x03)
  { /* V3 */
    const struct ra3_header *ra3=(const struct ra3_header *)buffer;
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_ra.extension;
    file_recovery_new->calculated_file_size=8 + be16(ra3->header_size) + be32(ra3->data_size);
    file_recovery_new->data_check=&data_check_size;
    file_recovery_new->file_check=&file_check_size;
    return 1;
  }
  else if(buffer[4]==0x00 && buffer[5]==0x04 &&
      buffer[8]=='.' && buffer[9]=='r' && buffer[10]=='a' && buffer[11]=='4')
  { /* V4 */
    const struct ra4_header *ra4=(const struct ra4_header *)buffer;
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_ra.extension;
    file_recovery_new->calculated_file_size=40 + be16(ra4->header_size) + be32(ra4->data_size);
    file_recovery_new->data_check=&data_check_size;
    file_recovery_new->file_check=&file_check_size;
    return 1;
  }
  return 0;
}

static void register_header_check_ra(file_stat_t *file_stat)
{
  static const unsigned char ra_header[4]  = { '.', 'r', 'a', 0xfd};
  register_header_check(0, ra_header,sizeof(ra_header), &header_check_ra, file_stat);
}
