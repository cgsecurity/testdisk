/*

    File: file_gsm.c

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
#include "log.h"
#include "memmem.h"

static void register_header_check_gsm(file_stat_t *file_stat);

const file_hint_t file_hint_gsm= {
  .extension="gsm",
  .description="Group Speciale Mobile GSM 06.10",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=0,
  .register_header_check=&register_header_check_gsm
};

struct block_header
{
  unsigned char marker;
  unsigned char payload[32];
} __attribute__ ((gcc_struct, __packed__));

static data_check_t data_check_gsm(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + sizeof(struct block_header) < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size - file_recovery->file_size + buffer_size/2;
    const struct block_header *hdr=(const struct block_header *)&buffer[i];
    if(hdr->marker < 0xd0 || hdr->marker > 0xdf)
      return DC_STOP;
    file_recovery->calculated_file_size+=sizeof(struct block_header);
  }
  return DC_CONTINUE;
}

static int header_check_gsm(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct block_header *hdr;
  unsigned int i=0;
  for(i=0, hdr=(const struct block_header *)buffer;
      i * sizeof(struct block_header) < file_recovery_new->blocksize;
      i++, hdr++)
  {
    if(hdr->marker < 0xd0 || hdr->marker > 0xdf)
      return 0;
  }
  if(i<3)
    return 0;
  if(file_recovery->file_stat!=NULL
      &&  file_recovery->file_stat->file_hint==&file_hint_gsm)
  {
    header_ignored(file_recovery_new);
    return 0;
  }
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_gsm.extension;
  file_recovery_new->min_filesize=sizeof(struct block_header);
  file_recovery_new->calculated_file_size=0;
  file_recovery_new->data_check=&data_check_gsm;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static void register_header_check_gsm(file_stat_t *file_stat)
{
  static const unsigned char gsm_header1[1]={ 0xd0 };
  static const unsigned char gsm_header2[1]={ 0xd1 };
  static const unsigned char gsm_header3[1]={ 0xd2 };
  static const unsigned char gsm_header4[1]={ 0xd3 };
  static const unsigned char gsm_header5[1]={ 0xd4 };
  static const unsigned char gsm_header6[1]={ 0xd5 };
  static const unsigned char gsm_header7[1]={ 0xd6 };
  static const unsigned char gsm_header8[1]={ 0xd7 };
  static const unsigned char gsm_header9[1]={ 0xd8 };
  static const unsigned char gsm_header10[1]={ 0xd9 };
  static const unsigned char gsm_header11[1]={ 0xda };
  static const unsigned char gsm_header12[1]={ 0xdb };
  static const unsigned char gsm_header13[1]={ 0xdc };
  static const unsigned char gsm_header14[1]={ 0xdd };
  static const unsigned char gsm_header15[1]={ 0xde };
  static const unsigned char gsm_header16[1]={ 0xdf };

  register_header_check(0, gsm_header1, sizeof(gsm_header1), &header_check_gsm, file_stat);
  register_header_check(0, gsm_header2, sizeof(gsm_header2), &header_check_gsm, file_stat);
  register_header_check(0, gsm_header3, sizeof(gsm_header3), &header_check_gsm, file_stat);
  register_header_check(0, gsm_header4, sizeof(gsm_header4), &header_check_gsm, file_stat);
  register_header_check(0, gsm_header5, sizeof(gsm_header5), &header_check_gsm, file_stat);
  register_header_check(0, gsm_header6, sizeof(gsm_header6), &header_check_gsm, file_stat);
  register_header_check(0, gsm_header7, sizeof(gsm_header7), &header_check_gsm, file_stat);
  register_header_check(0, gsm_header8, sizeof(gsm_header8), &header_check_gsm, file_stat);
  register_header_check(0, gsm_header9, sizeof(gsm_header9), &header_check_gsm, file_stat);
  register_header_check(0, gsm_header10, sizeof(gsm_header10), &header_check_gsm, file_stat);
  register_header_check(0, gsm_header11, sizeof(gsm_header11), &header_check_gsm, file_stat);
  register_header_check(0, gsm_header12, sizeof(gsm_header12), &header_check_gsm, file_stat);
  register_header_check(0, gsm_header13, sizeof(gsm_header13), &header_check_gsm, file_stat);
  register_header_check(0, gsm_header14, sizeof(gsm_header14), &header_check_gsm, file_stat);
  register_header_check(0, gsm_header15, sizeof(gsm_header15), &header_check_gsm, file_stat);
  register_header_check(0, gsm_header16, sizeof(gsm_header16), &header_check_gsm, file_stat);
}
