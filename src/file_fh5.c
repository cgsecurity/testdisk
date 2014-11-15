/*

    File: file_fh5.c

    Copyright (C) 2007 Christophe GRENIER <grenier@cgsecurity.org>
    Copyright (C) 2007 Peter Turczak <pspamt@netconsequence.de>
  
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
#include "common.h"
#include "filegen.h"

struct fh5_header_s
{
  unsigned char   id[8];
  uint32_t        datalen;    /* Big Endian size w/o headers */
} __attribute__ ((__packed__));
typedef struct fh5_header_s fh5_header_t;

static void register_header_check_fh5(file_stat_t *file_stat);

const file_hint_t file_hint_fh5= {
  .extension="fh5",
  .description="Macromedia Freehand 5",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_fh5
};

static void file_check_fh5(file_recovery_t *file_recovery)
{
  if(file_recovery->file_size < file_recovery->calculated_file_size)
    file_recovery->file_size=0;
  else if(file_recovery->file_size> file_recovery->calculated_file_size+4096)
    file_recovery->file_size=file_recovery->calculated_file_size+4096;
}

static int header_check_fh5(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const fh5_header_t *fh5_buffer=(const fh5_header_t *) buffer;
  if((const uint32_t)be32(fh5_buffer->datalen) < sizeof(struct fh5_header_s))
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->min_filesize=4096;
  file_recovery_new->calculated_file_size=be32(fh5_buffer->datalen);
  file_recovery_new->extension=file_hint_fh5.extension;
  file_recovery_new->file_check=file_check_fh5;
  //    log_debug("header_check_fh5: Guessed length : %u\n", fh5_file_size);
  return 1;
}

static void register_header_check_fh5(file_stat_t *file_stat)
{
  static const unsigned char fh5_header[8] = { 0x41, 0x47, 0x44, 0x31, 0xbe, 0xb8, 0xbb, 0xce };
  register_header_check(0, fh5_header,sizeof(fh5_header), &header_check_fh5, file_stat);
}
