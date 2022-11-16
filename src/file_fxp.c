/*

    File: file_fxp.c

    Copyright (C) 2022 Christophe GRENIER <grenier@cgsecurity.org>

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fxp)
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
static void register_header_check_fxp(file_stat_t *file_stat);

const file_hint_t file_hint_fxp= {
  .extension="fxp",
  .description="FX Preset files",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_fxp
};

struct fxp_header
{
  char magic[4];
  uint32_t size;
  char fxmagic[4];
  uint32_t version;
  char fxid[4];
  uint32_t fxversion;
  uint32_t numPrograms;
  char name[28];
  uint32_t chunksize;
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @*/
static int header_check_fxp(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct fxp_header *fxp=(const struct fxp_header *)buffer;
  if(be32(fxp->size) < sizeof(struct fxp_header))
    return 0;
  if(memcmp(&fxp->fxmagic, "FPCh", 4) != 0)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_fxp.extension;
  file_recovery_new->calculated_file_size=(uint64_t)be32(fxp->size);
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static void register_header_check_fxp(file_stat_t *file_stat)
{
  static const unsigned char fxp_header[4]=  { 'C' , 'c' , 'n' , 'K'   };
  register_header_check(0, fxp_header, sizeof(fxp_header), &header_check_fxp, file_stat);
}
#endif
