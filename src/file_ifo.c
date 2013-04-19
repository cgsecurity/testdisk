/*

    File: file_ifo.c

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
#include "common.h"

static void register_header_check_ifo(file_stat_t *file_stat);
static int header_check_ifo(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_ifo= {
  .extension="ifo",
  .description="DVD Video manager or title set",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_ifo
};

static const unsigned char ifo_header_vmg[12]=  { 'D', 'V', 'D', 'V', 'I', 'D', 'E', 'O', '-', 'V', 'M', 'G'};
static const unsigned char ifo_header_vts[12]=  { 'D', 'V', 'D', 'V', 'I', 'D', 'E', 'O', '-', 'V', 'T', 'S'};

static void register_header_check_ifo(file_stat_t *file_stat)
{
  register_header_check(0, ifo_header_vmg, sizeof(ifo_header_vmg), &header_check_ifo, file_stat);
  register_header_check(0, ifo_header_vts, sizeof(ifo_header_vts), &header_check_ifo, file_stat);
}

struct ifo_hdr
{
  char 	   name[12];
  uint32_t ls_BUP[4];
  uint32_t ls_IFO;
} __attribute__ ((__packed__));

static int header_check_ifo(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(buffer, ifo_header_vmg, sizeof(ifo_header_vmg))==0 ||
    memcmp(buffer, ifo_header_vts, sizeof(ifo_header_vts))==0)
  {
    const struct ifo_hdr *hdr=(const struct ifo_hdr *)buffer;
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_ifo.extension;
    file_recovery_new->calculated_file_size=((uint64_t)be32(hdr->ls_IFO)+1)*2048;
    file_recovery_new->data_check=&data_check_size;
    file_recovery_new->file_check=&file_check_size;
    return 1;
  }
  return 0;
}


