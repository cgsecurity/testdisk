/*

    File: file_bkf.c

    Copyright (C) 2006-2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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

static void register_header_check_bkf(file_stat_t *file_stat);
static int header_check_bkf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);
static void file_check_bkf(file_recovery_t *file_recovery);

const file_hint_t file_hint_bkf= {
  .extension="bkf",
  .description="MS Backup file",
  .min_header_distance=0,
  .max_filesize=-1,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_bkf
};

static const unsigned char bkf_header[4]= { 'T','A','P','E'};

static void register_header_check_bkf(file_stat_t *file_stat)
{
  register_header_check(0, bkf_header,sizeof(bkf_header), &header_check_bkf, file_stat);
}

static int header_check_bkf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(buffer,bkf_header,sizeof(bkf_header))==0 &&
    buffer[0x14]==0 && buffer[0x15]==0 && buffer[0x16]==0 && buffer[0x17]==0 &&
    buffer[0x18]==0 && buffer[0x19]==0 && buffer[0x1a]==0 && buffer[0x1b]==0 &&
    buffer[0x24]==0 && buffer[0x25]==0 && buffer[0x26]==0 && buffer[0x27]==0)
  {
    /* Microsoft Tape Format
     * The DBLK Type field is set to ‘TAPE’.
     * The Format Logical Address field is set to zero.
     * The Control Block ID field is set to zero.
     */
    reset_file_recovery(file_recovery_new);
    file_recovery_new->min_filesize=52;
    file_recovery_new->extension=file_hint_bkf.extension;
    file_recovery_new->file_check=&file_check_bkf;
    return 1;
  }
  return 0;
}

static void file_check_bkf(file_recovery_t *file_recovery)
{
  const unsigned char bkf_footer[4]= { 'S', 'F', 'M', 'B'};
  file_search_footer(file_recovery, bkf_footer, sizeof(bkf_footer), 0x400-4);
}
