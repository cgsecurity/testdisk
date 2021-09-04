/*

    File: file_nds.c

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_nds)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "filegen.h"

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_nds(file_stat_t *file_stat);

const file_hint_t file_hint_nds= {
  .extension="nds",
  .description="Nintendo DS Game ROM Image",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_nds
};

/*@
  @ requires file_recovery->file_rename==&file_rename_nds;
  @ requires valid_file_rename_param(file_recovery);
  @ ensures  valid_file_rename_result(file_recovery);
  @*/
static void file_rename_nds(file_recovery_t *file_recovery)
{
  FILE *file;
  unsigned char buffer[12];
  if((file=fopen(file_recovery->filename, "rb"))==NULL)
    return;
  if(fread(&buffer, sizeof(buffer), 1, file) != 1)
  {
    fclose(file);
    return ;
  }
  fclose(file);
  file_rename(file_recovery, &buffer, 12, 0, file_hint_nds.extension, 0);
}

/*@
  @ requires buffer_size >= 0x10;
  @ requires separation: \separated(&file_hint_nds, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_nds(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(&buffer[0x0c], "NTRJ", 4)==0)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_nds.extension;
  file_recovery_new->min_filesize=0x180;
  file_recovery_new->file_rename=&file_rename_nds;
  return 1;
}

static void register_header_check_nds(file_stat_t *file_stat)
{
  static const unsigned char nds_header[6]=  {
    0x24, 0xff, 0xae, 0x51, 0x69, 0x9a
  };
  register_header_check(0xc0, nds_header, sizeof(nds_header), &header_check_nds, file_stat);
}
#endif
