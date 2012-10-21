/*

    File: file_mft.c

    Copyright (C) 2012 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include "ntfs.h"

static void register_header_check_mft(file_stat_t *file_stat);
static int header_check_mft(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_mft= {
  .extension="mft",
  .description="NTFS MFT record",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=0,
  .enable_by_default=1,
  .register_header_check=&register_header_check_mft
};

static void file_rename_mft(const char *old_filename)
{
  unsigned char buffer[512];
  char buffer_cluster[32];
  FILE *file;
  int buffer_size;
  const struct ntfs_mft_record *record=(const struct ntfs_mft_record *)&buffer;
  if((file=fopen(old_filename, "rb"))==NULL)
    return;
  buffer_size=fread(buffer, 1, sizeof(buffer), file);
  fclose(file);
  if(buffer_size<54)
    return;
  sprintf(buffer_cluster, "record_%u", (unsigned int)le32(record->mft_record_number));
  file_rename(old_filename, buffer_cluster, strlen(buffer_cluster), 0, NULL, 1);
}

static int header_check_mft(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct ntfs_mft_record *mft_rec=(const struct ntfs_mft_record *)buffer;
  const unsigned int usa_ofs = le16(mft_rec->usa_ofs);
  const unsigned int usa_count = le16(mft_rec->usa_count);
  const unsigned int attrs_offset = le16(mft_rec->attrs_offset);
  const unsigned int bytes_in_use = le32(mft_rec->bytes_in_use);
  const unsigned int bytes_allocated = le32(mft_rec->bytes_allocated);
  if(!(memcmp(buffer,"FILE",4)==0 && 
    usa_ofs+usa_count <= attrs_offset &&
    42 <= attrs_offset &&
    attrs_offset%8==0 &&
    attrs_offset < bytes_in_use &&
    bytes_in_use <= bytes_allocated))
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_mft.extension;
  file_recovery_new->calculated_file_size=bytes_allocated;
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  file_recovery_new->file_rename=&file_rename_mft;
  return 1;
}

static void register_header_check_mft(file_stat_t *file_stat)
{
  register_header_check(0, "FILE", 4, &header_check_mft, file_stat);
}
