/*

    File: file_shp.c

    Copyright (C) 2023 Grzegorz Szymaszek <gszymaszek@short.pl>

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_shp)
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

/*@
  @ requires valid_register_header_check(file_stat);
  @*/
static void register_header_check_shp(file_stat_t *file_stat);

const file_hint_t file_hint_shp= {
  .extension="shp",
  .description="ESRI Shapefile",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_shp
};

static const uint8_t shp_header[4] = {0x00, 0x00, 0x27, 0x0a};

/* https://en.wikipedia.org/wiki/Shapefile */
struct shp_header
{
  int32_t magic;
  int32_t reserved[5];
  uint32_t size;
  int32_t version;
  int32_t shape_type;
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires buffer_size >= sizeof(struct shp_header);
  @ requires separation: \separated(&file_hint_shp, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures valid_header_check_result(\result, file_recovery_new);
  @ ensures (\result == 1) ==> (file_recovery_new->file_stat == \null);
  @ ensures (\result == 1) ==> (file_recovery_new->handle == \null);
  @ ensures (\result == 1) ==> (file_recovery_new->time == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->extension == file_hint_shp.extension);
  @ ensures (\result == 1) ==> (file_recovery_new->calculated_file_size >= 100);
  @ ensures (\result == 1) ==> (file_recovery_new->file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->min_filesize == 100);
  @ ensures (\result == 1) ==> (file_recovery_new->data_check == &data_check_size);
  @ ensures (\result == 1) ==> (file_recovery_new->file_check == &file_check_size);
  @ ensures (\result == 1) ==> (file_recovery_new->file_rename == \null);
  @ assigns file_recovery_new->filename[0];
  @ assigns file_recovery_new->time;
  @ assigns file_recovery_new->file_stat;
  @ assigns file_recovery_new->handle;
  @ assigns file_recovery_new->file_size;
  @ assigns file_recovery_new->location.list.prev;
  @ assigns file_recovery_new->location.list.next;
  @ assigns file_recovery_new->location.end;
  @ assigns file_recovery_new->location.data;
  @ assigns file_recovery_new->extension;
  @ assigns file_recovery_new->min_filesize;
  @ assigns file_recovery_new->calculated_file_size;
  @ assigns file_recovery_new->data_check;
  @ assigns file_recovery_new->file_check;
  @ assigns file_recovery_new->file_rename;
  @ assigns file_recovery_new->offset_error;
  @ assigns file_recovery_new->offset_ok;
  @ assigns file_recovery_new->checkpoint_status;
  @ assigns file_recovery_new->checkpoint_offset;
  @ assigns file_recovery_new->flags;
  @ assigns file_recovery_new->extra;
  @ assigns file_recovery_new->data_check_tmp;
  @*/
static int header_check_shp(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct shp_header *shp=(const struct shp_header *)buffer;
  const uint64_t size = (uint64_t)2 * be32(shp->size);

  if(le32(shp->version) != 1000)
    return 0;
  if(size < 100)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_shp.extension;
  file_recovery_new->min_filesize=100;
  file_recovery_new->calculated_file_size=size;
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static void register_header_check_shp(file_stat_t *file_stat)
{
  register_header_check(0, shp_header, sizeof(shp_header), &header_check_shp, file_stat);
}
#endif
