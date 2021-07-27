/*

    File: file_wmf.c

    Copyright (C) 2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_wmf)
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

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_wmf(file_stat_t *file_stat);

const file_hint_t file_hint_wmf = {
  .extension = "wmf",
  .description = "Microsoft Windows Metafile",
  .max_filesize = 50 * 1024 * 1024,
  .recover = 1,
  .enable_by_default = 1,
  .register_header_check = &register_header_check_wmf
};

struct wmf_header
{
  uint16_t type;
  uint16_t header_size;
  uint16_t version;
  uint32_t size;
  uint16_t num_objects;
  uint32_t max_record;
  uint16_t members;
} __attribute__((gcc_struct, __packed__));

struct wmf_placeable_record
{
  uint32_t key;
  uint16_t hwmf;
  uint64_t boundingbox;
  uint16_t inch;
  uint32_t reserved;
  uint16_t checksum;
} __attribute__((gcc_struct, __packed__));

/*@
  @ requires \valid_read(hdr);
  @ assigns  \nothing;
  @*/
static uint64_t wmf_check_meta_header(const struct wmf_header *hdr)
{
  const uint64_t size = (uint64_t)2 * le32(hdr->size);
  const unsigned int num_objects = le16(hdr->num_objects);
  const unsigned int max_record = le32(hdr->max_record);
  if(size < sizeof(struct wmf_header))
    return 0;
  if(num_objects == 0)
    return 0;
  if((uint64_t)2 * max_record + num_objects - 1 >= size)
    return 0;
  return size;
}

/*@
  @ requires buffer_size >= sizeof(struct wmf_header);
  @ requires separation: \separated(&file_hint_wmf, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_wmf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const uint64_t size = wmf_check_meta_header((const struct wmf_header *)buffer);
  if(size == 0)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension = file_hint_wmf.extension;
  file_recovery_new->calculated_file_size = size;
  file_recovery_new->data_check = &data_check_size;
  file_recovery_new->file_check = &file_check_size;
  return 1;
}

/*@
  @ requires buffer_size >= 0x16 + sizeof(struct wmf_header);
  @ requires separation: \separated(&file_hint_wmf, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_wmf_placeable(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct wmf_placeable_record *meta = (const struct wmf_placeable_record *)buffer;
  const struct wmf_header *hdr = (const struct wmf_header *)&buffer[0x16];
  uint64_t size;
  /* Check META_PLACEABLE */
  if(le32(meta->reserved) != 0)
    return 0;
  size = wmf_check_meta_header(hdr);
  if(size == 0)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension = file_hint_wmf.extension;
  file_recovery_new->calculated_file_size = 0x16 + size;
  file_recovery_new->data_check = &data_check_size;
  file_recovery_new->file_check = &file_check_size;
  return 1;
}

static void register_header_check_wmf(file_stat_t *file_stat)
{
  static const unsigned char apm_header[6] = { 0xd7, 0xcd, 0xc6, 0x9a, 0x00, 0x00 };
  /* WMF: file_type=disk, header size=9, version=3.0 */
  static const unsigned char wmf_header[6] = { 0x01, 0x00, 0x09, 0x00, 0x00, 0x03 };
  register_header_check(0, apm_header, sizeof(apm_header), &header_check_wmf_placeable, file_stat);
  register_header_check(0, wmf_header, sizeof(wmf_header), &header_check_wmf, file_stat);
}
#endif
