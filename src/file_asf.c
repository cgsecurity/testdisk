/*

    File: file_asf.c

    Copyright (C) 1998-2010 Christophe GRENIER <grenier@cgsecurity.org>
  
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

static void register_header_check_asf(file_stat_t *file_stat);
static int header_check_asf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_asf= {
  .extension="asf",
  .description="ASF, WMA, WMV: Advanced Streaming Format used for Audio/Video",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_asf
};

struct asf_header_obj_s {
  unsigned char object_id[16];
  uint64_t	object_size;
  uint32_t	nbr_header_obj;
  char		reserved1;	/* 1 */
  char		reserved2;	/* 2 */
} __attribute__ ((__packed__));

struct asf_file_prop_s {
  unsigned char object_id[16];
  uint64_t      object_size;
  unsigned char file_id[16];
  uint64_t      file_size;
  uint64_t      file_date;
} __attribute__ ((__packed__));

static int header_check_asf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct asf_header_obj_s *asf_header_obj=(const struct asf_header_obj_s *)buffer;
  const struct asf_file_prop_s  *asf_file_prop=(const struct asf_file_prop_s*)(asf_header_obj+1);
  unsigned int i;
  if(le64(asf_header_obj->object_size)<30 ||
      le64(asf_header_obj->object_size)>buffer_size)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_asf.extension;
  for(i=0;
      i<le32(asf_header_obj->nbr_header_obj) &&
      (const unsigned char *)(asf_file_prop+1) < buffer + buffer_size;
      i++)
  {
    static const unsigned char asf_file_prop_id[16]= {
      0xa1, 0xdc, 0xab, 0x8c, 0x47, 0xa9, 0xcf, 0x11, 
      0x8e, 0xe4, 0x00, 0xc0, 0x0c, 0x20, 0x53, 0x65
    };
    if(memcmp(asf_file_prop->object_id, asf_file_prop_id, sizeof(asf_file_prop_id))==0)
    {
      file_recovery_new->calculated_file_size=le64(asf_file_prop->file_size);
      file_recovery_new->data_check=&data_check_size;
      file_recovery_new->file_check=&file_check_size;
      file_recovery_new->time=td_ntfs2utc(le64(asf_file_prop->file_date));
      return 1;
    }
    if( le64(asf_file_prop->object_size)==0 ||
	le64(asf_file_prop->object_size)>1024*1024)
      return 1;
    asf_file_prop=(const struct asf_file_prop_s *)((const char *)asf_file_prop + le64(asf_file_prop->object_size));
  }
  return 1;
}

static void register_header_check_asf(file_stat_t *file_stat)
{
  static const unsigned char asf_header[16]= {
    0x30, 0x26, 0xb2, 0x75, 0x8e, 0x66, 0xcf, 0x11, 
    0xa6, 0xd9, 0x00, 0xaa, 0x00, 0x62, 0xce, 0x6c
  };
  register_header_check(0, asf_header,sizeof(asf_header), &header_check_asf, file_stat);
}
