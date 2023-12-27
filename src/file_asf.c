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
#include "log.h"

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_asf)
/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_asf(file_stat_t *file_stat);

const file_hint_t file_hint_asf= {
  .extension="asf",
  .description="ASF, WMA, WMV: Advanced Streaming Format used for Audio/Video",
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
} __attribute__ ((gcc_struct, __packed__));

struct asf_file_prop_s {
  unsigned char object_id[16];
  uint64_t      object_size;
  unsigned char file_id[16];
  uint64_t      file_size;
  int64_t       file_date;
} __attribute__ ((gcc_struct, __packed__));

struct asf_stream_prop_s {
  unsigned char object_id[16];
  uint64_t      object_size;
  unsigned char stream_type[16];
} __attribute__ ((gcc_struct, __packed__));

static const char *extension_wma="wma";
static const char *extension_wmv="wmv";

/*@
  @ requires buffer_size > sizeof(struct asf_header_obj_s);
  @ requires separation: \separated(&file_hint_asf, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_asf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct asf_header_obj_s *hdr=(const struct asf_header_obj_s*)buffer;
  const char *extension=file_hint_asf.extension;
  const unsigned int nbr_header_obj=le32(hdr->nbr_header_obj);
  uint64_t size=0;
  time_t time=0;
  unsigned int i;
  uint64_t offset_prop=sizeof(struct asf_header_obj_s);
  /* Header + File Properties + Stream Properties + Header Extension */
  if(le64(hdr->object_size)<30 ||
      le64(hdr->object_size) >= PHOTOREC_MAX_FILE_SIZE ||
      nbr_header_obj<4)
    return 0;
  /*@
    @ loop assigns extension, i, size, time, offset_prop;
    @ loop variant nbr_header_obj - i;
    @*/
  for(i=0;
      i < nbr_header_obj && offset_prop + 0x28 < buffer_size;
      i++)
  {
    const struct asf_file_prop_s *prop=(const struct asf_file_prop_s*)&buffer[offset_prop];
    const uint64_t object_size=le64(prop->object_size);
    // ASF_File_Properties_Object   // 8CABDCA1-A947-11CF-8EE4-00C00C205365
    // ASF_Stream_Properties_Object // B7DC0791-A9B7-11CF-8EE6-00C00C205365
    static const unsigned char asf_file_prop_id[16]= {
      0xa1, 0xdc, 0xab, 0x8c, 0x47, 0xa9, 0xcf, 0x11,
      0x8e, 0xe4, 0x00, 0xc0, 0x0c, 0x20, 0x53, 0x65
    };
    static const unsigned char asf_stream_prop_s[16]= {
      0x91, 0x07, 0xdc, 0xb7, 0xb7, 0xa9, 0xcf, 0x11,
      0x8e, 0xe6, 0x00, 0xc0, 0x0c, 0x20, 0x53, 0x65
    };
    if(object_size < 0x18)
    {
#ifndef DISABLED_FOR_FRAMAC
      log_info("header_check_asf object_size too small %llu\n", (long long unsigned)object_size);
#endif
      return 0;
    }
    if(object_size > 0x8000000000000000)
      return 0;
    if(memcmp(prop->object_id, asf_file_prop_id, sizeof(asf_file_prop_id))==0)
    {
      if(object_size < 0x28)
	return 0;
      size=le64(prop->file_size);
      if(size < sizeof(struct asf_header_obj_s) + sizeof(struct asf_file_prop_s))
	return 0;
      time=td_ntfs2utc(le64(prop->file_date));
    }
    else if(memcmp(prop->object_id, asf_stream_prop_s, sizeof(asf_stream_prop_s))==0)
    {
      const struct asf_stream_prop_s *stream=(const struct asf_stream_prop_s *)prop;
      const unsigned char wma[16]={
	0x40, 0x9e, 0x69, 0xf8, 0x4d, 0x5b, 0xcf, 0x11, 0xa8, 0xfd, 0x00, 0x80, 0x5f, 0x5c, 0x44, 0x2b
      };
      const unsigned char wmv[16]={
	0xc0, 0xef, 0x19, 0xbc, 0x4d, 0x5b, 0xcf, 0x11, 0xa8, 0xfd, 0x00, 0x80, 0x5f, 0x5c, 0x44, 0x2b
      };
      if(object_size < 0x28)
	return 0;
      if(memcmp(stream->stream_type, wma, sizeof(wma))==0)
	extension=extension_wma;
      else if(memcmp(stream->stream_type, wmv, sizeof(wmv))==0)
	extension=extension_wmv;
    }
    offset_prop+=object_size;
  }
  if(size > 0 && size < offset_prop)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=extension;
  file_recovery_new->min_filesize=offset_prop;
  file_recovery_new->time=time;
  if(size > 0)
  {
    file_recovery_new->calculated_file_size=size;
    file_recovery_new->data_check=&data_check_size;
    file_recovery_new->file_check=&file_check_size;
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
#endif
