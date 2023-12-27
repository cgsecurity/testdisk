/*

    File: file_mxf.c

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
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mxf)
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

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_mxf(file_stat_t *file_stat);

const file_hint_t file_hint_mxf= {
  .extension="mxf",
  .description="Material Exchange Format",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_mxf
};

/* http://tools.ietf.org/html/rfc4539
 * Media Type Registration for the
 * Society of Motion Picture and Television Engineers (SMPTE)
 * Material Exchange Format (MXF)
 * */

struct partition_pack_next
{
  uint16_t major_version;
  uint16_t minor_version;
  uint32_t kagsize;
  uint64_t this_partition;
  uint64_t previous_partition;
  uint64_t footer_partition;
  uint64_t header_byte_count;
  uint64_t index_byte_count;
  uint32_t index_SID;
  uint64_t body_offset;
  uint32_t body_SID;
  char	   op_pattern[16];
#ifndef DISABLED_FOR_FRAMAC
  char     essence_container[0];
#endif
} __attribute__ ((gcc_struct, __packed__));


/*@
  @ requires \valid_read(buffer + (0 .. buffer_size-1));
  @ requires 0 <= i < buffer_size - 0x14;
  @ terminates \true;
  @ ensures \result > 0;
  @ assigns \nothing;
  @*/
static uint64_t get_mxf_size(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int i)
{
  switch(buffer[i+0x10])
  {
    case 0x81:
      return (uint64_t)0x14+buffer[i+0x11];
    case 0x82:
      return (uint64_t)0x14+(buffer[i+0x11]<<8)+buffer[i+0x12];
    case 0x83:
      return (uint64_t)0x14+(buffer[i+0x11]<<16)+(buffer[i+0x12]<<8)+buffer[i+0x13];
    case 0x84:
      {
	const uint32_t *p32=(const uint32_t*)&buffer[i+0x11];
	return (uint64_t)0x14 + le32(*p32);
      }
    default:
      return (uint64_t)0x14+buffer[i+0x10];
  }
}

/*@
  @ requires file_recovery->data_check==&data_check_mxf;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ assigns file_recovery->calculated_file_size;
  @*/
static data_check_t data_check_mxf(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  static const unsigned char mxf_header[4]= { 0x06, 0x0e, 0x2b, 0x34 };
  /*@
    @ loop assigns file_recovery->calculated_file_size;
    @ loop variant file_recovery->file_size + buffer_size/2 - (file_recovery->calculated_file_size + 0x14);
    @*/
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 0x14 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size + buffer_size/2 - file_recovery->file_size;
    /*@ assert 0 <= i < buffer_size - 0x14; */
    if(memcmp(&buffer[i], mxf_header, sizeof(mxf_header))!=0)
      return DC_STOP;
#ifdef DEBUG_MXF
    log_info("data_check_mxf: header found 0x%02x\n", buffer[i+0x10]);
    log_info("fs=0x%llx\n", file_recovery->calculated_file_size);
#endif
    file_recovery->calculated_file_size+=get_mxf_size(buffer, buffer_size, i);
  }
  return DC_CONTINUE;
}

/*@
  @ requires buffer_size >= 0x26;
  @ requires separation: \separated(&file_hint_mxf, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_mxf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct partition_pack_next *hdr;
  if(buffer[0x0d]!=0x02 || buffer[0x0e]!=0x04)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_mxf.extension;
  switch(buffer[0x10])
  {
    case 0x81:
      hdr=(const struct partition_pack_next *)&buffer[0x12];
      break;
    case 0x82:
      hdr=(const struct partition_pack_next *)&buffer[0x13];
      break;
    case 0x83:
      hdr=(const struct partition_pack_next *)&buffer[0x14];
      break;
    case 0x84:
      hdr=(const struct partition_pack_next *)&buffer[0x15];
      break;
    default:
      hdr=(const struct partition_pack_next *)&buffer[0x11];
      break;
  }
  file_recovery_new->calculated_file_size=be64(hdr->footer_partition);
  file_recovery_new->data_check=&data_check_mxf;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static void register_header_check_mxf(file_stat_t *file_stat)
{
  static const unsigned char mxf_header[11]= {
    0x06, 0x0e, 0x2b, 0x34, 0x02, 0x05, 0x01, 0x01,
    0x0d, 0x01, 0x02
  };
  register_header_check(0, mxf_header,sizeof(mxf_header), &header_check_mxf, file_stat);
}
#endif
