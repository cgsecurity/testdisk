/*

    File: file_dpx.c

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_dpx)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#include <stdio.h>
#include "types.h"
#include "filegen.h"
#include "common.h"

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_dpx(file_stat_t *file_stat);

const file_hint_t file_hint_dpx= {
  .extension="dpx",
  .description="Cineon image file/SMTPE DPX",
  .max_filesize=10*1024*1024,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_dpx
};

/* Header information from http://www.cineon.com/ff_draft.php */
struct header_dpx
{
  uint32_t   	magic_num;        /* magic number 0x53445058 (SDPX) or 0x58504453 (XPDS) */
  uint32_t   	offset;           /* offset to image data in bytes */
  char		vers[8];          /* which header format version is being used (v1.0)*/
  uint32_t   	file_size;        /* file size in bytes */
  uint32_t   	ditto_key;        /* read time short cut - 0 = same, 1 = new */
  uint32_t   	gen_hdr_size;     /* generic header length in bytes */
  uint32_t   	ind_hdr_size;     /* industry header length in bytes */
  uint32_t   	user_data_size;   /* user-defined data length in bytes */
  char 		file_name[100];   /* image file name */
  char 		create_time[24];  /* file creation date "yyyy:mm:dd:hh:mm:ss:LTZ" */
  char 		creator[100];     /* file creator's name */
  char 		project[200];     /* project name */
  char 		copyright[200];   /* right to use or copyright info */
  uint32_t   	key;              /* encryption ( FFFFFFFF = unencrypted ) */
  char 		Reserved[104];    /* reserved field TBD (need to pad) */
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires buffer_size >= sizeof(struct header_dpx);
  @ requires separation: \separated(&file_hint_dpx, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_dpx(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  static const unsigned char ver10[8]= 	   {'V', '1', '.', '0', 0x00, 0x00, 0x00, 0x00};
  const struct header_dpx *dpx=(const struct header_dpx *)buffer;
  const unsigned int file_size=be32(dpx->file_size);
  if(memcmp(dpx->vers, ver10, sizeof(ver10))==0)
  {
    if(file_size < sizeof(struct header_dpx))
      return 0;
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_dpx.extension;
    file_recovery_new->calculated_file_size=file_size;
    file_recovery_new->data_check=&data_check_size;
    file_recovery_new->file_check=&file_check_size;
    file_recovery_new->time=get_time_from_YYYY_MM_DD_HH_MM_SS(dpx->create_time);
    return 1;
  }
  return 0;
}

static void register_header_check_dpx(file_stat_t *file_stat)
{
  register_header_check(0, "SDPX", 4, &header_check_dpx, file_stat);
#ifndef DISABLED_FOR_FRAMAC
  register_header_check(0, "XPDS", 4, &header_check_dpx, file_stat);
#endif
}
#endif
