/*

    File: file_lzh.c

    Copyright (C) 2013 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_lzh)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include <ctype.h>
#include "types.h"
#include "filegen.h"
#include "log.h"

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_lzh(file_stat_t *file_stat);

const file_hint_t file_hint_lzh= {
  .extension="lzh",
  .description="lzh/LArc archive",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_lzh
};

struct lzh_level0
{
  uint8_t  header_size;
  uint8_t  header_crc;
  uint8_t  method_id[5];
  uint32_t comp_size;
  uint32_t uncomp_size;
  uint32_t file_time;
  uint8_t  attrib;
  uint8_t  level;
  uint8_t  filename_len;
  /* Size should be 0, be carefull when using sizeof to decrement */
#ifndef DISABLED_FOR_FRAMAC
  uint8_t  filename[0];
#endif
} __attribute__ ((gcc_struct, __packed__));

struct lzh_level1
{
  uint8_t  header_size;
  uint8_t  header_crc;
  uint8_t  method_id[5];
  uint32_t comp_size;
  uint32_t uncomp_size;
  uint32_t file_time;
  uint8_t  reserved_20;
  uint8_t  level;
  uint8_t  filename_len;
#ifndef DISABLED_FOR_FRAMAC
  uint8_t  filename[0];
#endif
} __attribute__ ((gcc_struct, __packed__));

struct lzh_level2
{
  uint16_t header_size;
  uint8_t  method_id[5];
  uint32_t comp_size;
  uint32_t uncomp_size;
  uint32_t file_time_unix;
  uint8_t  reserved;
  uint8_t  level;
  uint16_t file_crc;
  uint8_t  os_id;
  uint16_t next_header_size;
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires file_recovery->file_rename==&file_rename_level0;
  @ requires valid_file_rename_param(file_recovery);
  @ ensures  valid_file_rename_result(file_recovery);
  @*/
static void file_rename_level0(file_recovery_t *file_recovery)
{
  unsigned char buffer[512];
  FILE *file;
  size_t buffer_size;
  unsigned int i;
  const struct lzh_level0 *hdr=(const struct lzh_level0 *)&buffer;
  const char *fn=(const char *)hdr + sizeof(struct lzh_level0);
  if((file=fopen(file_recovery->filename, "rb"))==NULL)
    return;
  buffer_size=fread(buffer, 1, sizeof(buffer), file);
  fclose(file);
  if(buffer_size < sizeof(struct lzh_level0))
    return;
  if(buffer_size < sizeof(struct lzh_level0) + hdr->filename_len)
    return;
  /*@ assert sizeof(struct lzh_level0) + hdr->filename_len <= buffer_size; */
  /*@
    @ loop invariant 0 <= i <= hdr->filename_len;
    @ loop assigns i;
    @ loop variant hdr->filename_len - i;
    @*/
  for(i=0; i< hdr->filename_len && fn[i]!=0 && fn[i]!='.'; i++);
  /*@ assert 0 <= i <= hdr->filename_len; */
  file_rename(file_recovery, fn, i, 0, NULL, 1);
}

/*@
  @ requires buffer_size >= sizeof(struct lzh_level0);
  @ requires buffer_size >= sizeof(struct lzh_level1);
  @ requires separation: \separated(&file_hint_lzh, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_lzh(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  switch(buffer[20])
  {
    /* Level 0 */
    case 0:
      {
	const struct lzh_level0 *hdr=(const struct lzh_level0 *)buffer;
	if(hdr->header_size!=22+hdr->filename_len)
	  return 0;
	reset_file_recovery(file_recovery_new);
	file_recovery_new->extension=file_hint_lzh.extension;
	file_recovery_new->file_rename=&file_rename_level0;
	return 1;
      }
      /* Level 1 */
    case 1:
      {
	const struct lzh_level1 *hdr=(const struct lzh_level1 *)buffer;
	if(hdr->reserved_20!=0x20)
	  return 0;
	reset_file_recovery(file_recovery_new);
	file_recovery_new->extension=file_hint_lzh.extension;
	return 1;
      }
      /* Level 2 */
    case 2:
      {
	//	const struct lzh_level2 *hdr=(const struct lzh_level2 *)buffer;
	reset_file_recovery(file_recovery_new);
	file_recovery_new->extension=file_hint_lzh.extension;
	return 1;
      }
  }
  return 0;
}

static void register_header_check_lzh(file_stat_t *file_stat)
{
  register_header_check(2, "-lh0-", 5, &header_check_lzh, file_stat);
#ifndef DISABLED_FOR_FRAMAC
  register_header_check(2, "-lh1-", 5, &header_check_lzh, file_stat);
  register_header_check(2, "-lh2-", 5, &header_check_lzh, file_stat);
  register_header_check(2, "-lh3-", 5, &header_check_lzh, file_stat);
  register_header_check(2, "-lh4-", 5, &header_check_lzh, file_stat);
  register_header_check(2, "-lh5-", 5, &header_check_lzh, file_stat);
  register_header_check(2, "-lh6-", 5, &header_check_lzh, file_stat);
  register_header_check(2, "-lh7-", 5, &header_check_lzh, file_stat);
  register_header_check(2, "-lhd-", 5, &header_check_lzh, file_stat);
  register_header_check(2, "-lzs-", 5, &header_check_lzh, file_stat);
  register_header_check(2, "-lz4-", 5, &header_check_lzh, file_stat);
#endif
}
#endif
