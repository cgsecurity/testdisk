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

static void register_header_check_lzh(file_stat_t *file_stat);

const file_hint_t file_hint_lzh= {
  .extension="lzh",
  .description="lzh/LArc archive",
  .min_header_distance=0,
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
  uint8_t  filename[0];
} __attribute__ ((__packed__));

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
  uint8_t  filename[0];
} __attribute__ ((__packed__));

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
} __attribute__ ((__packed__));

static void file_rename_level0(const char *old_filename)
{
  unsigned char buffer[512];
  FILE *file;
  size_t buffer_size;
  unsigned int i;
  const struct lzh_level0 *hdr=(const struct lzh_level0 *)&buffer;
  if((file=fopen(old_filename, "rb"))==NULL)
    return;
  buffer_size=fread(buffer, 1, sizeof(buffer), file);
  fclose(file);
  if(buffer_size<sizeof(struct lzh_level0))
    return;
  for(i=0; i< hdr->filename_len && hdr->filename[i]!=0 && hdr->filename[i]!='.'; i++);
  file_rename(old_filename, hdr->filename, i, 0, NULL, 1);
}

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
}
