/*

    File: file_ext2_fs.c

    Copyright (C) 1998-2005,2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include "common.h"
#include "ext2.h"
#include "filegen.h"

static void register_header_check_ext2_fs(file_stat_t *file_stat);
static int header_check_ext2_fs(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_ext2_fs= {
  .extension="ext",
  .description="ext2/ext3/ext4 Filesystem",
  .min_header_distance=0,
  .max_filesize=0,
  .recover=1,
  .enable_by_default=0,
  .register_header_check=&register_header_check_ext2_fs
};

static const unsigned char ext2_fs_header[2]= {0x53, 0xEF};

static void register_header_check_ext2_fs(file_stat_t *file_stat)
{
  register_header_check(0x438, ext2_fs_header,sizeof(ext2_fs_header), &header_check_ext2_fs, file_stat);
}

static int header_check_ext2_fs(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct ext2_super_block *sb=(const struct ext2_super_block *)&buffer[0x400];
  if(le16(sb->s_magic)!=EXT2_SUPER_MAGIC)
    return 0;
  if (le32(sb->s_free_blocks_count) >= le32(sb->s_blocks_count))
    return 0;
  if (le32(sb->s_free_inodes_count) >= le32(sb->s_inodes_count))
    return 0;
  if (le16(sb->s_errors)!=0 &&
      (le16(sb->s_errors) != EXT2_ERRORS_CONTINUE) &&
      (le16(sb->s_errors) != EXT2_ERRORS_RO) &&
      (le16(sb->s_errors) != EXT2_ERRORS_PANIC))
    return 0;
  if ((le16(sb->s_state) & ~(EXT2_VALID_FS | EXT2_ERROR_FS))!=0)
    return 0;
  if (le32(sb->s_blocks_count) == 0) /* reject empty filesystem */
    return 0;
  if(le32(sb->s_log_block_size)>2)  /* block size max = 4096, can be 8192 on alpha */
    return 0;
  if(le16(sb->s_block_group_nr)!=0)
    return 0;
  if(file_recovery!=NULL && file_recovery->file_stat!=NULL &&
       file_recovery->file_stat->file_hint==&file_hint_ext2_fs &&
       file_recovery->calculated_file_size==(uint64_t)le32(sb->s_blocks_count)*(EXT2_MIN_BLOCK_SIZE<<le32(sb->s_log_block_size)))
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_ext2_fs.extension;
  file_recovery_new->calculated_file_size=(uint64_t)le32(sb->s_blocks_count)*(EXT2_MIN_BLOCK_SIZE<<le32(sb->s_log_block_size));
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}
