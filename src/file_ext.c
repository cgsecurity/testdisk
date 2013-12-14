/*

    File: file_ext2_sb.c

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
#include "ext2_common.h"
#include "filegen.h"

static void register_header_check_ext2_sb(file_stat_t *file_stat);

const file_hint_t file_hint_ext2_sb= {
  .extension="ext",
  .description="ext2/ext3/ext4 Superblock",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=0,
  .enable_by_default=1,
  .register_header_check=&register_header_check_ext2_sb
};

static void file_rename_ext(const char *old_filename)
{
  unsigned char buffer[512];
  char buffer_cluster[32];
  FILE *file;
  const struct ext2_super_block *sb=(const struct ext2_super_block *)&buffer;
  int buffer_size;
  unsigned long int block_nr;
  if((file=fopen(old_filename, "rb"))==NULL)
    return;
  buffer_size=fread(buffer, 1, sizeof(buffer), file);
  fclose(file);
  if(buffer_size!=sizeof(buffer))
    return;
  block_nr=(le32(sb->s_first_data_block)+le16(sb->s_block_group_nr)*le32(sb->s_blocks_per_group));
  sprintf(buffer_cluster, "sb_%lu", block_nr);
  file_rename(old_filename, buffer_cluster, strlen(buffer_cluster), 0, NULL, 1);
}

static int header_check_ext2_sb(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct ext2_super_block *sb=(const struct ext2_super_block *)buffer;
  if(test_EXT2(sb, NULL)!=0)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_ext2_sb.extension;
  file_recovery_new->file_size=EXT2_MIN_BLOCK_SIZE<<le32(sb->s_log_block_size);
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  file_recovery_new->file_rename=&file_rename_ext;
  return 1;
}

static data_check_t data_check_extdir(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /* Save only one block */
  file_recovery->calculated_file_size=buffer_size/2;
  return DC_STOP;
}

static void file_rename_extdir(const char *old_filename)
{
  unsigned char buffer[512];
  char buffer_cluster[32];
  FILE *file;
  int buffer_size;
  const uint32_t *inode=(const uint32_t *)&buffer[0];
  if((file=fopen(old_filename, "rb"))==NULL)
    return;
  buffer_size=fread(buffer, 1, sizeof(buffer), file);
  fclose(file);
  if(buffer_size!=sizeof(buffer))
    return;
  sprintf(buffer_cluster, "inode_%u", (unsigned int)le32(*inode));
  file_rename(old_filename, buffer_cluster, strlen(buffer_cluster), 0, NULL, 1);
}

static int header_check_ext2_dir(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  static const unsigned char ext2_ll_dir2[6]= { 0x02, 0x02, '.',  '.', 0x00, 0x00};
  if(memcmp(&buffer[0x12], ext2_ll_dir2, sizeof(ext2_ll_dir2))!=0)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_ext2_sb.extension;
  file_recovery_new->data_check=&data_check_extdir;
  file_recovery_new->file_check=&file_check_size;
  file_recovery_new->file_rename=&file_rename_extdir;
  return 1;
}

static void register_header_check_ext2_sb(file_stat_t *file_stat)
{
  static const unsigned char ext2_sb_header[2]= {0x53, 0xEF};
  static const unsigned char ext2_ll_dir1[8]= {0x0c, 0x00, 0x01, 0x02, '.', 0x00, 0x00, 0x00};
  register_header_check(0x38, ext2_sb_header, sizeof(ext2_sb_header), &header_check_ext2_sb, file_stat);
  register_header_check(0x4, ext2_ll_dir1, sizeof(ext2_ll_dir1), &header_check_ext2_dir, file_stat);
}
