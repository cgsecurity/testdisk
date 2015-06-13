/*

    File: file_xfs.c

    Copyright (C) 2015 Christophe GRENIER <grenier@cgsecurity.org>

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
#include "xfs.h"
#include "filegen.h"

static void register_header_check_xfs(file_stat_t *file_stat);
static int header_check_xfs_sb(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_xfs= {
  .extension="xfs",
  .description="xfs structure",
  .max_filesize=0,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_xfs
};

static int header_check_xfs_sb(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct xfs_sb *sb=(const struct xfs_sb *)buffer;
  if(sb->sb_magicnum!=be32(XFS_SB_MAGIC) ||
      (uint16_t)be16(sb->sb_sectsize)  != (1U << sb->sb_sectlog) ||
      (uint32_t)be32(sb->sb_blocksize) != (1U << sb->sb_blocklog) ||
      (uint16_t)be16(sb->sb_inodesize) != (1U << sb->sb_inodelog))
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_xfs.extension;
  file_recovery_new->calculated_file_size=be32(sb->sb_blocksize);
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static data_check_t data_check_stopasap(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  return DC_STOP;
}

static int header_save_xfs(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(safe_header_only>0)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_xfs.extension;
  file_recovery_new->data_check=&data_check_stopasap;
  file_recovery_new->min_filesize=512;
  return 1;
}

typedef struct xfs_timestamp
{
  int32_t t_sec;
  int32_t t_nsec;
} xfs_timestamp_t;

typedef int64_t xfs_fsize_t;    /* bytes in a file */
typedef int32_t xfs_extnum_t;   /* # of extents in a file */
typedef int16_t xfs_aextnum_t;  /* # extents in an attribute fork */

typedef struct xfs_dinode_core
{
  uint16_t di_magic;
  uint16_t di_mode;
  int8_t di_version;
  int8_t di_format;
  uint16_t di_onlink;
  uint32_t di_uid;
  uint32_t di_gid;
  uint32_t di_nlink;
  uint16_t di_projid;
  uint8_t di_pad[8];
  uint16_t di_flushiter;
  xfs_timestamp_t di_atime;
  xfs_timestamp_t di_mtime;
  xfs_timestamp_t di_ctime;
  xfs_fsize_t di_size;
  xfs_drfsbno_t di_nblocks;
  xfs_extlen_t di_extsize;
  xfs_extnum_t di_nextents;
  xfs_aextnum_t di_anextents;
  uint8_t di_forkoff;
  int8_t di_aformat;
  uint32_t di_dmevmask;
  uint16_t di_dmstate;
  uint16_t di_flags;
  uint32_t di_gen;
} xfs_dinode_core_t;

static int header_check_xfs_inode(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const xfs_dinode_core_t *inode=(const xfs_dinode_core_t *)buffer;
  if(safe_header_only>0)
    return 0;
  if(inode->di_version!=2 ||
      inode->di_pad[0]!=0 || inode->di_pad[1]!=0 ||
      inode->di_pad[2]!=0 || inode->di_pad[3]!=0 ||
      inode->di_pad[4]!=0 || inode->di_pad[5]!=0 ||
      inode->di_pad[6]!=0 || inode->di_pad[7]!=0)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_xfs.extension;
  file_recovery_new->data_check=&data_check_stopasap;
  return 1;
}


static void register_header_check_xfs(file_stat_t *file_stat)
{
  static const unsigned char xagf[8]={'X','A','G','F', 0,0,0,1};
  static const unsigned char xagi[8]={'X','A','G','I', 0,0,0,1};
  static const unsigned char abtb[8]={'A','B','T','B', 0,0,0,1};
  static const unsigned char abtc[8]={'A','B','T','C', 0,0,0,1};
  static const unsigned char iabt[8]={'I','A','B','T', 0,0,0,1};
  register_header_check(0, "XFSB", 4, &header_check_xfs_sb, file_stat);
  register_header_check(0, xagf, 8, &header_save_xfs, file_stat);
  register_header_check(0, xagi, 8, &header_save_xfs, file_stat);
  register_header_check(0, abtb, 8, &header_save_xfs, file_stat);
  register_header_check(0, abtc, 8, &header_save_xfs, file_stat);
  register_header_check(0, iabt, 8, &header_save_xfs, file_stat);
  register_header_check(0, "IN", 2, &header_check_xfs_inode, file_stat);
}
