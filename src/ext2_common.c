/*

    File: ext2_common.c

    Copyright (C) 1998-2013 Christophe GRENIER <grenier@cgsecurity.org>
  
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
 
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include "types.h"
#include "common.h"
#include "ext2_common.h"

uint64_t td_ext2fs_blocks_count(const struct ext2_super_block *super)
{
  const uint64_t lo=le32(super->s_blocks_count);
  const uint64_t hi=le32(super->s_blocks_count_hi);
  /*@ assert lo < 1 << 32; */
  /*@ assert hi < 1 << 32; */
  /*@ assert hi << 32 < (1 << 64); */
  return lo |
    (EXT2_HAS_INCOMPAT_FEATURE(super, EXT4_FEATURE_INCOMPAT_64BIT) ?
     hi << 32 : 0);
}

uint64_t td_ext2fs_free_blocks_count(const struct ext2_super_block *super)
{
  const uint64_t lo=le32(super->s_free_blocks_count);
  const uint64_t hi=le32(super->s_free_blocks_hi);
  /*@ assert lo < 1 << 32; */
  /*@ assert hi < 1 << 32; */
  /*@ assert hi << 32 < (1 << 64); */
  return  lo|
    (EXT2_HAS_INCOMPAT_FEATURE(super, EXT4_FEATURE_INCOMPAT_64BIT) ?
     hi << 32 : 0);
}

int test_EXT2(const struct ext2_super_block *sb, const partition_t *partition)
{
  const unsigned int s_errors=le16(sb->s_errors);
  const uint64_t blocks_count=td_ext2fs_blocks_count(sb);
  const uint32_t s_log_block_size=le32(sb->s_log_block_size);
    /* There is a little offset ... */
  if(le16(sb->s_magic)!=EXT2_SUPER_MAGIC)
    return 1;
  if (td_ext2fs_free_blocks_count(sb) > blocks_count)
    return 2;
  if (le32(sb->s_free_inodes_count) > le32(sb->s_inodes_count))
    return 3;
  if (s_errors!=0 &&
      (s_errors != EXT2_ERRORS_CONTINUE) &&
      (s_errors != EXT2_ERRORS_RO) &&
      (s_errors != EXT2_ERRORS_PANIC))
    return 4;
  if ((le16(sb->s_state) & ~(EXT2_VALID_FS | EXT2_ERROR_FS))!=0)
    return 5;
  if(blocks_count == 0) /* reject empty filesystem */
    return 6;
  switch(s_log_block_size)
  {
    case 0:
    case 1:
    case 2: /* block size = 4096 (default) */
    case 3: /* can be 8192 on alpha */
    case 4: /* non standard blocksize */
    case 5: /* non standard blocksize */
    case 6: /* 64 KiB */
      break;
    default:
      return 7;
  }
  /*@ assert 0 <= s_log_block_size <= 6; */
  if(le32(sb->s_blocks_per_group)==0)
    return 8;
  if(partition==NULL)
    return 0;
  /*@ assert 0 <= EXT2_MIN_BLOCK_SIZE<<s_log_block_size <= EXT2_MIN_BLOCK_SIZE<<6; */
  /*@ assert 0 ≤ 64-10-s_log_block_size ≤ 64-10-6; */ ;
  if(blocks_count >= (uint64_t)1 << (64-10-s_log_block_size))
    return 9;
  /*@ assert blocks_count < 1 << (64-10-s_log_block_size); */
  if(partition->part_size!=0 &&
      partition->part_size < blocks_count * ((uint64_t)EXT2_MIN_BLOCK_SIZE<<s_log_block_size))
    return 8;
  return 0;
}
