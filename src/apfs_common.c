/*

    File: apfs_common.c

    Copyright (C) 2021 Christophe GRENIER <grenier@cgsecurity.org>

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
#include "apfs_common.h"
#include "log.h"

/*@
  @ requires \valid_read(data + (0 .. cnt-1));
  @ assigns  \nothing;
  @*/
static uint64_t fletcher64(const uint32_t *data, const size_t cnt, const uint64_t init)
{
  size_t k;
  uint64_t sum1 = init & 0xFFFFFFFFU;
  uint64_t sum2 = (init >> 32);
  /*@
    @ loop invariant 0 <= k <= cnt;
    @ loop assigns k, sum1, sum2;
    @*/
  for (k = 0; k < cnt; k++)
  {
    /* @assert k < cnt; */
    sum1 = (sum1 + le32(data[k]));
    sum2 = (sum2 + sum1);
  }
  sum1 = sum1 % 0xFFFFFFFF;
  sum2 = sum2 % 0xFFFFFFFF;
  return (sum2 << 32) | sum1;
}

/*@
  @ requires size >= 8;
  @ requires \valid_read((char *)block+ (0 .. size-1));
  @ assigns  \nothing;
  @*/
static uint64_t VerifyBlock(const void *block, const size_t size)
{
  uint64_t cs;
  const uint32_t *data = (const uint32_t *)block;
  const size_t size4 = size / sizeof(uint32_t);

  cs = fletcher64(data + 2, size4 - 2, 0);
  cs = fletcher64(data, 2, cs);
  return cs;
}

int test_APFS(const nx_superblock_t *sb, const partition_t *partition)
{
  if(le32(sb->nx_magic)!=0x4253584e)
    return 1;
  if((uint64_t)le32(sb->nx_xp_desc_blocks) + le32(sb->nx_xp_data_blocks) > le64(sb->nx_block_count))
    return 2;
  if(le32(sb->nx_block_size) < NX_MINIMUM_BLOCK_SIZE ||
      le32(sb->nx_block_size) > NX_MAXIMUM_BLOCK_SIZE)
    return 3;
  if(VerifyBlock(sb, 4096) != 0)
    return 4;
  return 0;
}
