/*

    File: ext2p.c

    Copyright (C) 2007-2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include "list.h"
#include "filegen.h"
#include "intrf.h"
#include "dir.h"
#ifdef HAVE_EXT2FS_EXT2_FS_H
#include "ext2fs/ext2_fs.h"
#endif
#ifdef HAVE_EXT2FS_EXT2FS_H
#include "ext2fs/ext2fs.h"
#endif
#include "ext2p.h"
#include "ext2_inc.h"
#include "ext2_dir.h"
#include "log.h"
#include "log_part.h"

#ifdef HAVE_LIBEXT2FS
unsigned int ext2_remove_used_space(disk_t *disk, const partition_t *partition, alloc_data_t *list_search_space)
{
  dir_data_t dir_data;
  switch(dir_partition_ext2_init(disk, partition, &dir_data, 0))
  {
    case DIR_PART_ENOIMP:
    case DIR_PART_ENOSYS:
      return 0;
    case DIR_PART_EIO:
      log_partition(disk, partition);
      log_error("Can't open filesystem. Filesystem seems damaged.\n");
      return 0;
    case DIR_PART_OK:
      break;
  }
  {
    const unsigned int sizeof_buffer=512;
    struct ext2_dir_struct *ls=(struct ext2_dir_struct *)dir_data.private_dir_data;
    unsigned char *buffer;
    uint64_t start_free=0;
    uint64_t end_free=0;
    unsigned long int block;
    unsigned long int start,end;
    const unsigned int blocksize=ls->current_fs->blocksize;
    ext2fs_block_bitmap bitmap;
    if(ext2fs_read_block_bitmap(ls->current_fs))
    {
      log_error("ext2fs_read_block_bitmap failed\n");
      return 0;
    }
    bitmap=ls->current_fs->block_map;
    if(bitmap==NULL)
      return 0;
#ifdef HAVE_EXT2FS_GET_GENERIC_BITMAP_START
    start=ext2fs_get_generic_bitmap_start(bitmap);
    end=ext2fs_get_generic_bitmap_end(bitmap);
#else
    start=bitmap->start;
    end=bitmap->end;
#endif
    log_trace("ext2_remove_used_space %lu-%lu\n", start, end);
    buffer=(unsigned char *)MALLOC(sizeof_buffer);
    for(block=start;block<=end;block++)
    {
#ifdef HAVE_EXT2FS_GET_GENERIC_BITMAP_START
      if(ext2fs_test_generic_bitmap(bitmap,block)!=0)
#else
      if(ext2fs_test_bit(block - bitmap->start, bitmap->bitmap)!=0)
#endif
      {
	/* Not free */
	if(end_free+1==partition->part_offset+(uint64_t)block*blocksize)
	  end_free+=blocksize;
	else
	{
	  if(start_free != end_free)
	    del_search_space(list_search_space, start_free, end_free);
	  start_free=partition->part_offset+(uint64_t)block*blocksize;
	  end_free=start_free+(uint64_t)blocksize-1;
	}
      }
    }
    free(buffer);
    if(start_free != end_free)
      del_search_space(list_search_space, start_free, end_free);
    dir_data.close(&dir_data);
    return blocksize;
  }
}
#endif
