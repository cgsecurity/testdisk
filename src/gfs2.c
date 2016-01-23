/*

    File: gfs2.c

    Copyright (C) 2011 Christophe GRENIER <grenier@cgsecurity.org>
  
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
 
#include "types.h"
#include "common.h"
#include "gfs2.h"
#include "fnctdsk.h"
#include "log.h"

static void set_gfs2_info(partition_t *partition)
{
  partition->upart_type=UP_GFS2;
  partition->info[0]='\0';
}

static int test_gfs2(disk_t *disk, const struct gfs2_sb *sb, const partition_t *partition, const int dump_ind)
{
  if(sb->sb_header.mh_magic != be32(GFS2_MAGIC))
    return 1;
  if(sb->sb_header.mh_format != be32(GFS2_FORMAT_SB))
    return 1;
  if(partition==NULL)
    return 0;
  if(dump_ind!=0)
  {
    log_info("\ngfs2 magic value at %u/%u/%u\n",
	offset2cylinder(disk, partition->part_offset),
	offset2head(disk, partition->part_offset),
	offset2sector(disk, partition->part_offset));
    dump_log(sb,DEFAULT_SECTOR_SIZE);
  }
  return 0;
}

int check_gfs2(disk_t *disk, partition_t *partition)
{
  unsigned char *buffer;
  buffer=(unsigned char*)MALLOC(512);
  if(disk->pread(disk, buffer, 512, partition->part_offset + (GFS2_SB_ADDR << GFS2_BASIC_BLOCK_SHIFT)) != 512)
  {
    free(buffer);
    return 1;
  }
  if(test_gfs2(disk, (const struct gfs2_sb *)buffer, partition,0)!=0)
  {
    free(buffer);
    return 1;
  }
  set_gfs2_info(partition);
  free(buffer);
  return 0;
}

int recover_gfs2(disk_t *disk, const struct gfs2_sb *sb, partition_t *partition, const int dump_ind)
{
  if(test_gfs2(disk,sb,partition,dump_ind)!=0)
    return 1;
  set_gfs2_info(partition);
  partition->part_size=disk->sector_size;
  partition->part_type_i386=(unsigned char)P_LINUX;
  return 0;
}
