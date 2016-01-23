/*

    File: ZFS.c

    Copyright (C) 2009 Christophe GRENIER <grenier@cgsecurity.org>

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
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "common.h"
#include "zfs.h"
#include "fnctdsk.h"
#include "log.h"
#include "guid_cpy.h"

static int test_ZFS(disk_t *disk, const struct vdev_boot_header *sb, const partition_t *partition, const int dump_ind);
static void set_ZFS_info(const struct vdev_boot_header *sb, partition_t *partition);

int check_ZFS(disk_t *disk,partition_t *partition)
{
  unsigned char *buffer=(unsigned char*)MALLOC(DEFAULT_SECTOR_SIZE);
  if(disk->pread(disk, buffer, DEFAULT_SECTOR_SIZE, partition->part_offset+0x2000) != DEFAULT_SECTOR_SIZE)
  {
    free(buffer);
    return 1;
  }
  if(test_ZFS(disk, (struct vdev_boot_header*)buffer, partition, 0)!=0)
  {
    free(buffer);
    return 1;
  }
  set_ZFS_info((struct vdev_boot_header*)buffer, partition);
  free(buffer);
  return 0;
}

static void set_ZFS_info(const struct vdev_boot_header *sb, partition_t *partition)
{
  partition->upart_type=UP_ZFS;
  sprintf(partition->info,"ZFS %lu (Data size unknown)", (long unsigned)le64(sb->vb_version));
}

int recover_ZFS(disk_t *disk, const struct vdev_boot_header *sb,partition_t *partition,const int verbose, const int dump_ind)
{
  if(test_ZFS(disk, sb, partition, dump_ind)!=0)
    return 1;
  if(partition==NULL)
    return 0;
  set_ZFS_info(sb, partition);
  partition->part_type_i386=P_LINUX;
  partition->part_type_mac=PMAC_LINUX;
  partition->part_type_sun=PSUN_LINUX;
  partition->part_type_gpt=GPT_ENT_TYPE_SOLARIS_USR;
  partition->part_size=(uint64_t)le64(sb->vb_offset);
  partition->blocksize=0;
  partition->sborg_offset=0;
  partition->sb_offset=0;
  if(verbose>0)
  {
    log_info("\n");
  }
  return 0;
}

static int test_ZFS(disk_t *disk, const struct vdev_boot_header *sb, const partition_t *partition, const int dump_ind)
{
  if(le64(sb->vb_magic)!=VDEV_BOOT_MAGIC)
    return 1;
  if(dump_ind!=0)
  {
    if(partition!=NULL && disk!=NULL)
      log_info("\nZFS magic value at %u/%u/%u\n",
          offset2cylinder(disk,partition->part_offset),
          offset2head(disk,partition->part_offset),
          offset2sector(disk,partition->part_offset));
    dump_log(sb,DEFAULT_SECTOR_SIZE);
  }
  return 0;
}
