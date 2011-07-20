/*

    File: vmfs.h

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

#ifndef _VMFS_H
#define _VMFS_H
#ifdef __cplusplus
extern "C" {
#endif
/* VMFS boot block */
#define VDEV_BOOT_MAGIC         0x2f5b007b10cULL
#define VDEV_BOOT_VERSION       1               /* version number       */
#define	VDEV_BOOT_HEADER_SIZE	(8 << 10)

struct vmfs_volume
{
  uint32_t magic;
  uint32_t version;
} __attribute__ ((__packed__));
struct vmfs_lvm
{
  uint64_t size;
  uint64_t blocks;
} __attribute__ ((__packed__));

int check_VMFS(disk_t *disk,partition_t *partition);
int recover_VMFS(disk_t *disk, const struct vmfs_volume *sb, partition_t *partition, const int verbose, const int dump_ind);
#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
