/*

    File: zfs.h

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

#ifndef _ZFS_H
#define _ZFS_H
#ifdef __cplusplus
extern "C" {
#endif
/* ZFS boot block */
#define VDEV_BOOT_MAGIC         0x2f5b007b10cULL
#define VDEV_BOOT_VERSION       1               /* version number       */
#define	VDEV_BOOT_HEADER_SIZE	(8 << 10)

struct vdev_boot_header {
        uint64_t        vb_magic;               /* VDEV_BOOT_MAGIC      */
        uint64_t        vb_version;             /* VDEV_BOOT_VERSION    */
        uint64_t        vb_offset;              /* start offset (bytes) */
        uint64_t        vb_size;                /* size (bytes)         */
        char            vb_pad[VDEV_BOOT_HEADER_SIZE - 4 * sizeof (uint64_t)];
};
int check_ZFS(disk_t *disk,partition_t *partition);
int recover_ZFS(disk_t *disk, const struct vdev_boot_header *ZFS_header,partition_t *partition,const int verbose, const int dump_ind);
#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
