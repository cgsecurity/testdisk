/*

    File: f2fs.h

    Copyright (C) 2018 Christophe GRENIER <grenier@cgsecurity.org>

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
#ifndef _F2FS_H
#define _F2FS_H
#ifdef __cplusplus
extern "C" {
#endif

/*@
  @ requires \valid(disk);
  @ requires valid_disk(disk);
  @ requires \valid(partition);
  @ requires \separated(disk, partition);
  @ decreases 0;
  @*/
int check_f2fs(disk_t *disk, partition_t *partition);

/*@
  @ requires \valid_read(hdr);
  @*/
int test_f2fs(const struct f2fs_super_block *hdr);

/*@
  @ requires \valid(disk);
  @ requires valid_disk(disk);
  @ requires \valid_read(hdr);
  @ requires \valid(partition);
  @ requires \separated(disk, hdr, partition);
  @*/
int recover_f2fs(const disk_t *disk, const struct f2fs_super_block *hdr, partition_t *partition);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
