/*
 * File xfs.h
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it would be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Further, this software is distributed without any warranty that it is
 * free of the rightful claim of any third person regarding infringement
 * or the like.  Any license provided herein, whether implied or
 * otherwise, applies only to this software file.  Patent licenses, if
 * any, provided herein do not apply to combinations of this program with
 * other software, or any other product whatsoever.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include "xfs_struct.h"
/*
 * Super block
 * Fits into a sector-sized buffer at address 0 of each allocation group.
 * Only the first of these is ever updated except during growfs.
 */
#ifndef _XFS_H
#define _XFS_H
#ifdef __cplusplus
extern "C" {
#endif

/*@
  @ requires \valid(disk_car);
  @ requires \valid(partition);
  @ requires separation: \separated(disk_car, partition);
  @ decreases 0;
  @*/
int check_xfs(disk_t *disk_car, partition_t *partition, const int verbose);

/*@
  @ requires \valid_read(disk_car);
  @ requires \valid_read(sb);
  @ requires \valid(partition);
  @ requires separation: \separated(disk_car, sb, partition);
  @*/
int recover_xfs(const disk_t *disk_car, const struct xfs_sb *sb, partition_t *partition, const int verbose, const int dump_ind);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
