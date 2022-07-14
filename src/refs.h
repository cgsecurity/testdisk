/*
 * File refs.h
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

#ifndef _REFS_H
#define _REFS_H
#ifdef __cplusplus
extern "C" {
#endif

#define ReFS_BS_SIZE 0x200
struct ReFS_boot_sector {
  uint8_t	ignored[3];
  uint32_t	fsname;
  uint8_t	mustBeZero[9];
  uint32_t	identifier;
  uint16_t	length;
  uint16_t	checksum;
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ decreases 0;
  @*/
int check_ReFS(disk_t *disk, partition_t *partition);
int recover_ReFS(const disk_t *disk, const struct ReFS_boot_sector *refs_header, partition_t *partition);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
