/*

    File: bcachefs_struct.h

    Copyright (C) 2024 Christophe GRENIER <grenier@cgsecurity.org>

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
#ifndef _BCACHEFS_STRUCT_H
#define _BCACHEFS_STRUCT_H

/* bcachefs superblock is located at offset 4096 (one 4k sector) from
 * start of device.  See linux/fs/bcachefs/bcachefs_format.h.
 *
 * Magic: c6 85 73 f6 4e 1a 45 ca 82 65 f5 7f 48 ba 6d 81
 */

#define BCACHEFS_SB_MAGIC_SIZE	16
#define BCACHEFS_UUID_SIZE	16
#define BCACHEFS_LABEL_SIZE	32
#define BCACHEFS_SUPER_OFFSET	4096	/* bytes from start of device */
#define BCACHEFS_SUPER_SIZE	512	/* minimum superblock read */

/* bcachefs on-disk superblock (simplified – fields needed for detection) */
struct bcachefs_super_block {
	/* Fletcher-64 checksum of rest of superblock */
	uint64_t	csum[2];
	uint16_t	version;
	uint16_t	version_min;
	uint16_t	pad[2];
	/* 16-byte magic: c6 85 73 f6 4e 1a 45 ca 82 65 f5 7f 48 ba 6d 81 */
	uint8_t		magic[BCACHEFS_SB_MAGIC_SIZE];
	uint8_t		uuid[BCACHEFS_UUID_SIZE];	/* user-visible UUID */
	uint8_t		user_uuid[BCACHEFS_UUID_SIZE];
	uint8_t		label[BCACHEFS_LABEL_SIZE];
	uint64_t	offset;		/* sector offset of this superblock */
	uint64_t	seq;		/* sequence number */
	uint16_t	block_size;	/* in 512-byte sectors */
	uint8_t		dev_idx;
	uint8_t		nr_devices;
	uint32_t	u64s;		/* size of variable-length section */
	uint64_t	time_base_lo;
	uint32_t	time_base_hi;
	uint32_t	time_precision;
	uint64_t	flags[8];
	uint64_t	features[2];
	uint64_t	compat[2];
} __attribute__((gcc_struct, __packed__));

#endif /* _BCACHEFS_STRUCT_H */
