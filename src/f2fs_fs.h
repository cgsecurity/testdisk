/*
    File: f2fs_fs.h

    Copyright (C) 2018 Christophe GRENIER <grenier@cgsecurity.org>

    Superblock information from Samsung Electronics Co., Ltd. http://www.samsung.com/

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
#ifndef F2FS_FS_H
#define F2FS_FS_H

#define F2FS_SUPER_MAGIC	0xF2F52010	/* F2FS Magic Number */

#define F2FS_SUPER_OFFSET		1024	/* byte-size offset */
#define F2FS_MIN_LOG_SECTOR_SIZE	9	/* 9 bits for 512 bytes */
#define F2FS_MAX_LOG_SECTOR_SIZE	12	/* 12 bits for 4096 bytes */
#define F2FS_LOG_SECTORS_PER_BLOCK	3	/* log number for sector/blk */
#define F2FS_BLKSIZE			4096	/* support only 4KB block */
#define F2FS_BLKSIZE_BITS		12	/* bits for F2FS_BLKSIZE */
#define F2FS_MAX_EXTENSION		64	/* # of extension entries */
#define F2FS_EXTENSION_LEN		8	/* max size of extension */
#define F2FS_BLK_ALIGN(x)	(((x) + F2FS_BLKSIZE - 1) >> F2FS_BLKSIZE_BITS)

/*
 * For further optimization on multi-head logs, on-disk layout supports maximum
 * 16 logs by default. The number, 16, is expected to cover all the cases
 * enoughly. The implementaion currently uses no more than 6 logs.
 * Half the logs are used for nodes, and the other half are used for data.
 */
#define MAX_ACTIVE_LOGS	16
#define MAX_ACTIVE_NODE_LOGS	8
#define MAX_ACTIVE_DATA_LOGS	8

#define VERSION_LEN	256
#define MAX_VOLUME_NAME		512
#define MAX_PATH_LEN		64
#define MAX_DEVICES		8

#define F2FS_MAX_QUOTAS		3

/*
 * For superblock
 */
struct f2fs_device {
	uint8_t  path[MAX_PATH_LEN];
	uint32_t total_segments;
} __attribute__ ((gcc_struct, __packed__));

struct f2fs_super_block {
	uint32_t magic;				/* Magic Number */
	uint16_t major_ver;			/* Major Version */
	uint16_t minor_ver;			/* Minor Version */
	uint32_t log_sectorsize;		/* log2 sector size in bytes */
	uint32_t log_sectors_per_block;		/* log2 # of sectors per block */
	uint32_t log_blocksize;			/* log2 block size in bytes */
	uint32_t log_blocks_per_seg;		/* log2 # of blocks per segment */
	uint32_t segs_per_sec;			/* # of segments per section */
	uint32_t secs_per_zone;			/* # of sections per zone */
	uint32_t checksum_offset;		/* checksum offset inside super block */
	uint64_t block_count;			/* total # of user blocks */
	uint32_t section_count;			/* total # of sections */
	uint32_t segment_count;			/* total # of segments */
	uint32_t segment_count_ckpt;		/* # of segments for checkpoint */
	uint32_t segment_count_sit;		/* # of segments for SIT */
	uint32_t segment_count_nat;		/* # of segments for NAT */
	uint32_t segment_count_ssa;		/* # of segments for SSA */
	uint32_t segment_count_main;		/* # of segments for main area */
	uint32_t segment0_blkaddr;		/* start block address of segment 0 */
	uint32_t cp_blkaddr;			/* start block address of checkpoint */
	uint32_t sit_blkaddr;			/* start block address of SIT */
	uint32_t nat_blkaddr;			/* start block address of NAT */
	uint32_t ssa_blkaddr;			/* start block address of SSA */
	uint32_t main_blkaddr;			/* start block address of main area */
	uint32_t root_ino;			/* root inode number */
	uint32_t node_ino;			/* node inode number */
	uint32_t meta_ino;			/* meta inode number */
	uint8_t  uuid[16];			/* 128-bit uuid for volume */
	uint16_t volume_name[MAX_VOLUME_NAME];	/* volume name */
	uint32_t extension_count;		/* # of extensions below */
	uint8_t  extension_list[F2FS_MAX_EXTENSION][F2FS_EXTENSION_LEN];/* extension array */
	uint32_t cp_payload;
	uint8_t  version[VERSION_LEN];		/* the kernel version */
	uint8_t  init_version[VERSION_LEN];	/* the initial kernel version */
	uint32_t feature;			/* defined features */
	uint8_t  encryption_level;		/* versioning level for encryption */
	uint8_t  encrypt_pw_salt[16];		/* Salt used for string2key algorithm */
	struct f2fs_device devs[MAX_DEVICES];	/* device list */
	uint32_t qf_ino[F2FS_MAX_QUOTAS];	/* quota inode numbers */
	uint8_t  hot_ext_count;			/* # of hot file extension */
	uint8_t  reserved[314];			/* valid reserved region */
} __attribute__ ((gcc_struct, __packed__));

#endif  /* F2FS_FS_H */
