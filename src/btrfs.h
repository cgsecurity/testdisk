/*

    File: btrfs.h

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
#ifdef __cplusplus
extern "C" {
#endif

#define BTRFS_SUPER_INFO_OFFSET (64 * 1024)
#define BTRFS_SUPER_INFO_SIZE 4096

#define BTRFS_SUPER_MIRROR_MAX   3
#define BTRFS_SUPER_MIRROR_SHIFT 12
#define BTRFS_MAGIC "_BHRfS_M"

#define BTRFS_FSID_SIZE 16

/* 32 bytes in various csum fields */
#define BTRFS_CSUM_SIZE 32
/*
 * this is a very generous portion of the super block, giving us
 * room to translate 14 chunks with 3 stripes each.
 */
#define BTRFS_SYSTEM_CHUNK_ARRAY_SIZE 2048
#define BTRFS_LABEL_SIZE 256

/*
 * Structure of the super block
 * Check http://git.kernel.org/?p=linux/kernel/git/mason/btrfs-progs-unstable.git;a=blob;f=ctree.h;hb=HEAD
 * for an up-to-date version
 * Fields are in low endian
 */

#define BTRFS_UUID_SIZE 16
struct btrfs_dev_item {
	/* the internal btrfs device id */
	uint64_t devid;

	/* size of the device */
	uint64_t total_bytes;

	/* bytes used */
	uint64_t bytes_used;

	/* optimal io alignment for this device */
	uint32_t io_align;

	/* optimal io width for this device */
	uint32_t io_width;

	/* minimal io size for this device */
	uint32_t sector_size;

	/* type and info about this device */
	uint64_t type;

	/* expected generation for this device */
	uint64_t generation;

	/*
	 * starting byte of this partition on the device,
	 * to allowr for stripe alignment in the future
	 */
	uint64_t start_offset;

	/* grouping information for allocation decisions */
	uint32_t dev_group;

	/* seek speed 0-100 where 100 is fastest */
	uint8_t seek_speed;

	/* bandwidth 0-100 where 100 is fastest */
	uint8_t bandwidth;

	/* btrfs generated uuid for this device */
	uint8_t uuid[BTRFS_UUID_SIZE];

	/* uuid of FS who owns this device */
	uint8_t fsid[BTRFS_UUID_SIZE];
} __attribute__ ((__packed__));

struct btrfs_super_block {
	uint8_t csum[BTRFS_CSUM_SIZE];
	/* the first 3 fields must match struct btrfs_header */
	uint8_t fsid[BTRFS_FSID_SIZE];    /* FS specific uuid */
	uint64_t bytenr; /* this block number */
	uint64_t flags;

	/* allowed to be different from the btrfs_header from here own down */
	uint64_t magic;
	uint64_t generation;
	uint64_t root;
	uint64_t chunk_root;
	uint64_t log_root;

	/* this will help find the new super based on the log root */
	uint64_t log_root_transid;
	uint64_t total_bytes;
	uint64_t bytes_used;
	uint64_t root_dir_objectid;
	uint64_t num_devices;
	uint32_t sectorsize;
	uint32_t nodesize;
	uint32_t leafsize;
	uint32_t stripesize;
	uint32_t sys_chunk_array_size;
	uint64_t chunk_root_generation;
	uint64_t compat_flags;
	uint64_t compat_ro_flags;
	uint64_t incompat_flags;
	uint16_t csum_type;
	uint8_t root_level;
	uint8_t chunk_root_level;
	uint8_t log_root_level;
	struct btrfs_dev_item dev_item;

	char label[BTRFS_LABEL_SIZE];

	/* future expansion */
	uint64_t reserved[32];
	uint8_t sys_chunk_array[BTRFS_SYSTEM_CHUNK_ARRAY_SIZE];
} __attribute__ ((__packed__));

int check_btrfs(disk_t *disk_car,partition_t *partition);
int recover_btrfs(disk_t *disk_car, const struct btrfs_super_block *sb,partition_t *partition,const int verbose, const int dump_ind);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
