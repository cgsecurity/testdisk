/*

    File: bcachefs.c

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

/*
 * bcachefs superblock detection and partition recovery.
 *
 * bcachefs is a Copy-on-Write filesystem introduced in Linux 6.7 (2024).
 * The primary superblock sits at byte offset 4096 from the start of the
 * device.  The 16-byte magic is:
 *   c6 85 73 f6  4e 1a 45 ca  82 65 f5 7f  48 ba 6d 81
 *
 * References:
 *   linux/fs/bcachefs/bcachefs_format.h
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include "types.h"
#include "common.h"
#include "bcachefs.h"
#include "fnctdsk.h"
#include "log.h"
#include "guid_cpy.h"

/* 16-byte on-disk magic constant */
static const uint8_t BCACHEFS_MAGIC[BCACHEFS_SB_MAGIC_SIZE] = {
	0xc6, 0x85, 0x73, 0xf6, 0x4e, 0x1a, 0x45, 0xca,
	0x82, 0x65, 0xf5, 0x7f, 0x48, 0xba, 0x6d, 0x81
};

static int test_bcachefs(const struct bcachefs_super_block *sb);

/*
 * Populate partition fields from a validated bcachefs superblock.
 */
static void set_bcachefs_info(const struct bcachefs_super_block *sb, partition_t *partition)
{
	const unsigned int block_size = le16(sb->block_size) * DEFAULT_SECTOR_SIZE;
	partition->upart_type = UP_BTRFS; /* closest generic Linux FS type */
	partition->blocksize  = (block_size > 0) ? block_size : 4096;
	set_part_name(partition, (const char *)sb->label, BCACHEFS_LABEL_SIZE);
	snprintf(partition->info, sizeof(partition->info),
		"bcachefs blocksize=%u", partition->blocksize);
}

/*
 * check_bcachefs - read and validate the primary superblock from disk.
 * Returns 0 on success, non-zero on failure.
 */
int check_bcachefs(disk_t *disk_car, partition_t *partition)
{
	unsigned char *buffer = (unsigned char *)MALLOC(BCACHEFS_SUPER_SIZE);
	if(disk_car->pread(disk_car, buffer, BCACHEFS_SUPER_SIZE,
		partition->part_offset + BCACHEFS_SUPER_OFFSET) != BCACHEFS_SUPER_SIZE)
	{
		free(buffer);
		return 1;
	}
	if(test_bcachefs((struct bcachefs_super_block *)buffer) != 0)
	{
		free(buffer);
		return 1;
	}
	set_bcachefs_info((struct bcachefs_super_block *)buffer, partition);
	free(buffer);
	return 0;
}

/*
 * recover_bcachefs - fill partition metadata from an already-read superblock.
 * Called by the analyse layer after the buffer has been read at search_type_8
 * offset (4096 bytes in).
 * Returns 0 on success, non-zero if the superblock is invalid.
 */
int recover_bcachefs(const disk_t *disk, const struct bcachefs_super_block *sb,
	partition_t *partition, const int verbose, const int dump_ind)
{
	if(test_bcachefs(sb) != 0)
		return 1;
	if(dump_ind != 0)
	{
		if(partition != NULL && disk != NULL)
			log_info("\nbcachefs magic value at %u/%u/%u\n",
				offset2cylinder(disk, partition->part_offset),
				offset2head(disk, partition->part_offset),
				offset2sector(disk, partition->part_offset));
		dump_log(sb, BCACHEFS_SUPER_SIZE);
	}
	if(partition == NULL)
		return 0;
	set_bcachefs_info(sb, partition);
	partition->part_type_i386 = P_LINUX;
	partition->part_type_mac  = PMAC_LINUX;
	partition->part_type_sun  = PSUN_LINUX;
	partition->part_type_gpt  = GPT_ENT_TYPE_LINUX_DATA;
	/* bcachefs does not store total device size in the superblock header;
	 * leave part_size at 0 so TestDisk uses geometry-based estimation. */
	partition->part_size     = 0;
	partition->sborg_offset  = BCACHEFS_SUPER_OFFSET;
	partition->sb_size       = BCACHEFS_SUPER_SIZE;
	guid_cpy(&partition->part_uuid, (const efi_guid_t *)sb->uuid);
	if(verbose > 0)
	{
		log_info("\n");
		log_info("recover_bcachefs: version=%u block_size=%u\n",
			(unsigned int)le16(sb->version),
			(unsigned int)le16(sb->block_size));
	}
	return 0;
}

/*
 * test_bcachefs - validate magic bytes and basic sanity of a superblock buffer.
 * Static: only used within this translation unit.
 */
static int test_bcachefs(const struct bcachefs_super_block *sb)
{
	if(memcmp(sb->magic, BCACHEFS_MAGIC, BCACHEFS_SB_MAGIC_SIZE) != 0)
		return 1;
	/* block_size of 0 is invalid */
	if(le16(sb->block_size) == 0)
		return 1;
	return 0;
}
