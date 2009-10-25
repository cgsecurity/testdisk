/*

    File: md.h

    Copyright (C) 1998-2004 Christophe GRENIER <grenier@cgsecurity.org>
  
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
   physical layout of Linux RAID devices
          Copyright (C) 1996-98 Ingo Molnar, Gadi Oxman
*/

#ifndef _MD_P_H
#define _MD_P_H
#ifdef __cplusplus
extern "C" {
#endif

/*
 * RAID superblock.
 *
 * The RAID superblock maintains some statistics on each RAID configuration.
 * Each real device in the RAID set contains it near the end of the device.
 * Some of the ideas are copied from the ext2fs implementation.
 *
 * We currently use 4096 bytes as follows:
 *
 *	word offset	function
 *
 *	   0  -    31	Constant generic RAID device information.
 *        32  -    63   Generic state information.
 *	  64  -   127	Personality specific information.
 *	 128  -   511	12 32-words descriptors of the disks in the raid set.
 *	 512  -   911	Reserved.
 *	 912  -  1023	Disk specific descriptor.
 */

/*
 * If x is the real device size in bytes, we return an apparent size of:
 *
 *	y = (x & ~(MD_RESERVED_BYTES - 1)) - MD_RESERVED_BYTES
 *
 * and place the 4kB superblock at offset y.
 */
#define MD_MAX_CHUNK_SIZE 		(4096*1024)
#define MD_RESERVED_BYTES		(64 * 1024)
#define MD_RESERVED_SECTORS		(MD_RESERVED_BYTES / 512)
#define MD_RESERVED_BLOCKS		(MD_RESERVED_BYTES / BLOCK_SIZE)

#define MD_NEW_SIZE_SECTORS(x)		((x & ~(MD_RESERVED_SECTORS - 1)) - MD_RESERVED_SECTORS)
#define MD_NEW_SIZE_BLOCKS(x)		((x & ~(MD_RESERVED_BLOCKS - 1)) - MD_RESERVED_BLOCKS)

#define MD_SB_BYTES			4096
#define MD_SB_WORDS			(MD_SB_BYTES / 4)
#define MD_SB_BLOCKS			(MD_SB_BYTES / BLOCK_SIZE)
#define MD_SB_SECTORS			(MD_SB_BYTES / 512)

/*
 * The following are counted in 32-bit words
 */
#define	MD_SB_GENERIC_OFFSET		0
#define MD_SB_PERSONALITY_OFFSET	64
#define MD_SB_DISKS_OFFSET		128
#define MD_SB_DESCRIPTOR_OFFSET		992

#define MD_SB_GENERIC_CONSTANT_WORDS	32
#define MD_SB_GENERIC_STATE_WORDS	32
#define MD_SB_GENERIC_WORDS		(MD_SB_GENERIC_CONSTANT_WORDS + MD_SB_GENERIC_STATE_WORDS)
#define MD_SB_PERSONALITY_WORDS		64
#define MD_SB_DESCRIPTOR_WORDS		32
#define MD_SB_DISKS			27
#define MD_SB_DISKS_WORDS		(MD_SB_DISKS*MD_SB_DESCRIPTOR_WORDS)
#define MD_SB_RESERVED_WORDS		(1024 - MD_SB_GENERIC_WORDS - MD_SB_PERSONALITY_WORDS - MD_SB_DISKS_WORDS - MD_SB_DESCRIPTOR_WORDS)
#define MD_SB_EQUAL_WORDS		(MD_SB_GENERIC_WORDS + MD_SB_PERSONALITY_WORDS + MD_SB_DISKS_WORDS)

/*
 * Device "operational" state bits
 */
#define MD_DISK_FAULTY		0 /* disk is faulty / operational */
#define MD_DISK_ACTIVE		1 /* disk is running or spare disk */
#define MD_DISK_SYNC		2 /* disk is in sync with the raid set */
#define MD_DISK_REMOVED		3 /* disk is in sync with the raid set */

typedef struct mdp_device_descriptor_s {
	uint32_t number;		/* 0 Device number in the entire set	      */
	uint32_t major;		/* 1 Device major number		      */
	uint32_t minor;		/* 2 Device minor number		      */
	uint32_t raid_disk;	/* 3 The role of the device in the raid set   */
	uint32_t state;		/* 4 Operational state			      */
	uint32_t reserved[MD_SB_DESCRIPTOR_WORDS - 5];
} mdp_disk_t;

#define MD_SB_MAGIC		0xa92b4efc

/*
 * Superblock state bits
 */
#define MD_SB_CLEAN		0
#define MD_SB_ERRORS		1

typedef struct mdp_superblock_s {
	/*
	 * Constant generic information
	 */
	uint32_t md_magic;		/*  0 MD identifier 			      */
	uint32_t major_version;	/*  1 major version to which the set conforms */
	uint32_t minor_version;	/*  2 minor version ...			      */
	uint32_t patch_version;	/*  3 patchlevel version ...		      */
	uint32_t gvalid_words;	/*  4 Number of used words in this section    */
	uint32_t set_uuid0;	/*  5 Raid set identifier		      */
	uint32_t ctime;		/*  6 Creation time			      */
	uint32_t level;		/*  7 Raid personality			      */
	uint32_t size;		/*  8 Apparent size of each individual disk   */
	uint32_t nr_disks;		/*  9 total disks in the raid set	      */
	uint32_t raid_disks;	/* 10 disks in a fully functional raid set    */
	uint32_t md_minor;		/* 11 preferred MD minor device number	      */
	uint32_t not_persistent;	/* 12 does it have a persistent superblock    */
	uint32_t set_uuid1;	/* 13 Raid set identifier #2		      */
	uint32_t set_uuid2;	/* 14 Raid set identifier #3		      */
	uint32_t set_uuid3;	/* 15 Raid set identifier #4		      */
	uint32_t gstate_creserved[MD_SB_GENERIC_CONSTANT_WORDS - 16];

	/*
	 * Generic state information
	 */
	uint32_t utime;		/*  0 Superblock update time		      */
	uint32_t state;		/*  1 State bits (clean, ...)		      */
	uint32_t active_disks;	/*  2 Number of currently active disks	      */
	uint32_t working_disks;	/*  3 Number of working disks		      */
	uint32_t failed_disks;	/*  4 Number of failed disks		      */
	uint32_t spare_disks;	/*  5 Number of spare disks		      */
	uint32_t sb_csum;		/*  6 checksum of the whole superblock        */
#ifdef __BIG_ENDIAN
	uint32_t events_hi;	/*  7 high-order of superblock update count   */
	uint32_t events_lo;	/*  8 low-order of superblock update count    */
#else
	uint32_t events_lo;	/*  7 low-order of superblock update count    */
	uint32_t events_hi;	/*  8 high-order of superblock update count   */
#endif
	uint32_t gstate_sreserved[MD_SB_GENERIC_STATE_WORDS - 9];

	/*
	 * Personality information
	 */
	uint32_t layout;		/*  0 the array's physical layout	      */
	uint32_t chunk_size;	/*  1 chunk size in bytes		      */
	uint32_t root_pv;		/*  2 LV root PV */
	uint32_t root_block;	/*  3 LV root block */
	uint32_t pstate_reserved[MD_SB_PERSONALITY_WORDS - 4];

	/*
	 * Disks information
	 */
	mdp_disk_t disks[MD_SB_DISKS];

	/*
	 * Reserved
	 */
	uint32_t reserved[MD_SB_RESERVED_WORDS];

	/*
	 * Active descriptor
	 */
	mdp_disk_t this_disk;

} mdp_super_t;

/*
 * The version-1 superblock :
 * All numeric fields are little-endian.
 *
 * total size: 256 bytes plus 2 per device.
 *  1K allows 384 devices.
 */
struct mdp_superblock_1 {
	/* constant array information - 128 bytes */
	uint32_t	md_magic;	/* MD_SB_MAGIC: 0xa92b4efc - little endian */
	uint32_t	major_version;	/* 1 */
	uint32_t	feature_map;	/* bit 0 set if 'bitmap_offset' is meaningful */
	uint32_t	pad0;		/* always set to 0 when writing */

	uint8_t	set_uuid[16];	/* user-space generated. */
	char	set_name[32];	/* set and interpreted by user-space */

	uint64_t	ctime;		/* lo 40 bits are seconds, top 24 are microseconds or 0*/
	uint32_t	level;		/* -4 (multipath), -1 (linear), 0,1,4,5 */
	uint32_t	layout;		/* only for raid5 and raid10 currently */
	uint64_t	size;		/* used size of component devices, in 512byte sectors */

	uint32_t	chunksize;	/* in 512byte sectors */
	uint32_t	raid_disks;
	int32_t	bitmap_offset;	/* sectors after start of superblock that bitmap starts
				 * NOTE: signed, so bitmap can be before superblock
				 * only meaningful of feature_map[0] is set.
				 */

	/* These are only valid with feature bit '4' */
	uint32_t	new_level;	/* new level we are reshaping to		*/
	uint64_t	reshape_position;	/* next address in array-space for reshape */
	uint32_t	delta_disks;	/* change in number of raid_disks		*/
	uint32_t	new_layout;	/* new layout					*/
	uint32_t	new_chunk;	/* new chunk size (bytes)			*/
	uint8_t	pad1[128-124];	/* set to 0 when written */

	/* constant this-device information - 64 bytes */
	uint64_t	data_offset;	/* sector start of data, often 0 */
	uint64_t	data_size;	/* sectors in this device that can be used for data */
	uint64_t	super_offset;	/* sector start of this superblock */
	uint64_t	recovery_offset;/* sectors before this offset (from data_offset) have been recovered */
	uint32_t	dev_number;	/* permanent identifier of this  device - not role in raid */
	uint32_t	cnt_corrected_read; /* number of read errors that were corrected by re-writing */
	uint8_t	device_uuid[16]; /* user-space setable, ignored by kernel */
	uint8_t	devflags;	/* per-device flags.  Only one defined...*/
#define	WriteMostly1	1	/* mask for writemostly flag in above */
	uint8_t	pad2[64-57];	/* set to 0 when writing */

	/* array state information - 64 bytes */
	uint64_t	utime;		/* 40 bits second, 24 btes microseconds */
	uint64_t	events;		/* incremented when superblock updated */
	uint64_t	resync_offset;	/* data before this offset (from data_offset) known to be in sync */
	uint32_t	sb_csum;	/* checksum upto devs[max_dev] */
	uint32_t	max_dev;	/* size of devs[] array to consider */
	uint8_t	pad3[64-32];	/* set to 0 when writing */

	/* device state information. Indexed by dev_number.
	 * 2 bytes per device
	 * Note there are no per-device state flags. State information is rolled
	 * into the 'roles' value.  If a device is spare or faulty, then it doesn't
	 * have a meaningful role.
	 */
	uint16_t	dev_roles[0];	/* role in array, or 0xffff for a spare, or 0xfffe for faulty */
};

#if 0
static inline uint64_t md_event(mdp_super_t *sb) {
	uint64_t ev = sb->events_hi;
	return (ev<<32)| sb->events_lo;
}
#endif

/* TestDisk */
int check_MD(disk_t *disk_car,partition_t *partition,const int verbose);
int recover_MD(disk_t *disk_car, const struct mdp_superblock_s *sb, partition_t *partition, const int verbose, const int dump_ind);
int recover_MD_from_partition(disk_t *disk_car, partition_t *partition, const int verbose);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif 
