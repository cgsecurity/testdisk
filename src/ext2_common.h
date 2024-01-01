/*

    File: ext2_common.h

    Copyright (C) 2013 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifndef EXT2_COMMON_H
#define EXT2_COMMON_H
#ifdef __cplusplus
extern "C" {
#endif

#define EXT2_SUPERBLOCK_SIZE 1024

#define EXT2_SB(sb)     (sb)

/*
 * The second extended file system magic number
 */
#define EXT2_SUPER_MAGIC	0xEF53
#define EXT2_MIN_BLOCK_SIZE		1024
#define	EXT2_MAX_BLOCK_SIZE		4096
#define EXT2_MIN_BLOCK_LOG_SIZE		  10

#define EXT2_MIN_BLOCK (EXT2_MIN_BLOCK_SIZE/DEFAULT_SECTOR_SIZE)

/*
 * File system states
 */
#define	EXT2_VALID_FS			0x0001	/* Unmounted cleanly */
#define	EXT2_ERROR_FS			0x0002	/* Errors detected */

/*
 * Behaviour when detecting errors
 */
#define EXT2_ERRORS_CONTINUE		1	/* Continue execution */
#define EXT2_ERRORS_RO			2	/* Remount fs read-only */
#define EXT2_ERRORS_PANIC		3	/* Panic */
#define EXT2_ERRORS_DEFAULT		EXT2_ERRORS_CONTINUE

/*
 * Feature set definitions
 */
#define EXT2_HAS_COMPAT_FEATURE(sb,mask)                        \
        ( le32(EXT2_SB(sb)->s_feature_compat) & (mask) )
#define EXT2_HAS_RO_COMPAT_FEATURE(sb,mask)                     \
        ( le32(EXT2_SB(sb)->s_feature_ro_compat) & (mask) )
#define EXT2_HAS_INCOMPAT_FEATURE(sb,mask)                      \
        ( le32(EXT2_SB(sb)->s_feature_incompat) & (mask) )

#define EXT2_FEATURE_COMPAT_DIR_PREALLOC        0x0001
#define EXT2_FEATURE_COMPAT_IMAGIC_INODES	0x0002
#define EXT3_FEATURE_COMPAT_HAS_JOURNAL		0x0004
#define EXT2_FEATURE_COMPAT_EXT_ATTR		0x0008
#define EXT2_FEATURE_COMPAT_RESIZE_INO		0x0010
#define EXT2_FEATURE_COMPAT_DIR_INDEX		0x0020
#define EXT2_FEATURE_COMPAT_LAZY_BG		0x0040
#define EXT2_FEATURE_COMPAT_ANY			0xffffffff


#define EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER     0x0001
#define EXT2_FEATURE_RO_COMPAT_LARGE_FILE       0x0002
//#define EXT2_FEATURE_RO_COMPAT_BTREE_DIR        0x0004
#define EXT4_FEATURE_RO_COMPAT_HUGE_FILE	0x0008
#define EXT4_FEATURE_RO_COMPAT_GDT_CSUM		0x0010
#define EXT4_FEATURE_RO_COMPAT_DIR_NLINK	0x0020
#define EXT4_FEATURE_RO_COMPAT_EXTRA_ISIZE	0x0040
#define EXT2_FEATURE_RO_COMPAT_ANY		0xffffffff

#define EXT2_FEATURE_INCOMPAT_COMPRESSION       0x0001
#define EXT2_FEATURE_INCOMPAT_FILETYPE          0x0002
#define EXT3_FEATURE_INCOMPAT_RECOVER		0x0004
#define EXT3_FEATURE_INCOMPAT_JOURNAL_DEV	0x0008
#define EXT2_FEATURE_INCOMPAT_META_BG		0x0010
#define EXT3_FEATURE_INCOMPAT_EXTENTS		0x0040
#define EXT4_FEATURE_INCOMPAT_64BIT		0x0080
#define EXT4_FEATURE_INCOMPAT_MMP		0x0100
#define EXT2_FEATURE_INCOMPAT_ANY		0xffffffff

/*
 * Structure of the super block
 */
struct ext2_super_block {
	uint32_t	s_inodes_count;		/* Inodes count */
	uint32_t	s_blocks_count;		/* Blocks count */
	uint32_t	s_r_blocks_count;	/* Reserved blocks count */
	uint32_t	s_free_blocks_count;	/* Free blocks count */
	uint32_t	s_free_inodes_count;	/* Free inodes count */
	uint32_t	s_first_data_block;	/* First Data Block */
	uint32_t	s_log_block_size;	/* Block size */
	int32_t	s_log_frag_size;	/* Fragment size */
	uint32_t	s_blocks_per_group;	/* # Blocks per group */
	uint32_t	s_frags_per_group;	/* # Fragments per group */
	uint32_t	s_inodes_per_group;	/* # Inodes per group */
	uint32_t	s_mtime;		/* Mount time */
	uint32_t	s_wtime;		/* Write time */
	uint16_t	s_mnt_count;		/* Mount count */
	int16_t	s_max_mnt_count;	/* Maximal mount count */
	uint16_t	s_magic;		/* Magic signature */
	uint16_t	s_state;		/* File system state */
	uint16_t	s_errors;		/* Behaviour when detecting errors */
	uint16_t	s_minor_rev_level; 	/* minor revision level */
	uint32_t	s_lastcheck;		/* time of last check */
	uint32_t	s_checkinterval;	/* max. time between checks */
	uint32_t	s_creator_os;		/* OS */
	uint32_t	s_rev_level;		/* Revision level */
	uint16_t	s_def_resuid;		/* Default uid for reserved blocks */
	uint16_t	s_def_resgid;		/* Default gid for reserved blocks */
	/*
	 * These fields are for EXT2_DYNAMIC_REV superblocks only.
	 *
	 * Note: the difference between the compatible feature set and
	 * the incompatible feature set is that if there is a bit set
	 * in the incompatible feature set that the kernel doesn't
	 * know about, it should refuse to mount the filesystem.
	 *
	 * e2fsck's requirements are more strict; if it doesn't know
	 * about a feature in either the compatible or incompatible
	 * feature set, it must abort and not try to meddle with
	 * things it doesn't understand...
	 */
	uint32_t	s_first_ino; 		/* First non-reserved inode */
	uint16_t   s_inode_size; 		/* size of inode structure */
	uint16_t	s_block_group_nr; 	/* block group # of this superblock */
	uint32_t	s_feature_compat; 	/* compatible feature set */
	uint32_t	s_feature_incompat; 	/* incompatible feature set */
	uint32_t	s_feature_ro_compat; 	/* readonly-compatible feature set */
	uint8_t	s_uuid[16];		/* 128-bit uuid for volume */
	char	s_volume_name[16]; 	/* volume name */
	char	s_last_mounted[64]; 	/* directory where last mounted */
	uint32_t	s_algorithm_usage_bitmap; /* For compression */
	/*
	 * Performance hints.  Directory preallocation should only
	 * happen if the EXT2_COMPAT_PREALLOC flag is on.
	 */
	uint8_t	s_prealloc_blocks;	/* Nr of blocks to try to preallocate*/
	uint8_t	s_prealloc_dir_blocks;	/* Nr to preallocate for dirs */
	uint16_t	s_reserved_gdt_blocks;	/* Per group table for online growth */
	/*
	 * Journaling support valid if EXT2_FEATURE_COMPAT_HAS_JOURNAL set.
	 */
	uint8_t		s_journal_uuid[16];	/* uuid of journal superblock */
	uint32_t	s_journal_inum;		/* inode number of journal file */
	uint32_t	s_journal_dev;		/* device number of journal file */
	uint32_t	s_last_orphan;		/* start of list of inodes to delete */
	uint32_t	s_hash_seed[4];		/* HTREE hash seed */
	uint8_t		s_def_hash_version;	/* Default hash version to use */
	uint8_t		s_jnl_backup_type; 	/* Default type of journal backup */
	uint16_t	s_desc_size;		/* Group desc. size: INCOMPAT_64BIT */
	uint32_t	s_default_mount_opts;
	uint32_t	s_first_meta_bg;	/* First metablock group */
	uint32_t	s_mkfs_time;		/* When the filesystem was created */
	uint32_t	s_jnl_blocks[17]; 	/* Backup of the journal inode */
	uint32_t	s_blocks_count_hi;	/* Blocks count high 32bits */
	uint32_t	s_r_blocks_count_hi;	/* Reserved blocks count high 32 bits*/
	uint32_t	s_free_blocks_hi; 	/* Free blocks count */
	uint16_t	s_min_extra_isize;	/* All inodes have at least # bytes */
	uint16_t	s_want_extra_isize; 	/* New inodes should reserve # bytes */
	uint32_t	s_flags;		/* Miscellaneous flags */
	uint16_t   	s_raid_stride;		/* RAID stride */
	uint16_t   	s_mmp_update_interval;  /* # seconds to wait in MMP checking */
	uint64_t   	s_mmp_block;            /* Block for multi-mount protection */
	uint32_t   	s_raid_stripe_width;    /* blocks on all data disks (N*stride)*/
	uint8_t		s_log_groups_per_flex;	/* FLEX_BG group size */
	uint8_t    	s_reserved_char_pad;
	uint16_t	s_reserved_pad;		/* Padding to next 32bits */
	uint64_t	s_kbytes_written;	/* nr of lifetime kilobytes written */
	uint32_t	s_snapshot_inum;	/* Inode number of active snapshot */
	uint32_t	s_snapshot_id;		/* sequential ID of active snapshot */
	uint64_t	s_snapshot_r_blocks_count; /* reserved blocks for active
					      snapshot's future use */
	uint32_t	s_snapshot_list;	/* inode number of the head of the on-disk snapshot list */
	uint32_t	s_error_count;		/* number of fs errors */
	uint32_t	s_first_error_time;	/* first time an error happened */
	uint32_t	s_first_error_ino;	/* inode involved in first error */
	uint64_t	s_first_error_block;	/* block involved of first error */
	uint8_t		s_first_error_func[32];	/* function where the error happened */
	uint32_t	s_first_error_line;	/* line number where error happened */
	uint32_t	s_last_error_time;	/* most recent time of an error */
	uint32_t	s_last_error_ino;	/* inode involved in last error */
	uint32_t	s_last_error_line;	/* line number where error happened */
	uint64_t	s_last_error_block;	/* block involved of last error */
	uint8_t		s_last_error_func[32];	/* function where the error happened */
	uint8_t		s_mount_opts[64];
	uint32_t	s_usr_quota_inum;	/* inode number of user quota file */
	uint32_t	s_grp_quota_inum;	/* inode number of group quota file */
	uint32_t	s_overhead_blocks;	/* overhead blocks/clusters in fs */
	uint32_t   	s_reserved[108];        /* Padding to the end of the block */
	uint32_t	s_checksum;		/* crc32c(superblock) */
};

/*@
  @ requires \valid_read(super);
  @ terminates \true;
  @ assigns  \nothing;
  @*/
uint64_t td_ext2fs_blocks_count(const struct ext2_super_block *super);

/*@
  @ requires \valid_read(super);
  @ terminates \true;
  @ assigns  \nothing;
  @*/
uint64_t td_ext2fs_free_blocks_count(const struct ext2_super_block *super);

/*@
  @ requires \valid_read(sb);
  @ requires \initialized(sb);
  @ requires partition==\null || (\valid_read(partition) && valid_partition(partition));
  @ requires \separated(sb, partition);
  @ terminates \true;
  @ assigns  \nothing;
  @ ensures  \result == 7 ==> le32(sb->s_log_block_size) > 6;
  @ ensures  \result == 0 ==> le32(sb->s_log_block_size) <= 6;
  @ */
int test_EXT2(const struct ext2_super_block *sb, const partition_t *partition);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
