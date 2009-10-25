/*

    File: rfs.h

    Copyright (C) 2005-2006  Christophe GRENIER <grenier@cgsecurity.org>
    Taken from ReiserFS v0.91. Reiserfs Copyright 1996, 1997, 1998 Hans Reiser
  
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

#define REISERFS_SUPER_MAGIC		"ReIsErFs"
#define REISERFS2_SUPER_MAGIC		"ReIsEr2Fs"
#define REISERFS3_SUPER_MAGIC		"ReIsEr3Fs"
#define REISERFS_FIRST_BLOCK		8
#define REISERFS_VALID_FS		1
#define REISERFS_ERROR_FS		2
#define REISERFS_MIN_BLOCK_AMOUNT	100

/* 8*512 for offset + 512 for format40_super */
#define REISERFS_SUPER_BLOCK_SIZE	9*512

struct reiserfs_super_block
{
	uint32_t s_block_count;		/* 0x00 blocks count         */
	uint32_t s_free_blocks;		/* 0x04 free blocks count    */
	uint32_t s_root_block;		/* 0x08 root block number    */
	uint32_t s_journal_block;	/* 0x0C journal block number    */
	uint32_t s_journal_dev;		/* 0x10 journal device number  */
	uint32_t s_orig_journal_size;	/* 0x14 size of the journal on FS creation. */
	uint32_t s_journal_trans_max;	/* 0x18 max number of blocks in a transaction.  */
	uint32_t s_journal_block_count;	/* 0x1C total size of the journal. can change over time  */
	uint32_t s_journal_max_batch;	/* 0x20 max number of blocks to batch into a trans */
	uint32_t s_journal_max_commit_age;	/* 0x24 in seconds, how old can an async commit be */
	uint32_t s_journal_max_trans_age;	/* 0x28 in seconds, how old can a transaction be */
	uint16_t s_blocksize;		/* 0x2C block size           */
	uint16_t s_oid_maxsize;		/* 0x2E max size of object id array, see get_objectid() commentary  */
	uint16_t s_oid_cursize;		/* 0x30 current size of object id array */
	uint16_t s_state;		/* 0x32 valid or error       */
	char s_magic[10];		/* 0x34 reiserfs magic string indicates that file system is reiserfs */
	uint16_t sb_fs_state; 		/* 0x3E it is set to used by fsck to mark which phase of
					   rebuilding is done (used for fsck debugging) */
	uint32_t s_hash_function_code;	/* 0x40 indicate, what hash fuction is being use to sort names in a directory*/
	uint16_t s_tree_height;		/* 0x44 height of disk tree */
	uint16_t s_bmap_nr;		/* 0x46 amount of bitmap blocks needed to address each block of file system */
	uint16_t sb_version; 		/* 72 this field is only reliable on
					   filesystem with non-standard journal */
	uint16_t sb_reserved_for_journal;  /* 74 size in blocks of journal area on
					   main device, we need to keep after
					   non-standard journal relocation */
/* 76 */     uint32_t sb_inode_generation; 
/* 80 */     uint32_t s_flags;                /* Right now used only by inode-attributes, if enabled */
/* 84 */    unsigned char s_uuid[16];      /* filesystem unique identifier */
/*100 */    unsigned char s_label[16];     /* filesystem volume label */
/*116 */    char s_unused[88] ;            /* zero filled by mkreiserfs and reiserfs_convert_objectid_map_v1()
                                            * so any additions must be updated there as well. */ 
/*204*/
} __attribute__ ((__packed__));

#define SB_SIZE (sizeof(struct reiserfs_super_block))

#define REISERFS4_SUPER_MAGIC		"ReIsEr4"
#define MAGIC_SIZE 16
struct reiser4_master_sb {
  char magic[16];         /* "ReIsEr4" */
  uint16_t disk_plugin_id;     /* id of disk layout plugin */
  uint16_t blocksize;
  char uuid[16];          /* unique id */
  char label[16];         /* filesystem label */
  uint64_t diskmap;            /* location of the diskmap. 0 if not present */
} __attribute__ ((__packed__));

struct format40_super {
  uint64_t sb_block_count;
  uint64_t sb_free_blocks;
  uint64_t sb_root_block;

  /* These 2 fields are for oid data. */
  uint64_t sb_oid[2];

  uint64_t sb_flushes;

  uint32_t sb_mkfs_id;
  char sb_magic[MAGIC_SIZE];

  uint16_t sb_tree_height;
  uint16_t sb_policy;
  uint64_t sb_flags;

  char sb_unused[432];
} __attribute__((packed));

int check_rfs(disk_t *disk_car,partition_t *partition,const int verbose);
int recover_rfs(disk_t *disk_car, const struct reiserfs_super_block *sb,partition_t *partition,const int verbose, const int dump_ind);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
