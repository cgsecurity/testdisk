/*

    File: bfs.h

    Copyright (C) 1998-2006 Christophe GRENIER <grenier@cgsecurity.org>
  
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

/* real size is 164 */
#define BFS_SUPERBLOCK_SIZE 512

typedef struct block_run
{
    uint32_t   allocation_group;
    uint16_t  start;
    uint16_t  len;       /* in blocks */
} block_run;

typedef block_run inode_addr;


#define B_OS_NAME_LENGTH 32

struct disk_super_block          /* super block as it is on disk */
{
    char         name[B_OS_NAME_LENGTH];
    uint32_t        magic1;                /* 0x20 */
    uint32_t        fs_byte_order;         /* 0x24 */

    uint32_t       block_size;            /* 0x28 in bytes */
    uint32_t       block_shift;           /* 0x2C block_size == (1 << block_shift) */

    uint64_t        num_blocks;            /* 0x30 */
    uint64_t        used_blocks;           /* 0x38 */

    uint32_t        inode_size;            /* 0x40 # of bytes per inode */

    uint32_t        magic2;                /* 0x44 */
    uint32_t        blocks_per_ag;         /* 0x48 in blocks */
    uint32_t        ag_shift;              /* 0x4C # of bits to shift to get ag num */
    uint32_t        num_ags;               /* 0x50 # of allocation groups */
    uint32_t        flags;                 /* 0x54 if it's clean, etc */
    block_run    log_blocks;             /* 0x58 a block_run of the log blocks */
    uint64_t        log_start;              /* 0x60 block # of the beginning */
    uint64_t        log_end;                /* 0x68 block # of the end of the log */

    uint32_t        magic3;                /* 0x70 */
    inode_addr   root_dir;              /* 0x74 */
    inode_addr   indices;               /* 0x7C */

    uint32_t        pad[8];               /* 0x84 extra stuff for the future */
					/* 0xA4-0xFF */
};


/*the flags field can have these values */
#define BFS_CLEAN   0x434c454e           /* 'CLEN', for flags field */
#define BFS_DIRTY   0x44495254           /* 'DIRT', for flags field */

/* these are the magic numbers for the 3 magic fields */
#define SUPER_BLOCK_MAGIC1   0x42465331    /* BFS1 */
#define SUPER_BLOCK_MAGIC2   0xdd121031
#define SUPER_BLOCK_MAGIC3   0x15b6830e

/* this is stored in the fs_byte_order field... it's kind of dumb */
#define BFS_BIG_ENDIAN       0x42494745    /* BIGE */
/* int test_beos(struct disk_super_block *,partition_t); */
int check_BeFS(disk_t *disk_car, partition_t *partition);
int recover_BeFS(disk_t *disk_car, const struct disk_super_block *beos_block, partition_t *partition, const int dump_ind);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
