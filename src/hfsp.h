/*
    File: hfsp.h, TestDisk

    Copyright (C) 2005-2006 Christophe GRENIER <grenier@cgsecurity.org>
    Original header comes from libhfs - library for reading and writing
    Macintosh HFS volumes
    Copyright (C) 2000 Klaus Halfmann <klaus.halfmann@feri.de>
    Original work by 1996-1998 Robert Leslie <rob@mars.org>
    other work 2000 from Brad Boyer (flar@pants.nu)

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
#ifndef _HFSP_H
#define _HFSP_H
#ifdef __cplusplus
extern "C" {
#endif

#define HFSP_BOOT_SECTOR_SIZE 512
#define HFSP_BLOCKSZ            512	/* A sector for Apple is always 512 bytes */
#define HFSP_BLOCKSZ_BITS       9	/* 1<<9 == 512  */
#define	HFSP_VOLHEAD_SIG        0x482B  /* 'H+'	*/
#define HFSX_VOLHEAD_SIG        0x4858  /* 'HX' */

#define HFSP_VERSION    4
#define HFSX_VERSION    5

// Minimum Key size for all btrees
#define HFSP_CAT_KEY_MIN_LEN	6

// Maximum Key size for all btrees
#define HFSP_CAT_KEY_MAX_LEN	516

/* HFS+ includes POSIX permissions , although marked as reserved they will be
 * used as such. Is ignored by MacOS 8-9 but probably not by MacOS X.
 */
typedef struct {
        uint32_t         owner;
        uint32_t         group;
        uint32_t         mode;
        uint32_t         dev;
} hfsp_perm;

/* A single contiguous area (fragment) of a file */
typedef struct {
        uint32_t         start_block;
        uint32_t         block_count;
} hfsp_extent;

/* A file may contain up to 8 normale extents, all other
   are found in some extra extent area */
typedef hfsp_extent hfsp_extent_rec[8];

/* Information for a "Fork" in a file
 * Forks are the "usual" DATA and RSRC forks or special files
 * (e.g. the Volume Bitmap)
 */
typedef struct {
        uint64_t		total_size;  // logical size
        uint32_t		clump_size;  // number of bytes to preallocate
        uint32_t		total_blocks;
        hfsp_extent_rec extents;     // initial (8) extents
} hfsp_fork_raw;

/* HFS+ Volume Header
 * Always found at block 2 of the disk, a copy is stored
 * at the second to last block of the disk.
 */
typedef struct hfsp_vh {
        uint16_t         signature;   // 00: must be HFSPLUS_VOLHEAD_SIG 'H+'
        uint16_t         version;     // 02: 4 for HFS+, 5 for HFSX
        uint32_t         attributes;  // 04: See bit constants below
        uint32_t         last_mount_vers; // 08
                // Use a registered creator code here (See libhfsp.h)
		// Mac OS uses '8.10' well
        uint32_t         reserved;	// 0C
 
        uint32_t         create_date; // 10 local time !
        uint32_t         modify_date; // 14 GMT (?)
        uint32_t         backup_date; // 18 GMT (?)
        uint32_t         checked_date; // 1C GMT (?) fsck ?
 
        uint32_t         file_count;	// 20
         // not including special files but including DATA and RSRC forks
        uint32_t         folder_count; // 24 excluding the root folder
 
        uint32_t         blocksize;	// 28
         // must be multiple of HFSPLUS_SECTOR_SIZE,
         // should be a multiple of 4k for harddisk
        uint32_t         total_blocks;	// 2C
        uint32_t         free_blocks;	// 30
         // The total number of unused allocation blocks on the disk.
 
        uint32_t         next_alloc;
         // hint where to search for next allocation blocks
        uint32_t         rsrc_clump_sz;
         // default clump size for rsrc forks
        uint32_t         data_clump_sz;
         // default clump size for data forks
        uint32_t	       next_cnid;
         // next unused catalog id
        uint32_t         write_count;
         // increment on every mount (and write ?)
        uint64_t        encodings_bmp;
                // for every encoding used on the disk a bit is set
                // ignored but eventually must be cared for
        char          finder_info[32];                                      
	hfsp_fork_raw   alloc_file;
         // stores bitmap of use/free blocks
        hfsp_fork_raw   ext_file;
         // stores oferflow extents
        hfsp_fork_raw   cat_file;
	 // This contains the root directory
        hfsp_fork_raw   attr_file;
        hfsp_fork_raw   start_file;
         // a special startup file may be described here (used by ?)
} hfsp_vh;

/* HFS+ volume attributes */
/* 0-6 reserved, may be used in memory only */
#define HFSPLUS_VOL_RESERVED1 0x000000FF
#define HFSPLUS_VOL_HARDLOCK  0x00000080 // Used in Memory by finder only
#define HFSPLUS_VOL_UNMNT     0x00000100
        // clear this bit when mounting, set as last step of unmounting
        // This is checked by (slower) ROM code
#define HFSPLUS_VOL_SPARE_BLK 0x00000200
#define HFSPLUS_VOL_NOCACHE   0x00000400
        // in case of RAM or ROM disk (try a HFS+ Ramdisk :)
#define HFSPLUS_VOL_INCNSTNT  0x00000800
        // Reverse meaning as of HFSPLUS_VOL_UNMNT
        // This is checked by (faster) Mac OS code
/* 12-14 reserved */
#define HFSPLUS_VOL_RESERVED2 0x00007000
#define HFSPLUS_VOL_SOFTLOCK  0x00008000
#define HFSPLUS_VOL_RESERVED3 0xFFFF0000


int check_HFSP(disk_t *disk_car,partition_t *partition,const int verbose);
int test_HFSP(disk_t *disk_car, const struct hfsp_vh *vh,partition_t *partition,const int verbose, const int dump_ind);
int recover_HFSP(disk_t *disk_car, const struct hfsp_vh *vh,partition_t *partition,const int verbose, const int dump_ind, const int backup);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
