/*

    File: cramfs.h

    Copyright (C) 2004-2006 Christophe GRENIER <grenier@cgsecurity.org>
  
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
/* real size is 76 */
#define CRAMFS_SUPERBLOCK_SIZE 512
#define CRAMFS_MAGIC		0x28cd3d45	/* some random number */
#define CRAMFS_SIGNATURE	"Compressed ROMFS"

struct cramfs_info {
	uint32_t crc;
	uint32_t edition;
	uint32_t blocks;
	uint32_t files;
};

/*
 * Width of various bitfields in struct cramfs_inode.
 * Primarily used to generate warnings in mkcramfs.
 */
#define CRAMFS_MODE_WIDTH 16
#define CRAMFS_UID_WIDTH 16
#define CRAMFS_SIZE_WIDTH 24
#define CRAMFS_GID_WIDTH 8
#define CRAMFS_NAMELEN_WIDTH 6
#define CRAMFS_OFFSET_WIDTH 26

/*
 * Since inode.namelen is a unsigned 6-bit number, the maximum cramfs
 * path length is 63 << 2 = 252.
 */
#define CRAMFS_MAXPATHLEN (((1 << CRAMFS_NAMELEN_WIDTH) - 1) << 2)

/*
 * Reasonably terse representation of the inode data.
 */
struct cramfs_inode {
	uint32_t mode:CRAMFS_MODE_WIDTH, uid:CRAMFS_UID_WIDTH;
	/* SIZE for device files is i_rdev */
	uint32_t size:CRAMFS_SIZE_WIDTH, gid:CRAMFS_GID_WIDTH;
	/* NAMELEN is the length of the file name, divided by 4 and
           rounded up.  (cramfs doesn't support hard links.) */
	/* OFFSET: For symlinks and non-empty regular files, this
	   contains the offset (divided by 4) of the file data in
	   compressed form (starting with an array of block pointers;
	   see README).  For non-empty directories it is the offset
	   (divided by 4) of the inode of the first file in that
	   directory.  For anything else, offset is zero. */
	uint32_t namelen:CRAMFS_NAMELEN_WIDTH, offset:CRAMFS_OFFSET_WIDTH;
};


struct cramfs_super {
	uint32_t magic;			/* 0x28cd3d45 - random number */
	uint32_t size;			/* length in bytes */
	uint32_t flags;			/* feature flags */
	uint32_t future;		/* reserved for future use */
	uint8_t signature[16];		/* "Compressed ROMFS" */
	struct cramfs_info fsid;	/* unique filesystem info */
	uint8_t name[16];		/* user-defined name */
	struct cramfs_inode root;	/* root inode data */
};


int check_cramfs(disk_t *disk_car,partition_t *partition,const int verbose);
int recover_cramfs(disk_t *disk_car, const struct cramfs_super *sb,partition_t *partition,const int verbose, const int dump_ind);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
