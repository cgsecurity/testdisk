/*

    File: gfs2.h

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

// Structure from gfs2_ondisk.h
#define GFS2_MAGIC		0x01161970
#define GFS2_BASIC_BLOCK	512
#define GFS2_BASIC_BLOCK_SHIFT	9
#define GFS2_FORMAT_SB		100

/*
 * An on-disk inode number
 */

struct gfs2_inum {
	uint64_t no_formal_ino;
	uint64_t no_addr;
};

struct gfs2_meta_header {
	uint32_t mh_magic;
	uint32_t mh_type;
	uint64_t __pad0;		/* Was generation number in gfs1 */
	uint32_t mh_format;
	/* This union is to keep userspace happy */
	union {
		uint32_t mh_jid;		/* Was incarnation number in gfs1 */
		uint32_t __pad1;
	};
};
/* Address of superblock in GFS2 basic blocks */
#define GFS2_SB_ADDR		128
#define GFS2_LOCKNAME_LEN	64

struct gfs2_sb {
	struct gfs2_meta_header sb_header;

	uint32_t sb_fs_format;
	uint32_t sb_multihost_format;
	uint32_t  __pad0;	/* Was superblock flags in gfs1 */

	uint32_t sb_bsize;
	uint32_t sb_bsize_shift;
	uint32_t __pad1;	/* Was journal segment size in gfs1 */

	struct gfs2_inum sb_master_dir; /* Was jindex dinode in gfs1 */
	struct gfs2_inum __pad2; /* Was rindex dinode in gfs1 */
	struct gfs2_inum sb_root_dir;

	char sb_lockproto[GFS2_LOCKNAME_LEN];
	char sb_locktable[GFS2_LOCKNAME_LEN];

	struct gfs2_inum __pad3; /* Was quota inode in gfs1 */
	struct gfs2_inum __pad4; /* Was licence inode in gfs1 */
#define GFS2_HAS_UUID 1
	uint8_t sb_uuid[16]; /* The UUID, maybe 0 for backwards compat */
};

//
int check_gfs2(disk_t *disk_car, partition_t *partition);
int recover_gfs2(disk_t *disk_car, const struct gfs2_sb *sb, partition_t *partition, const int dump_ind);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
