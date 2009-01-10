/*
 * File xfs.h
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it would be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Further, this software is distributed without any warranty that it is
 * free of the rightful claim of any third person regarding infringement
 * or the like.  Any license provided herein, whether implied or
 * otherwise, applies only to this software file.  Patent licenses, if
 * any, provided herein do not apply to combinations of this program with
 * other software, or any other product whatsoever.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

/*
 * Super block
 * Fits into a sector-sized buffer at address 0 of each allocation group.
 * Only the first of these is ever updated except during growfs.
 */
#ifdef __cplusplus
extern "C" {
#endif

#define XFS_SUPERBLOCK_SIZE	512

#define	XFS_SB_MAGIC		0x58465342	/* 'XFSB' */
#define	XFS_SB_VERSION_1	1		/* 5.3, 6.0.1, 6.1 */
#define	XFS_SB_VERSION_2	2		/* 6.2 - attributes */
#define	XFS_SB_VERSION_3	3		/* 6.2 - new inode version */
#define	XFS_SB_VERSION_4	4		/* 6.2+ - bitmask version */
#define XFS_SB_VERSION_NUMBITS          0x000f

typedef	uint32_t	xfs_extlen_t;	/* extent length in blocks */
typedef uint64_t	xfs_drfsbno_t;	/* blockno in filesystem (raw) */
typedef	uint64_t	xfs_drtbno_t;	/* extent (block) in realtime area */
typedef uint64_t	xfs_ino_t;	/* <inode> type */
typedef uint32_t	xfs_agblock_t;	/* blockno in alloc. group */
typedef	uint32_t	xfs_agnumber_t;	/* allocation group number */
typedef uint64_t        xfs_dfsbno_t;

struct xfs_sb
{
	uint32_t	sb_magicnum;	/* magic number == XFS_SB_MAGIC */
	uint32_t	sb_blocksize;	/* logical block size, bytes */
	xfs_drfsbno_t	sb_dblocks;	/* number of data blocks */
	xfs_drfsbno_t	sb_rblocks;	/* number of realtime blocks */
	xfs_drtbno_t	sb_rextents;	/* number of realtime extents */
	uint8_t		sb_uuid[16];	/* file system unique id */
	xfs_dfsbno_t	sb_logstart;	/* starting block of log if internal */
	xfs_ino_t	sb_rootino;	/* root inode number */
	xfs_ino_t	sb_rbmino;	/* bitmap inode for realtime extents */
	xfs_ino_t	sb_rsumino;	/* summary inode for rt bitmap */
	xfs_agblock_t	sb_rextsize;	/* realtime extent size, blocks */
	xfs_agblock_t	sb_agblocks;	/* size of an allocation group */
	xfs_agnumber_t	sb_agcount;	/* number of allocation groups */
	xfs_extlen_t	sb_rbmblocks;	/* number of rt bitmap blocks */
	xfs_extlen_t	sb_logblocks;	/* number of log blocks */
	uint16_t	sb_versionnum;	/* header version == XFS_SB_VERSION */
	uint16_t	sb_sectsize;	/* volume sector size, bytes */
	uint16_t	sb_inodesize;	/* inode size, bytes */
	uint16_t	sb_inopblock;	/* inodes per block */
	char		sb_fname[12];	/* file system name */
	uint8_t	sb_blocklog;	/* log2 of sb_blocksize */
	uint8_t	sb_sectlog;	/* log2 of sb_sectsize */
	uint8_t	sb_inodelog;	/* log2 of sb_inodesize */
	uint8_t	sb_inopblog;	/* log2 of sb_inopblock */
	uint8_t	sb_agblklog;	/* log2 of sb_agblocks (rounded up) */
	uint8_t	sb_rextslog;	/* log2 of sb_rextents */
	uint8_t	sb_inprogress;	/* mkfs is in progress, don't mount */
	uint8_t	sb_imax_pct;	/* max % of fs for inode space */
					/* statistics */
	/*
	 * These fields must remain contiguous.  If you really
	 * want to change their layout, make sure you fix the
	 * code in xfs_trans_apply_sb_deltas().
	 */
	uint64_t	sb_icount;	/* allocated inodes */
	uint64_t	sb_ifree;	/* free inodes */
	uint64_t	sb_fdblocks;	/* free data blocks */
	uint64_t	sb_frextents;	/* free realtime extents */
	/*
	 * End contiguous fields.
	 */
	xfs_ino_t	sb_uquotino;	/* user quota inode */
	xfs_ino_t	sb_gquotino;	/* group quota inode */
	uint16_t	sb_qflags;	/* quota flags */
	uint8_t	sb_flags;	/* misc. flags */
	uint8_t	sb_shared_vn;	/* shared version number */
	xfs_extlen_t	sb_inoalignmt;	/* inode chunk alignment, fsblocks */
	uint32_t	sb_unit;	/* stripe or raid unit */
	uint32_t	sb_width;	/* stripe or raid width */
	uint8_t	sb_dirblklog;	/* log2 of dir block size (fsbs) */
	uint8_t	sb_logsectlog;	/* log2 of the log sector size */
	uint16_t	sb_logsectsize;	/* sector size for the log, bytes */
	uint32_t	sb_logsunit;	/* stripe unit size for the log */
	uint32_t	sb_features2;	/* additonal feature bits */
} __attribute__ ((__packed__));

int check_xfs(disk_t *disk_car,partition_t *partition,const int verbose);
int recover_xfs(disk_t *disk_car, const struct xfs_sb *sb,partition_t *partition,const int verbose, const int dump_ind);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
