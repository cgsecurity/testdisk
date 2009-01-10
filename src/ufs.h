/*
 * File ufs.h
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
#ifdef __cplusplus
extern "C" {
#endif

/* ufs superblock size is 1377 but there is room for 8192 */
#define UFS_SUPERBLOCK_SIZE 2048

#define UFS_BBLOCK 0
#define UFS_BBSIZE 8192
#define UFS_SBLOCK 8192
#define UFS_SBSIZE 8192

#define UFS_SECTOR_SIZE 512
#define UFS_SECTOR_BITS 9
#define UFS_MAGIC  0x00011954
#define UFS_CIGAM  0x54190100 /* byteswapped MAGIC */
#define UFS2_MAGIC 0x19540119
#define UFS2_CIGAM 0x19015419

/* Copied from FreeBSD */
/*
 * Each disk drive contains some number of filesystems.
 * A filesystem consists of a number of cylinder groups.
 * Each cylinder group has inodes and data.
 *
 * A filesystem is described by its super-block, which in turn
 * describes the cylinder groups.  The super-block is critical
 * data and is replicated in each cylinder group to protect against
 * catastrophic loss.  This is done at `newfs' time and the critical
 * super-block data does not change, so the copies need not be
 * referenced further unless disaster strikes.
 *
 * For filesystem fs, the offsets of the various blocks of interest
 * are given in the super block as:
 *      [fs->fs_sblkno]         Super-block
 *      [fs->fs_cblkno]         Cylinder group block
 *      [fs->fs_iblkno]         Inode blocks
 *      [fs->fs_dblkno]         Data blocks
 * The beginning of cylinder group cg in fs, is given by
 * the ``cgbase(fs, cg)'' macro.
 *
 * Depending on the architecture and the media, the superblock may
 * reside in any one of four places. For tiny media where every block
 * counts, it is placed at the very front of the partition. Historically,
 * UFS1 placed it 8K from the front to leave room for the disk label and
 * a small bootstrap. For UFS2 it got moved to 64K from the front to leave
 * room for the disk label and a bigger bootstrap, and for really piggy
 * systems we check at 256K from the front if the first three fail. In
 * all cases the size of the superblock will be SBLOCKSIZE. All values are
 * given in byte-offset form, so they do not imply a sector size. The
 * SBLOCKSEARCH specifies the order in which the locations should be searched.
 */
#define SBLOCK_FLOPPY        0
#define SBLOCK_UFS1       8192
#define SBLOCK_UFS2      65536
#define SBLOCK_PIGGY    262144
#define SBLOCKSIZE        8192
#define SBLOCKSEARCH \
        { SBLOCK_UFS2, SBLOCK_UFS1, SBLOCK_FLOPPY, SBLOCK_PIGGY, -1 }


/* HP specific MAGIC values */

#define UFS_MAGIC_LFN   0x00095014 /* fs supports filenames > 14 chars */
#define UFS_CIGAM_LFN   0x14500900 /* srahc 41 < semanelif stroppus sf */

#define UFS_MAGIC_SEC   0x00612195 /* B1 security fs */
#define UFS_CIGAM_SEC   0x95216100

#define UFS_MAGIC_FEA   0x00195612 /* fs_featurebits supported */
#define UFS_CIGAM_FEA   0x12561900

#define UFS_MAGIC_4GB   0x05231994 /* fs > 4 GB && fs_featurebits */
#define UFS_CIGAM_4GB   0x94192305

/* Seems somebody at HP goofed here. B1 and lfs are both 0x2 !?! */
#define UFS_FSF_LFN     0x00000001 /* long file names */
#define UFS_FSF_B1      0x00000002 /* B1 security */
#define UFS_FSF_LFS     0x00000002 /* large files */
#define UFS_FSF_LUID    0x00000004 /* large UIDs */

/* End of HP stuff */


#define UFS_BSIZE	8192
#define UFS_MINBSIZE	4096
#define UFS_FSIZE	1024
#define UFS_MAXFRAG	(UFS_BSIZE / UFS_FSIZE)

#define UFS_NDADDR 12
#define UFS_NINDIR 3

#define UFS_IND_BLOCK	(UFS_NDADDR + 0)
#define UFS_DIND_BLOCK	(UFS_NDADDR + 1)
#define UFS_TIND_BLOCK	(UFS_NDADDR + 2)

#define UFS_NDIR_FRAGMENT (UFS_NDADDR << uspi->s_fpbshift)
#define UFS_IND_FRAGMENT (UFS_IND_BLOCK << uspi->s_fpbshift)
#define UFS_DIND_FRAGMENT (UFS_DIND_BLOCK << uspi->s_fpbshift)
#define UFS_TIND_FRAGMENT (UFS_TIND_BLOCK << uspi->s_fpbshift)

#define UFS_ROOTINO 2
#define UFS_FIRST_INO (UFS_ROOTINO + 1)

#define UFS_USEEFT  ((__u16)65535)

#define UFS_FSOK      0x7c269d38
#define UFS_FSACTIVE  ((char)0x00)
#define UFS_FSCLEAN   ((char)0x01)
#define UFS_FSSTABLE  ((char)0x02)
#define UFS_FSOSF1    ((char)0x03)	/* is this correct for DEC OSF/1? */
#define UFS_FSBAD     ((char)0xff)

/* From here to next blank line, s_flags for ufs_sb_info */
/* directory entry encoding */
#define UFS_DE_MASK		0x00000010	/* mask for the following */
#define UFS_DE_OLD		0x00000000
#define UFS_DE_44BSD		0x00000010
/* uid encoding */
#define UFS_UID_MASK		0x00000060	/* mask for the following */
#define UFS_UID_OLD		0x00000000
#define UFS_UID_44BSD		0x00000020
#define UFS_UID_EFT		0x00000040
/* superblock state encoding */
#define UFS_ST_MASK		0x00000700	/* mask for the following */
#define UFS_ST_OLD		0x00000000
#define UFS_ST_44BSD		0x00000100
#define UFS_ST_SUN		0x00000200
#define UFS_ST_SUNx86		0x00000400
/*cylinder group encoding */
#define UFS_CG_MASK		0x00003000	/* mask for the following */
#define UFS_CG_OLD		0x00000000
#define UFS_CG_44BSD		0x00002000
#define UFS_CG_SUN		0x00001000
/* filesystem type encoding */
#define UFS_TYPE_MASK		0x00010000	/* mask for the following */
#define UFS_TYPE_UFS1		0x00000000
#define UFS_TYPE_UFS2		0x00010000


/* fs_inodefmt options */
#define UFS_42INODEFMT	-1
#define UFS_44INODEFMT	2

/* mount options */
#define UFS_MOUNT_ONERROR		0x0000000F
#define UFS_MOUNT_ONERROR_PANIC		0x00000001
#define UFS_MOUNT_ONERROR_LOCK		0x00000002
#define UFS_MOUNT_ONERROR_UMOUNT	0x00000004
#define UFS_MOUNT_ONERROR_REPAIR	0x00000008

#define UFS_MOUNT_UFSTYPE		0x0000FFF0
#define UFS_MOUNT_UFSTYPE_OLD		0x00000010
#define UFS_MOUNT_UFSTYPE_44BSD		0x00000020
#define UFS_MOUNT_UFSTYPE_SUN		0x00000040
#define UFS_MOUNT_UFSTYPE_NEXTSTEP	0x00000080
#define UFS_MOUNT_UFSTYPE_NEXTSTEP_CD	0x00000100
#define UFS_MOUNT_UFSTYPE_OPENSTEP	0x00000200
#define UFS_MOUNT_UFSTYPE_SUNx86	0x00000400
#define UFS_MOUNT_UFSTYPE_HP	        0x00000800
#define UFS_MOUNT_UFSTYPE_UFS2		0x00001000

#define ufs_clear_opt(o,opt)	o &= ~UFS_MOUNT_##opt
#define ufs_set_opt(o,opt)	o |= UFS_MOUNT_##opt
#define ufs_test_opt(o,opt)	((o) & UFS_MOUNT_##opt)

/*
 * MINFREE gives the minimum acceptable percentage of file system
 * blocks which may be free. If the freelist drops below this level
 * only the superuser may continue to allocate blocks. This may
 * be set to 0 if no reserve of free blocks is deemed necessary,
 * however throughput drops by fifty percent if the file system
 * is run at between 95% and 100% full; thus the minimum default
 * value of fs_minfree is 5%. However, to get good clustering
 * performance, 10% is a better choice. hence we use 10% as our
 * default value. With 10% free space, fragmentation is not a
 * problem, so we choose to optimize for time.
 */
#define UFS_MINFREE         5
#define UFS_DEFAULTOPT      UFS_OPTTIME
            
/*
 * Turn file system block numbers into disk block addresses.
 * This maps file system blocks to device size blocks.
 */
#define ufs_fsbtodb(uspi, b)	((b) << (uspi)->s_fsbtodb)
#define	ufs_dbtofsb(uspi, b)	((b) >> (uspi)->s_fsbtodb)

/*
 * Cylinder group macros to locate things in cylinder groups.
 * They calc file system addresses of cylinder group data structures.
 */
#define	ufs_cgbase(c)	(uspi->s_fpg * (c))
#define ufs_cgstart(c)	((uspi)->fs_magic == UFS2_MAGIC ?  ufs_cgbase(c) : \
	(ufs_cgbase(c)  + uspi->s_cgoffset * ((c) & ~uspi->s_cgmask)))
#define	ufs_cgsblock(c)	(ufs_cgstart(c) + uspi->s_sblkno)	/* super blk */
#define	ufs_cgcmin(c)	(ufs_cgstart(c) + uspi->s_cblkno)	/* cg block */
#define	ufs_cgimin(c)	(ufs_cgstart(c) + uspi->s_iblkno)	/* inode blk */
#define	ufs_cgdmin(c)	(ufs_cgstart(c) + uspi->s_dblkno)	/* 1st data */

/*
 * Macros for handling inode numbers:
 *     inode number to file system block offset.
 *     inode number to cylinder group number.
 *     inode number to file system block address.
 */
#define	ufs_inotocg(x)		((x) / uspi->s_ipg)
#define	ufs_inotocgoff(x)	((x) % uspi->s_ipg)
#define	ufs_inotofsba(x)	(ufs_cgimin(ufs_inotocg(x)) + ufs_inotocgoff(x) / uspi->s_inopf)
#define	ufs_inotofsbo(x)	((x) % uspi->s_inopf)

/*
 * Give cylinder group number for a file system block.
 * Give cylinder group block number for a file system block.
 */
#define	ufs_dtog(d)	((d) / uspi->s_fpg)
#define	ufs_dtogd(d)	((d) % uspi->s_fpg)

/*
 * Compute the cylinder and rotational position of a cyl block addr.
 */
#define ufs_cbtocylno(bno) \
	((bno) * uspi->s_nspf / uspi->s_spc)
#define ufs_cbtorpos(bno) \
	((((bno) * uspi->s_nspf % uspi->s_spc / uspi->s_nsect \
	* uspi->s_trackskew + (bno) * uspi->s_nspf % uspi->s_spc \
	% uspi->s_nsect * uspi->s_interleave) % uspi->s_nsect \
	* uspi->s_nrpos) / uspi->s_npsect)

/*
 * The following macros optimize certain frequently calculated
 * quantities by using shifts and masks in place of divisions
 * modulos and multiplications.
 */
#define ufs_blkoff(loc)		((loc) & uspi->s_qbmask)
#define ufs_fragoff(loc)	((loc) & uspi->s_qfmask)
#define ufs_lblktosize(blk)	((blk) << uspi->s_bshift)
#define ufs_lblkno(loc)		((loc) >> uspi->s_bshift)
#define ufs_numfrags(loc)	((loc) >> uspi->s_fshift)
#define ufs_blkroundup(size)	(((size) + uspi->s_qbmask) & uspi->s_bmask)
#define ufs_fragroundup(size)	(((size) + uspi->s_qfmask) & uspi->s_fmask)
#define ufs_fragstoblks(frags)	((frags) >> uspi->s_fpbshift)
#define ufs_blkstofrags(blks)	((blks) << uspi->s_fpbshift)
#define ufs_fragnum(fsb)	((fsb) & uspi->s_fpbmask)
#define ufs_blknum(fsb)		((fsb) & ~uspi->s_fpbmask)

#define	UFS_MAXNAMLEN 255
#define UFS_MAXMNTLEN 512
#define UFS2_MAXMNTLEN 468
#define UFS2_MAXVOLLEN 32
#define UFS_MAXCSBUFS 31
#define UFS_LINK_MAX 32000
#define	UFS2_NOCSPTRS	28

/*
 * UFS_DIR_PAD defines the directory entries boundaries
 * (must be a multiple of 4)
 */
#define UFS_DIR_PAD			4
#define UFS_DIR_ROUND			(UFS_DIR_PAD - 1)
#define UFS_DIR_REC_LEN(name_len)	(((name_len) + 1 + 8 + UFS_DIR_ROUND) & ~UFS_DIR_ROUND)

struct ufs_timeval {
	uint32_t	tv_sec;
	uint32_t	tv_usec;
} __attribute__ ((__packed__));

struct ufs_csum {
	uint32_t	cs_ndir;	/* number of directories */
	uint32_t	cs_nbfree;	/* number of free blocks */
	uint32_t	cs_nifree;	/* number of free inodes */
	uint32_t	cs_nffree;	/* number of free frags */
} __attribute__ ((__packed__));
struct ufs2_csum_total {
	uint64_t	cs_ndir;	/* number of directories */
	uint64_t	cs_nbfree;	/* number of free blocks */
	uint64_t	cs_nifree;	/* number of free inodes */
	uint64_t	cs_nffree;	/* number of free frags */
	uint64_t   cs_numclusters;	/* number of free clusters */
	uint64_t   cs_spare[3];	/* future expansion */
} __attribute__ ((__packed__));

struct fs_u11_u1_st {
  int8_t	fs_fsmnt[UFS_MAXMNTLEN];/* name mounted on */
  uint32_t	fs_cgrotor;	/* last cg searched */
  uint32_t	fs_csp[UFS_MAXCSBUFS];/*list of fs_cs info buffers */
  uint32_t	fs_maxcluster;
  uint32_t	fs_cpc;		/* cyl per cycle in postbl */
  uint16_t	fs_opostbl[16][8]; /* old rotation block list head */
} __attribute__ ((__packed__));

struct fs_u11_u2_st {
	int8_t  fs_fsmnt[UFS2_MAXMNTLEN];	/* name mounted on */
	uint8_t   fs_volname[UFS2_MAXVOLLEN]; /* volume name */
	uint64_t  fs_swuid;		/* system-wide uid */
	uint32_t  fs_pad;	/* due to alignment of fs_swuid */
	uint32_t   fs_cgrotor;     /* last cg searched */
	uint32_t   fs_ocsp[UFS2_NOCSPTRS]; /*list of fs_cs info buffers */
	uint32_t   fs_contigdirs;/*# of contiguously allocated dirs */
	uint32_t   fs_csp;	/* cg summary info buffer for fs_cs */
	uint32_t   fs_maxcluster;
	uint32_t   fs_active;/* used by snapshots to track fs */
	uint32_t   fs_old_cpc;	/* cyl per cycle in postbl */
	uint32_t   fs_maxbsize;/*maximum blocking factor permitted */
	uint64_t   fs_sparecon64[17];/*old rotation block list head */
	uint64_t   fs_sblockloc; /* byte offset of standard superblock */
	struct  ufs2_csum_total fs_cstotal;/*cylinder summary information*/
	struct  ufs_timeval    fs_time;		/* last time written */
	uint64_t    fs_size;		/* number of blocks in fs */
	uint64_t    fs_dsize;	/* number of data blocks in fs */
	uint64_t   fs_csaddr;	/* blk addr of cyl grp summary area */
	uint64_t    fs_pendingblocks;/* blocks in process of being freed */
	uint32_t    fs_pendinginodes;/*inodes in process of being freed */
} __attribute__ ((__packed__));

/*
 * This is the actual superblock, as it is laid out on the disk.
 */
struct ufs_super_block {
	uint32_t	fs_link;	/* UNUSED */
	uint32_t	fs_rlink;	/* UNUSED */
	uint32_t	fs_sblkno;	/* addr of super-block in filesys */
	uint32_t	fs_cblkno;	/* offset of cyl-block in filesys */
	uint32_t	fs_iblkno;	/* offset of inode-blocks in filesys */
	uint32_t	fs_dblkno;	/* offset of first data after cg */
	uint32_t	fs_cgoffset;	/* cylinder group offset in cylinder */
	uint32_t	fs_cgmask;	/* used to calc mod fs_ntrak */
	uint32_t	fs_time;	/* last time written -- time_t */
	uint32_t	fs_size;	/* number of blocks in fs */
	uint32_t	fs_dsize;	/* number of data blocks in fs */
	uint32_t	fs_ncg;		/* number of cylinder groups */
	uint32_t	fs_bsize;	/* size of basic blocks in fs */
	uint32_t	fs_fsize;	/* size of frag blocks in fs */
	uint32_t	fs_frag;	/* number of frags in a block in fs */
/* these are configuration parameters */
	uint32_t	fs_minfree;	/* minimum percentage of free blocks */
	uint32_t	fs_rotdelay;	/* num of ms for optimal next block */
	uint32_t	fs_rps;		/* disk revolutions per second */
/* these fields can be computed from the others */
	uint32_t	fs_bmask;	/* ``blkoff'' calc of blk offsets */
	uint32_t	fs_fmask;	/* ``fragoff'' calc of frag offsets */
	uint32_t	fs_bshift;	/* ``lblkno'' calc of logical blkno */
	uint32_t	fs_fshift;	/* ``numfrags'' calc number of frags */
/* these are configuration parameters */
	uint32_t	fs_maxcontig;	/* max number of contiguous blks */
	uint32_t	fs_maxbpg;	/* max number of blks per cyl group */
/* these fields can be computed from the others */
	uint32_t	fs_fragshift;	/* block to frag shift */
	uint32_t	fs_fsbtodb;	/* fsbtodb and dbtofsb shift constant */
	uint32_t	fs_sbsize;	/* actual size of super block */
	uint32_t	fs_csmask;	/* csum block offset */
	uint32_t	fs_csshift;	/* csum block number */
	uint32_t	fs_nindir;	/* value of NINDIR */
	uint32_t	fs_inopb;	/* value of INOPB */
	uint32_t	fs_nspf;	/* value of NSPF */
/* yet another configuration parameter */
	uint32_t	fs_optim;	/* optimization preference, see below */
/* these fields are derived from the hardware */
	union {
		struct {
			uint32_t	fs_npsect;	/* # sectors/track including spares */
		} fs_sun;
		struct {
			uint32_t	fs_state;	/* file system state time stamp */
		} fs_sunx86;
	} fs_u1;
	uint32_t	fs_interleave;	/* hardware sector interleave */
	uint32_t	fs_trackskew;	/* sector 0 skew, per track */
/* a unique id for this filesystem (currently unused and unmaintained) */
/* In 4.3 Tahoe this space is used by fs_headswitch and fs_trkseek */
/* Neither of those fields is used in the Tahoe code right now but */
/* there could be problems if they are.                            */
	uint32_t	fs_id[2];	/* file system id */
/* sizes determined by number of cylinder groups and their sizes */
	uint32_t	fs_csaddr;	/* blk addr of cyl grp summary area */
	uint32_t	fs_cssize;	/* size of cyl grp summary area */
	uint32_t	fs_cgsize;	/* cylinder group size */
/* these fields are derived from the hardware */
	uint32_t	fs_ntrak;	/* tracks per cylinder */
	uint32_t	fs_nsect;	/* sectors per track */
	uint32_t	fs_spc;		/* sectors per cylinder */
/* this comes from the disk driver partitioning */
	uint32_t	fs_ncyl;	/* cylinders in file system */
/* these fields can be computed from the others */
	uint32_t	fs_cpg;		/* cylinders per group */
	uint32_t	fs_ipg;		/* inodes per cylinder group */
	uint32_t	fs_fpg;		/* blocks per group * fs_frag */
/* this data must be re-computed after crashes */
	struct ufs_csum fs_cstotal;	/* cylinder summary information */
/* these fields are cleared at mount time */
	int8_t	fs_fmod;	/* super block modified flag */
	int8_t	fs_clean;	/* file system is clean flag */
	int8_t	fs_ronly;	/* mounted read-only flag */
	int8_t	fs_flags;	/* currently unused flag */
	union {
		struct fs_u11_u1_st fs_u1;
		struct fs_u11_u2_st fs_u2;
	}  fs_u11;
	union {
		struct {
			uint32_t	fs_sparecon[53];/* reserved for future constants */
			uint32_t	fs_reclaim;
			uint32_t	fs_sparecon2[1];
			uint32_t	fs_state;	/* file system state time stamp */
			uint32_t	fs_qbmask[2];	/* ~usb_bmask */
			uint32_t	fs_qfmask[2];	/* ~usb_fmask */
		} fs_sun;
		struct {
			uint32_t	fs_sparecon[53];/* reserved for future constants */
			uint32_t	fs_reclaim;
			uint32_t	fs_sparecon2[1];
			uint32_t	fs_npsect;	/* # sectors/track including spares */
			uint32_t	fs_qbmask[2];	/* ~usb_bmask */
			uint32_t	fs_qfmask[2];	/* ~usb_fmask */
		} fs_sunx86;
		struct {
			uint32_t	fs_sparecon[50];/* reserved for future constants */
			uint32_t	fs_contigsumsize;/* size of cluster summary array */
			uint32_t	fs_maxsymlinklen;/* max length of an internal symlink */
			uint32_t	fs_inodefmt;	/* format of on-disk inodes */
			uint32_t	fs_maxfilesize[2];	/* max representable file size */
			uint32_t	fs_qbmask[2];	/* ~usb_bmask */
			uint32_t	fs_qfmask[2];	/* ~usb_fmask */
			uint32_t	fs_state;	/* file system state time stamp */
		} fs_44;
	} fs_u2;
	uint32_t	fs_postblformat;	/* format of positional layout tables */
	uint32_t	fs_nrpos;		/* number of rotational positions */
	uint32_t	fs_postbloff;		/* (__s16) rotation block list head */
	uint32_t	fs_rotbloff;		/* (uint8_t) blocks for each rotation */
	uint32_t	fs_magic;		/* magic number */
	uint8_t	fs_space[1];		/* list of blocks for each rotation */
} __attribute__ ((__packed__));

/*
 * Preference for optimization.
 */
#define UFS_OPTTIME	0	/* minimize allocation time */
#define UFS_OPTSPACE	1	/* minimize disk fragmentation */

/*
 * Rotational layout table format types
 */
#define UFS_42POSTBLFMT		-1	/* 4.2BSD rotational table format */
#define UFS_DYNAMICPOSTBLFMT	1	/* dynamic rotational table format */


int check_ufs(disk_t *disk_car,partition_t *partition,const int verbose);
int recover_ufs(disk_t *disk_car, const struct ufs_super_block *sb, partition_t *partition,const int verbose, const int dump_ind);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
