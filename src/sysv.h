/*

    File: sysv.c

    Copyright (C) 2004-2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#define SYSV4_SUPERBLOCK_SIZE 512

#define __packed2__  __attribute__ ((packed, aligned(2)))

/* inode numbers are 16 bit */

typedef uint16_t sysv_ino_t;

/* Block numbers are 24 bit, sometimes stored in 32 bit.
   On Coherent FS, they are always stored in PDP-11 manner: the least
   significant 16 bits come last.
*/

/* typedef uint32_t sysv_zone_t; */

/* Among the blocks ... */
/* Xenix FS, Coherent FS: block 0 is the boot block, block 1 the super-block.
   SystemV FS: block 0 contains both the boot sector and the super-block. */
/* The first inode zone is sb->sv_firstinodezone (1 or 2). */

/* Among the inodes ... */
/* 0 is non-existent */
#define SYSV_BADBL_INO	1	/* inode of bad blocks file */
#define SYSV_ROOT_INO	2	/* inode of root directory */


/* Xenix super-block data on disk */
#define XENIX_NICINOD	100	/* number of inode cache entries */
#define XENIX_NICFREE	100	/* number of free block list chunk entries */
struct xenix_super_block {
	uint16_t		s_isize; /* index of first data zone */
	uint32_t		s_fsize __packed2__; /* total number of zones of this fs */
	/* the start of the free block list: */
	uint16_t		s_nfree;	/* number of free blocks in s_free, <= XENIX_NICFREE */
	uint32_t		s_free[XENIX_NICFREE]; /* first free block list chunk */
	/* the cache of free inodes: */
	uint16_t		s_ninode; /* number of free inodes in s_inode, <= XENIX_NICINOD */
	sysv_ino_t	s_inode[XENIX_NICINOD]; /* some free inodes */
	/* locks, not used by Linux: */
	char		s_flock;	/* lock during free block list manipulation */
	char		s_ilock;	/* lock during inode cache manipulation */
	char		s_fmod;		/* super-block modified flag */
	char		s_ronly;	/* flag whether fs is mounted read-only */
	uint32_t		s_time __packed2__; /* time of last super block update */
	uint32_t		s_tfree __packed2__; /* total number of free zones */
	uint16_t		s_tinode;	/* total number of free inodes */
	int16_t		s_dinfo[4];	/* device information ?? */
	char		s_fname[6];	/* file system volume name */
	char		s_fpack[6];	/* file system pack name */
	char		s_clean;	/* set to 0x46 when filesystem is properly unmounted */
	char		s_fill[371];
	int32_t		s_magic;	/* version of file system */
	int32_t		s_type;		/* type of file system: 1 for 512 byte blocks
								2 for 1024 byte blocks
								3 for 2048 byte blocks */
};

/* SystemV FS comes in two variants:
 * sysv2: System V Release 2 (e.g. Microport), structure elements aligned(2).
 * sysv4: System V Release 4 (e.g. Consensys), structure elements aligned(4).
 */
#define SYSV_NICINOD	100	/* number of inode cache entries */
#define SYSV_NICFREE	50	/* number of free block list chunk entries */

/* SystemV4 super-block data on disk */
struct sysv4_super_block {
	uint16_t	s_isize;		/* 0x00 index of first data zone */
	uint16_t	s_pad0;			/* 0x02 */
	uint32_t	s_fsize;		/* 0x04 total number of zones of this fs */
						/* the start of the free block list: */
	uint16_t	s_nfree;		/* 0x08 number of free blocks in s_free, <= SYSV_NICFREE */
	uint16_t	s_pad1;			/* 0x0a */
	uint32_t	s_free[SYSV_NICFREE]; 	/* 0x0c first free block list chunk */
						/* the cache of free inodes: */
	uint16_t	s_ninode;		/* 0xd4 number of free inodes in s_inode, <= SYSV_NICINOD */
	uint16_t	s_pad2;			/* 0xd6 */
	sysv_ino_t     s_inode[SYSV_NICINOD]; 	/* 0xd8 some free inodes */
	char	s_flock;			/* 0x1a0 lock during free block list manipulation */
	char	s_ilock;			/* 0x1a1 lock during inode cache manipulation */
	char	s_fmod;				/* 0x1a2 super-block modified flag */
	char	s_ronly;			/* 0x1a3 flag whether fs is mounted read-only */
	uint32_t	s_time;			/* 0x1a4 time of last super block update */
	int16_t	s_dinfo[4];			/* 0x1a8 device information ?? */
	uint32_t	s_tfree;		/* 0x1b0 total number of free zones */
	uint16_t	s_tinode;		/* 0x1b4 total number of free inodes */
	char	s_fname[6];			/* 0x1b6 file system volume name */
	char	s_fpack[6];			/* 0x1bc file system pack name */
	uint16_t	s_pad3;			/* 0x1c2 */
	int32_t	s_fill[12];			/* 0x1c4 */
	int32_t	s_state;			/* 0x1f4 file system state: 0x7c269d38-s_time means clean */
	int32_t	s_magic;			/* 0x1f8 version of file system */
	int32_t	s_type;		/* 0x1fc type of file system: 1 for 512 byte blocks
								2 for 1024 byte blocks */
} __attribute__ ((__packed__));

/* SystemV2 super-block data on disk */
struct sysv2_super_block {
	uint16_t	s_isize; 		/* 0x00 index of first data zone */
	uint32_t	s_fsize __packed2__;	/* 0x02 total number of zones of this fs */
	/* the start of the free block list: */
	uint16_t	s_nfree;		/* number of free blocks in s_free, <= SYSV_NICFREE */
	uint32_t	s_free[SYSV_NICFREE];	/* first free block list chunk */
	/* the cache of free inodes: */
	uint16_t	s_ninode;		/* number of free inodes in s_inode, <= SYSV_NICINOD */
	sysv_ino_t     s_inode[SYSV_NICINOD]; /* some free inodes */
	/* locks, not used by Linux: */
	char	s_flock;		/* lock during free block list manipulation */
	char	s_ilock;		/* lock during inode cache manipulation */
	char	s_fmod;			/* super-block modified flag */
	char	s_ronly;		/* flag whether fs is mounted read-only */
	uint32_t	s_time __packed2__;	/* time of last super block update */
	int16_t	s_dinfo[4];		/* device information ?? */
	uint32_t	s_tfree __packed2__;	/* total number of free zones */
	uint16_t	s_tinode;		/* total number of free inodes */
	char	s_fname[6];		/* file system volume name */
	char	s_fpack[6];		/* file system pack name */
	int32_t	s_fill[14];
	int32_t	s_state;		/* file system state: 0xcb096f43 means clean */
	int32_t	s_magic;		/* version of file system */
	int32_t	s_type;			/* type of file system: 1 for 512 byte blocks
								2 for 1024 byte blocks */
};

/* V7 super-block data on disk */
#define V7_NICINOD     100     /* number of inode cache entries */
#define V7_NICFREE     50      /* number of free block list chunk entries */
struct v7_super_block {
	uint16_t    s_isize;        /* index of first data zone */
	uint32_t    s_fsize __packed2__; /* total number of zones of this fs */
	/* the start of the free block list: */
	uint16_t    s_nfree;        /* number of free blocks in s_free, <= V7_NICFREE */
	uint32_t    s_free[V7_NICFREE]; /* first free block list chunk */
	/* the cache of free inodes: */
	uint16_t    s_ninode;       /* number of free inodes in s_inode, <= V7_NICINOD */
	sysv_ino_t      s_inode[V7_NICINOD]; /* some free inodes */
	/* locks, not used by Linux or V7: */
	char    s_flock;        /* lock during free block list manipulation */
	char    s_ilock;        /* lock during inode cache manipulation */
	char    s_fmod;         /* super-block modified flag */
	char    s_ronly;        /* flag whether fs is mounted read-only */
	uint32_t     s_time __packed2__; /* time of last super block update */
	/* the following fields are not maintained by V7: */
	uint32_t     s_tfree __packed2__; /* total number of free zones */
	uint16_t     s_tinode;       /* total number of free inodes */
	uint16_t     s_m;            /* interleave factor */
	uint16_t     s_n;            /* interleave factor */
	char    s_fname[6];     /* file system name */
	char    s_fpack[6];     /* file system pack name */
};

/* Coherent super-block data on disk */
#define COH_NICINOD	100	/* number of inode cache entries */
#define COH_NICFREE	64	/* number of free block list chunk entries */
struct coh_super_block {
	uint16_t		s_isize;	/* index of first data zone */
	uint32_t		s_fsize __packed2__; /* total number of zones of this fs */
	/* the start of the free block list: */
	uint16_t s_nfree;	/* number of free blocks in s_free, <= COH_NICFREE */
	uint32_t		s_free[COH_NICFREE] __packed2__; /* first free block list chunk */
	/* the cache of free inodes: */
	uint16_t		s_ninode;	/* number of free inodes in s_inode, <= COH_NICINOD */
	sysv_ino_t	s_inode[COH_NICINOD]; /* some free inodes */
	/* locks, not used by Linux: */
	char		s_flock;	/* lock during free block list manipulation */
	char		s_ilock;	/* lock during inode cache manipulation */
	char		s_fmod;		/* super-block modified flag */
	char		s_ronly;	/* flag whether fs is mounted read-only */
	uint32_t		s_time __packed2__; /* time of last super block update */
	uint32_t		s_tfree __packed2__; /* total number of free zones */
	uint16_t		s_tinode;	/* total number of free inodes */
	uint16_t		s_interleave_m;	/* interleave factor */
	uint16_t		s_interleave_n;
	char		s_fname[6];	/* file system volume name */
	char		s_fpack[6];	/* file system pack name */
	uint32_t		s_unique;	/* zero, not used */
};

int check_sysv(disk_t *disk_car,partition_t *partition,const int verbose);
int recover_sysv(disk_t *disk_car, const struct sysv4_super_block *sbd, partition_t *partition,const int verbose, const int dump_ind);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
