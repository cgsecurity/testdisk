/*

    File: bsd.h

    Copyright (C) 1998-2004,2006,2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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
/* Come mainly from sys/disklabel.h and disktab.h */

#ifndef _BSD_H
#define _BSD_H
#ifdef __cplusplus
extern "C" {
#endif
/* BSD_DISKLABEL_SIZE is 276 */
#define BSD_DISKLABEL_SIZE 512
#define STANDALONE

#define BBSIZE		8192	/* size of boot area, with label */

#ifdef __i386__
#define LABELSECTOR	1			/* sector containing label */
#define LABELOFFSET	0			/* offset of label in sector */
#endif

#ifndef	LABELSECTOR
#define LABELSECTOR	0			/* sector containing label */
#endif

#ifndef	LABELOFFSET
#define LABELOFFSET	64			/* offset of label in sector */
#endif

#define DISKMAGIC	((uint32_t)0x82564557)	/* The disk magic number */

#define	LABEL_PART	2		/* partition containing label */
#define	RAW_PART	2		/* partition containing whole disk */
#define	SWAP_PART	1		/* partition normally containing swap */

struct disklabel {
	uint32_t d_magic;		/* the magic number */
	uint16_t d_type;		/* drive type */
	uint16_t d_subtype;		/* controller/d_type specific */
	char	  d_typename[16];	/* type name, e.g. "eagle" */

	/* 
	 * d_packname contains the pack identifier and is returned when
	 * the disklabel is read off the disk or in-core copy.
	 * d_boot0 and d_boot1 are the (optional) names of the
	 * primary (block 0) and secondary (block 1-15) bootstraps
	 * as found in /usr/mdec.  These are returned when using
	 * getdiskbyname(3) to retrieve the values from /etc/disktab.
	 */
#if defined(KERNEL) || defined(STANDALONE)
	char	  d_packname[16];		/* pack identifier */ 
#else
	union {
		char	un_d_packname[16];	/* pack identifier */
		struct {
			char *un_d_boot0;	/* primary bootstrap name */
			char *un_d_boot1;	/* secondary bootstrap name */
		} un_b;
	} d_un;
#define d_packname	d_un.un_d_packname
#define d_boot0		d_un.un_b.un_d_boot0
#define d_boot1		d_un.un_b.un_d_boot1
#endif	/* ! KERNEL or STANDALONE */

			/* disk geometry: */
	uint32_t d_secsize;		/* # of bytes per sector */
	uint32_t d_nsectors;		/* # of data sectors per track */
	uint32_t d_ntracks;		/* # of tracks per cylinder */
	uint32_t d_ncylinders;		/* # of data cylinders per unit */
	uint32_t d_secpercyl;		/* # of data sectors per cylinder */
	uint32_t d_secperunit;		/* # of data sectors per unit */

	/*
	 * Spares (bad sector replacements) below are not counted in
	 * d_nsectors or d_secpercyl.  Spare sectors are assumed to
	 * be physical sectors which occupy space at the end of each
	 * track and/or cylinder.
	 */
	uint16_t d_sparespertrack;	/* # of spare sectors per track */
	uint16_t d_sparespercyl;	/* # of spare sectors per cylinder */
	/*
	 * Alternate cylinders include maintenance, replacement, configuration
	 * description areas, etc.
	 */
	uint32_t d_acylinders;		/* # of alt. cylinders per unit */

			/* hardware characteristics: */
	/*
	 * d_interleave, d_trackskew and d_cylskew describe perturbations
	 * in the media format used to compensate for a slow controller.
	 * Interleave is physical sector interleave, set up by the
	 * formatter or controller when formatting.  When interleaving is
	 * in use, logically adjacent sectors are not physically
	 * contiguous, but instead are separated by some number of
	 * sectors.  It is specified as the ratio of physical sectors
	 * traversed per logical sector.  Thus an interleave of 1:1
	 * implies contiguous layout, while 2:1 implies that logical
	 * sector 0 is separated by one sector from logical sector 1.
	 * d_trackskew is the offset of sector 0 on track N relative to
	 * sector 0 on track N-1 on the same cylinder.  Finally, d_cylskew
	 * is the offset of sector 0 on cylinder N relative to sector 0
	 * on cylinder N-1.
	 */
	uint16_t d_rpm;		/* rotational speed */
	uint16_t d_interleave;		/* hardware sector interleave */
	uint16_t d_trackskew;		/* sector 0 skew, per track */
	uint16_t d_cylskew;		/* sector 0 skew, per cylinder */
	uint32_t d_headswitch;		/* head switch time, usec */
	uint32_t d_trkseek;		/* track-to-track seek, usec */
	uint32_t d_flags;		/* generic flags */
#define NDDATA 5
	uint32_t d_drivedata[NDDATA];	/* drive-type specific information */
#define NSPARE 5
	uint32_t d_spare[NSPARE];	/* reserved for future use */
	uint32_t d_magic2;		/* the magic number (again) */
	uint16_t d_checksum;		/* xor of data incl. partitions */

			/* filesystem and partition information: */
	uint16_t d_npartitions;	/* number of partitions in following */
	uint32_t d_bbsize;		/* size of boot area at sn0, bytes */
	uint32_t d_sbsize;		/* max size of fs superblock, bytes */
	struct	partition {		/* the partition table */
		uint32_t p_size;	/* number of sectors in partition */
		uint32_t p_offset;	/* starting sector */
		uint32_t p_fsize;	/* filesystem basic fragment size */
		uint8_t p_fstype;	/* filesystem type, see below */
		uint8_t p_frag;	/* filesystem fragments per block */
		union {
			uint16_t cpg;	/* UFS: FS cylinders per group */
			uint16_t sgs;	/* LFS: FS segment shift */
		} __partition_u1;
#define	p_cpg	__partition_u1.cpg
#define	p_sgs	__partition_u1.sgs
	} d_partitions[BSD_MAXPARTITIONS];	/* actually may be more */
};
#define TST_FS_UNUSED       0               /* unused */
#define TST_FS_SWAP         1               /* swap */
#define TST_FS_V6           2               /* Sixth Edition */
#define TST_FS_V7           3               /* Seventh Edition */
#define TST_FS_SYSV         4               /* System V */
#define TST_FS_V71K         5               /* V7 with 1K blocks (4.1, 2.9) */
#define TST_FS_V8           6               /* Eighth Edition, 4K blocks */
#define TST_FS_BSDFFS       7               /* 4.2BSD fast filesystem */
#define TST_FS_MSDOS        8               /* MSDOS filesystem */
#define TST_FS_BSDLFS       9               /* 4.4BSD log-structured filesystem */
#define TST_FS_OTHER        10              /* in use, but unknown/unsupported */
#define TST_FS_HPFS         11              /* OS/2 high-performance filesystem */
#define TST_FS_ISO9660      12              /* ISO 9660, normally CD-ROM */
#define TST_FS_BOOT         13              /* partition contains bootstrap */
#define TST_FS_VINUM        14              /* Vinum drive */
#define TST_FS_RAID         15              /* RAIDFrame drive */
#define TST_FS_JFS2         21              /* IBM JFS2 */
int check_BSD(disk_t *disk_car,partition_t *partition,const int verbose,const unsigned int max_partitions);
int recover_BSD(disk_t *disk_car, const struct disklabel*bsd_header,partition_t *partition,const int verbose, const int dump_ind);
#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
