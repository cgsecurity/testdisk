/*

    File: file_dump.c

    Copyright (C) 2007 Christophe GRENIER <grenier@cgsecurity.org>
  
    This software is free software; you can redistribute it and/or modify
    it under the tedumps of the GNU General Public License as published by
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "common.h"
#include "filegen.h"
#define TS_TAPE         1       /* dump tape header */

static void register_header_check_dump(file_stat_t *file_stat);

const file_hint_t file_hint_dump= {
  .extension="dump",
  .description="Dump/Restore archive",
  .min_header_distance=0,
  .max_filesize=(((uint64_t)1<<33)-1),
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_dump
};

/*
 * TP_BSIZE is the size of file blocks on the dump tapes.
 * Note that TP_BSIZE must be a multiple of DEV_BSIZE.
 *
 * NTREC is the number of TP_BSIZE blocks that are written
 * in each tape record. HIGHDENSITYTREC is the number of
 * TP_BSIZE blocks that are written in each tape record on
 * 6250 BPI or higher density tapes.
 *
 * TP_NINDIR is the number of indirect pointers in a TS_INODE
 * or TS_ADDR record. Note that it must be a power of two.
 */
#define TP_BSIZE	1024
#define NTREC   	10
#define HIGHDENSITYTREC	32
#define TP_NINDIR	(TP_BSIZE/2)
#define LBLSIZE		16
#define NAMELEN		64

struct	dump_struct
{
  int32_t	c_type;		    /* record type (see below) */
  int32_t	c_old_date;	    /* date of this dump */
  int32_t	c_old_ddate;	    /* date of previous dump */
  int32_t	c_volume;	    /* dump volume number */
  int32_t	c_old_tapea;	    /* logical block of this record */
  uint32_t	c_inumber;	    /* number of inode */
  int32_t	c_magic;	    /* magic number (see above) */
  int32_t	c_checksum;	    /* record checksum */
  /*
   * Start old dinode structure, expanded for binary
   * compatibility with UFS1.
   */
  uint16_t 	c_mode;	    /* file mode */
  int16_t	c_spare1[3];	    /* old nlink, ids */
  uint64_t 	c_size;	    /* file byte count */
  int32_t	c_old_atime;	    /* old last access time, seconds */
  int32_t	c_atimensec;	    /* last access time, nanoseconds */
  int32_t	c_old_mtime;	    /* old last modified time, secs */
  int32_t	c_mtimensec;	    /* last modified time, nanosecs */
  int32_t	c_spare2[2];	    /* old ctime */
  int32_t	c_rdev;		    /* for devices, device number */
  int32_t	c_birthtimensec;    /* creation time, nanosecs */
  int64_t	c_birthtime;	    /* creation time, seconds */
  int64_t	c_atime;	    /* last access time, seconds */
  int64_t	c_mtime;	    /* last modified time, seconds */
  int32_t	c_spare4[7];	    /* old block pointers */
  uint32_t 	c_file_flags;	    /* status flags (chflags) */
  int32_t	c_spare5[2];	    /* old blocks, generation number */
  uint32_t 	c_uid;	    /* file owner */
  uint32_t 	c_gid;	    /* file group */
  int32_t	c_spare6[2];	    /* previously unused spares */
  /*
   * End old dinode structure.
   */
  int32_t	c_count;	    /* number of valid c_addr entries */
  char	c_addr[TP_NINDIR];  /* 1 => data; 0 => hole in inode */
  char	c_label[LBLSIZE];   /* dump label */
  int32_t	c_level;	    /* level of this dump */
  char	c_filesys[NAMELEN]; /* name of dumpped file system */
  char	c_dev[NAMELEN];	    /* name of dumpped device */
  char	c_host[NAMELEN];    /* name of dumpped host */
  int32_t	c_flags;	    /* additional information */
  int32_t	c_old_firstrec;	    /* first record on volume */
  int64_t	c_date;		    /* date of this dump */
  int64_t	c_ddate;	    /* date of previous dump */
  int64_t	c_tapea;	    /* logical block of this record */
  int64_t	c_firstrec;	    /* first record on volume */
  int32_t	c_spare[24];	    /* reserved for future uses */
};
/*
 * special record types
 */
#define TS_TAPE 	1	/* dump tape header */
#define TS_INODE	2	/* beginning of file record */
#define TS_ADDR 	4	/* continuation of file record */
#define TS_BITS 	3	/* map of inodes on tape */
#define TS_CLRI 	6	/* map of inodes deleted since last dump */
#define TS_END  	5	/* end of volume marker */

static int header_check_dump(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct dump_struct *dump=(const struct dump_struct*)buffer;
  if(le32(dump->c_type)!=TS_TAPE)
    return 0;
  reset_file_recovery(file_recovery_new);
#ifdef DJGPP
  file_recovery_new->extension="dmp";
#else
  file_recovery_new->extension=file_hint_dump.extension;
#endif
  file_recovery_new->time=le32(dump->c_old_date);
  return 1;
}

static void register_header_check_dump(file_stat_t *file_stat)
{
  static const unsigned char dump_header_le_old_fs[4]  = { 0x6b, 0xea, 0x00, 0x00};
  static const unsigned char dump_header_le_new_fs[4]  = { 0x6c, 0xea, 0x00, 0x00};
  register_header_check(0x18, dump_header_le_old_fs,sizeof(dump_header_le_old_fs), &header_check_dump, file_stat);
  register_header_check(0x18, dump_header_le_new_fs,sizeof(dump_header_le_new_fs), &header_check_dump, file_stat);
}
