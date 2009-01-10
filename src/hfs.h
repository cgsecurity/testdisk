/*
    File: hfs.h, TestDisk

    Copyright (C) 2005 Christophe GRENIER <grenier@cgsecurity.org>

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
#ifndef _HFS_H
#define _HFS_H
#ifdef __cplusplus
extern "C" {
#endif

/* HFS superblock size is 162 */
#define HFS_SUPERBLOCK_SIZE 512
#define HFS_SUPER_MAGIC           0x4244 /* "BD": HFS MDB (super block) */

struct hfs_extent {
  uint16_t block;
  uint16_t count;
} __attribute__ ((__packed__));
typedef struct hfs_extent hfs_extent_rec[3];

typedef struct hfs_mdb hfs_mdb_t;
struct hfs_mdb {
  uint16_t drSigWord;                  /* 0x00 Signature word indicating fs type */
  uint32_t drCrDate;                   /* 0x02 fs creation date/time */
  uint32_t drLsMod;                    /* 0x06 fs modification date/time */
  uint16_t drAtrb;                     /* 0x0A fs attributes */
  uint16_t drNmFls;                    /* 0x0C number of files in root directory */
  uint16_t drVBMSt;                    /* 0x0E location (in 512-byte blocks)
					  of the volume bitmap */
  uint16_t drAllocPtr;                 /* 0x10 location (in allocation blocks)
					  to begin next allocation search */
  uint16_t drNmAlBlks;                 /* 0x12 number of allocation blocks */
  uint32_t drAlBlkSiz;                 /* 0x14 bytes in an allocation block */
  uint32_t drClpSiz;                   /* 0x18 clumpsize, the number of bytes to
					  allocate when extending a file */
  uint16_t drAlBlSt;                   /* 0x1C location (in 512-byte blocks)
					  of the first allocation block */
  uint32_t drNxtCNID;                  /* 0x1E CNID to assign to the next
					  file or directory created */
  uint16_t drFreeBks;                  /* 0x22 number of free allocation blocks */
  uint8_t  drVN[28];                   /* 0x24 the volume label */
  uint32_t drVolBkUp;                  /* 0x40 fs backup date/time */
  uint16_t drVSeqNum;                  /* 0x44 backup sequence number */
  uint32_t drWrCnt;                    /* 0x46 fs write count */
  uint32_t drXTClpSiz;                 /* 0x4a clumpsize for the extents B-tree */
  uint32_t drCTClpSiz;                 /* 0x4e clumpsize for the catalog B-tree */
  uint16_t drNmRtDirs;                 /* 0x52 number of directories in
					  the root directory */
  uint32_t drFilCnt;                   /* 0x54 number of files in the fs */
  uint32_t drDirCnt;                   /* 0x58 number of directories in the fs */
  uint8_t  drFndrInfo[32];             /* 0x5c data used by the Finder */
  uint16_t drEmbedSigWord;             /* 0x7c embedded volume signature */
  uint32_t drEmbedExtent;              /* 0x7e starting block number (xdrStABN)
					  and number of allocation blocks
					  (xdrNumABlks) occupied by embedded
					  volume */
  uint32_t drXTFlSize;                 /* 0x82 bytes in the extents B-tree */
  hfs_extent_rec drXTExtRec;           /* 0x86 extents B-tree's first 3 extents */
  uint32_t drCTFlSize;                 /* 0x92 bytes in the catalog B-tree */
  hfs_extent_rec drCTExtRec;           /* 0x96 catalog B-tree's first 3 extents */
} __attribute__ ((__packed__));
int check_HFS(disk_t *disk_car,partition_t *partition,const int verbose);
int test_HFS(disk_t *disk_car, const hfs_mdb_t *hfs_mdb,partition_t *partition,const int verbose, const int dump_ind);
int recover_HFS(disk_t *disk_car, const hfs_mdb_t *hfs_mdb,partition_t *partition,const int verbose, const int dump_ind, const int backup);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif /* _HFS_H */
