/*

    File: fat_common.h

    Copyright (C) 2013 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifndef _FAT_COMMON_H
#define _FAT_COMMON_H
#ifdef __cplusplus
extern "C" {
#endif

#define FAT1X_PART_NAME 0x2B
#define FAT32_PART_NAME 0x47
#define FAT_NAME1       0x36
#define FAT_NAME2       0x52    /* FAT32 only */

#define DELETED_FLAG 0xe5 /* marks file as deleted when in name[0] */
#define IS_FREE(n) (!*(n) || *(const unsigned char *) (n) == DELETED_FLAG)
#define ATTR_RO      1  /* read-only */
#define ATTR_HIDDEN  2  /* hidden */
#define ATTR_SYS     4  /* system */
#define ATTR_VOLUME  8  /* volume label */
#define ATTR_DIR     16 /* directory */
#define ATTR_ARCH    32 /* archived */

#define ATTR_NONE    0 /* no attribute bits */
#define ATTR_UNUSED  (ATTR_VOLUME | ATTR_ARCH | ATTR_SYS | ATTR_HIDDEN)
	/* attribute bits that are copied "as is" */
#define ATTR_EXT     (ATTR_RO | ATTR_HIDDEN | ATTR_SYS | ATTR_VOLUME)
#define ATTR_EXT_MASK     (ATTR_RO | ATTR_HIDDEN | ATTR_SYS | ATTR_VOLUME | ATTR_DIR | ATTR_ARCH)
	/* bits that are used by the Windows 95/Windows NT extended FAT */
#define FAT12_BAD	0x0FF7
#define FAT12_EOC	0x0FF8
#define FAT16_BAD	0xFFF7
#define FAT16_EOC	0xFFF8
#define FAT32_BAD	0x0FFFFFF7
#define FAT32_EOC	0x0FFFFFF8
#define FAT1x_BOOT_SECTOR_SIZE 0x200

/*
 * FAT partition boot sector information, taken from the Linux
 * kernel sources.
 */

struct fat_boot_sector {
	uint8_t	ignored[3];	/* 0x00 Boot strap short or near jump */
	int8_t	system_id[8];	/* 0x03 Name - can be used to special case
				   partition manager volumes */
	uint8_t	sector_size[2];	/* 0x0B bytes per logical sector */
	uint8_t	sectors_per_cluster;	/* 0x0D sectors/cluster */
	uint16_t	reserved;	/* 0x0E reserved sectors */
	uint8_t	fats;		/* 0x10 number of FATs */
	uint8_t	dir_entries[2];	/* 0x11 root directory entries */
	uint8_t	sectors[2];	/* 0x13 number of sectors */
	uint8_t	media;		/* 0x15 media code (unused) */
	uint16_t	fat_length;	/* 0x16 sectors/FAT */
	uint16_t	secs_track;	/* 0x18 sectors per track */
	uint16_t	heads;		/* 0x1A number of heads */
	uint32_t	hidden;		/* 0x1C hidden sectors (unused) */
	uint32_t	total_sect;	/* 0x20 number of sectors (if sectors == 0) */

	/* The following fields are only used by FAT32 */
	uint32_t	fat32_length;	/* 0x24=36 sectors/FAT */
	uint16_t	flags;		/* 0x28 bit 8: fat mirroring, low 4: active fat */
	uint8_t	version[2];	/* 0x2A major, minor filesystem version */
	uint32_t	root_cluster;	/* 0x2C first cluster in root directory */
	uint16_t	info_sector;	/* 0x30 filesystem info sector */
	uint16_t	backup_boot;	/* 0x32 backup boot sector */
	uint8_t	BPB_Reserved[12];	/* 0x34 Unused */
	uint8_t	BS_DrvNum;		/* 0x40 */
	uint8_t	BS_Reserved1;		/* 0x41 */
	uint8_t	BS_BootSig;		/* 0x42 */
	uint8_t	BS_VolID[4];		/* 0x43 */
	uint8_t	BS_VolLab[11];		/* 0x47 */
	uint8_t	BS_FilSysType[8];	/* 0x52=82*/

	/* */
	uint8_t	nothing[420];	/* 0x5A */
	uint16_t	marker;
} __attribute__ ((gcc_struct, __packed__));

struct fat_fsinfo {
  uint32_t leadsig;		/* 0x41615252 */
  uint8_t reserved1[480];
  uint32_t strucsig;		/* 0x61417272 */
  uint32_t freecnt;     	/* free clusters 0xfffffffff if unknown */
  uint32_t nextfree;		/* next free cluster */
  uint8_t reserved3[12];
  uint32_t magic3;		/* 0xAA550000 */
} __attribute__ ((gcc_struct, __packed__));

struct msdos_dir_entry {
	uint8_t	name[8];		/* 00 name and extension */
	uint8_t  ext[3];
	uint8_t	attr;			/* 0B attribute bits */
	uint8_t    lcase;		/* 0C Case for base and extension */
	uint8_t	        ctime_ms;	/* 0D Creation time, milliseconds */
	uint16_t	ctime;		/* 0E Creation time */
	uint16_t	cdate;		/* 10 Creation date */
	uint16_t	adate;		/* 12 Last access date */
	uint16_t        starthi;	/* 14 High 16 bits of cluster in FAT32 */
	uint16_t	time;           /* 16 time, date and first cluster */
        uint16_t        date;		/* 18 */
        uint16_t        start;		/* 1A */
	uint32_t	size;		/* 1C file size (in bytes) */
} __attribute__ ((gcc_struct, __packed__));

/* Up to 13 characters of the name */
struct msdos_dir_slot {
	uint8_t    id;			/* 00 sequence number for slot */
	uint8_t    name0_4[10];		/* 01 first 5 characters in name */
	uint8_t    attr;		/* 0B attribute byte */
	uint8_t    reserved;		/* 0C always 0 */
	uint8_t    alias_checksum;	/* 0D checksum for 8.3 alias */
	uint8_t    name5_10[12];	/* 0E 6 more characters in name */
	uint16_t   start;		/* 1A starting cluster number, 0 in long slots */
	uint8_t    name11_12[4];	/* 1C last 2 characters in name */
};


/*@
  @ requires \valid_read(entry);
  @ requires \initialized(entry);
  @ terminates \true;
  @ assigns \nothing;
  @ */
unsigned int fat_get_cluster_from_entry(const struct msdos_dir_entry *entry);

/*@
  @ requires \valid_read(buffer + (0 .. 0x40-1));
  @ assigns \nothing;
  @ */
int is_fat_directory(const unsigned char *buffer);

/*@
  @ requires \valid_read(fat_header);
  @ requires \initialized(fat_header);
  @ terminates \true;
  @ ensures \result <= 65535;
  @ assigns \nothing;
  @ */
unsigned int get_dir_entries(const struct fat_boot_sector *fat_header);

/*@
  @ requires \valid_read(fat_header);
  @ requires \initialized(fat_header);
  @ terminates \true;
  @ ensures \result <= 65535;
  @ assigns \nothing;
  @ */
unsigned int fat_sector_size(const struct fat_boot_sector *fat_header);

/*@
  @ requires \valid_read(fat_header);
  @ requires \initialized(fat_header);
  @ terminates \true;
  @ ensures \result <= 65535;
  @ assigns \nothing;
  @ */
unsigned int fat_sectors(const struct fat_boot_sector *fat_header);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
