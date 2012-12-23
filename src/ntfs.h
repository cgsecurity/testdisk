/*

    File: ntfs.h

    Copyright (C) 1998-2006,2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#define NTFS_BOOT_SECTOR_SIZE 0x200

struct ntfs_boot_sector {
	uint8_t	ignored[3];	/* 0x00 Boot strap short or near jump */
	int8_t	system_id[8];	/* 0x03 Name : NTFS */
	uint8_t	sector_size[2];	/* 0x0B bytes per logical sector */
	uint8_t	sectors_per_cluster;	/* 0x0D sectors/cluster */
	uint16_t	reserved;	/* 0x0E reserved sectors = 0 */
	uint8_t	fats;		/* 0x10 number of FATs = 0 */
	uint8_t	dir_entries[2];	/* 0x11 root directory entries = 0 */
	uint8_t	sectors[2];	/* 0x13 number of sectors = 0 */
	uint8_t	media;		/* 0x15 media code (unused) */
	uint16_t	fat_length;	/* 0x16 sectors/FAT = 0 */
	uint16_t	secs_track;	/* 0x18 sectors per track */
	uint16_t	heads;		/* 0x1A number of heads */
	uint32_t	hidden;		/* 0x1C hidden sectors (unused) */
	uint32_t	total_sect;	/* 0x20 number of sectors = 0 */
	uint8_t	physical_drive;	/* 0x24 physical drive number  */
	uint8_t	unused;		/* 0x25 */
	uint16_t	reserved2;	/* 0x26 usually 0x80 */
	uint64_t	sectors_nbr;	/* 0x28 total sectors nbr */
	uint64_t	mft_lcn;	/* 0x30 Cluster location of mft data.*/
	uint64_t	mftmirr_lcn;	/* 0x38 Cluster location of copy of mft.*/
	int8_t   clusters_per_mft_record;		/* 0x40 */
	uint8_t  	reserved0[3];               	/* zero */
	int8_t	clusters_per_index_record;	/* 0x44 clusters per index block */
	uint8_t  	reserved1[3];               	/* zero */
	uint64_t 	volume_serial_number;       	/* 0x48 Irrelevant (serial number). */
	uint32_t 	checksum;                   	/* 0x50 Boot sector checksum. */
	uint8_t  	bootstrap[426];             	/* 0x54 Irrelevant (boot up code). */
	uint16_t	marker;				/* 0x1FE */
	} __attribute__ ((__packed__));

struct ntfs_mft_record {
  uint32_t	magic;		/* FILE */
  uint16_t	usa_ofs;
  uint16_t	usa_count;
  uint64_t	lsn;
  uint16_t	sequence_number;
  uint16_t	link_count;
  uint16_t	attrs_offset;	/* Must be aligned to 8-byte boundary */
  uint16_t	flags;
  uint32_t	bytes_in_use;	/* Must be aligned to 8-byte boundary */
  uint32_t	bytes_allocated;
  uint64_t	base_mft_record;
  uint16_t	next_attr_instance;
  uint16_t	reserved;		/* NTFS 3.1+ */
  uint32_t	mft_record_number;	/* NTFS 3.1+ */
} __attribute__ ((__packed__));

int check_NTFS(disk_t *disk_car,partition_t *partition,const int verbose,const int dump_ind);
int log_ntfs2_info(const struct ntfs_boot_sector *nh1, const struct ntfs_boot_sector *nh2);
int log_ntfs_info(const struct ntfs_boot_sector *ntfs_header);
int is_ntfs(const partition_t *partition);
int is_part_ntfs(const partition_t *partition);
int ntfs_get_attr(const char *mft_record, const int my_type, partition_t *partition, const char *end, const int verbose, const char*file_name_to_find);
int recover_NTFS(disk_t *disk_car, const struct ntfs_boot_sector*ntfs_header,partition_t *partition,const int verbose, const int dump_ind, const int backup);
int test_NTFS(const disk_t *disk_car,const struct ntfs_boot_sector*ntfs_header, partition_t *partition,const int verbose, const int dump_ind);
#define NTFS_GETU8(p)      (*(const uint8_t*)(p))
#define NTFS_GETU16(p)     (le16(*(const uint16_t*)(p)))
#define NTFS_GETU32(p)     (le32(*(const uint32_t*)(p)))
#define NTFS_GETU64(p)     (le64(*(const uint64_t*)(p)))
unsigned int ntfs_sector_size(const struct ntfs_boot_sector *ntfs_header);
int rebuild_NTFS_BS(disk_t *disk_car,partition_t *partition, const int verbose, const int interface, const unsigned int expert, char**current_cmd);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
