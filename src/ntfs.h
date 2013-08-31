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

#define NTFS_Magic 0x454c4946     /* FILE */

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

typedef struct ntfs_mft_record ntfs_recordheader;

typedef struct _ntfs_attribheader
{
  uint32_t type;		/* Attribute Type (e.g. 0x10, 0x60) */
  uint32_t cbAttribute;         /* Length (including this header) */
  uint8_t  bNonResident;        /* Non-resident flag */
  uint8_t  cName;               /* Name length */
  uint16_t offName;             /* Offset to the Attribute */
  uint16_t flags;               /* Flags */
  uint16_t idAttribute;         /* Attribute Id (a) */
}
ntfs_attribheader;

typedef struct _ntfs_attribresident
{
  ntfs_attribheader header;
  uint32_t cbAttribData;    	/* Length of the Attribute */
  uint16_t offAttribData;   	/* Offset to the Attribute */
  uint8_t  bIndexed;            /* Indexed flag */
  uint8_t  padding;             /* 0x00 Padding */
}
ntfs_attribresident;

typedef struct _ntfs_attribnonresident
{
  ntfs_attribheader header;
  uint64_t startVCN;            /* Starting VCN */
  uint64_t lastVCN;             /* Last VCN */
  uint16_t offDataRuns;         /* Offset to the Data Runs */
  uint16_t compUnitSize;    	/* Compression Unit Size (b) */
  uint32_t padding;             /* Padding */
  uint64_t cbAllocated;         /* Allocated size of the attribute (c) */
  uint64_t cbAttribData;    	/* Real size of the attribute */
  uint64_t cbInitData;          /* Initialized data size of the stream (d) */
}
ntfs_attribnonresident;

/* The original definitions come from ntfs-3g/layout.h */
/**
 * struct INDEX_HEADER -
 *
 * This is the header for indexes, describing the INDEX_ENTRY records, which
 * follow the INDEX_HEADER. Together the index header and the index entries
 * make up a complete index.
 *
 * IMPORTANT NOTE: The offset, length and size structure members are counted
 * relative to the start of the index header structure and not relative to the
 * start of the index root or index allocation structures themselves.
 */
typedef struct {
/*  0*/ uint32_t entries_offset;/* Byte offset from the INDEX_HEADER to first
                                   INDEX_ENTRY, aligned to 8-byte boundary.  */
/*  4*/ uint32_t index_length;  /* Data size in byte of the INDEX_ENTRY's,
                                   including the INDEX_HEADER, aligned to 8. */
/*  8*/ uint32_t allocated_size;/* Allocated byte size of this index (block),
                                   multiple of 8 bytes. See more below.      */
        /* 
           For the index root attribute, the above two numbers are always
           equal, as the attribute is resident and it is resized as needed.
           
           For the index allocation attribute, the attribute is not resident 
           and the allocated_size is equal to the index_block_size specified 
           by the corresponding INDEX_ROOT attribute minus the INDEX_BLOCK 
           size not counting the INDEX_HEADER part (i.e. minus -24).
         */
/* 12*/ uint8_t ih_flags;    	/* Bit field of INDEX_HEADER_FLAGS.  */
/* 13*/ uint8_t reserved[3];    /* Reserved/align to 8-byte boundary.*/
/* sizeof() == 16 */
} __attribute__((__packed__)) TD_INDEX_HEADER;

/**
 * struct FILE_NAME_ATTR - Attribute: Filename (0x30).
 *
 * NOTE: Always resident.
 * NOTE: All fields, except the parent_directory, are only updated when the
 *	 filename is changed. Until then, they just become out of sync with
 *	 reality and the more up to date values are present in the standard
 *	 information attribute.
 * NOTE: There is conflicting information about the meaning of each of the time
 *	 fields but the meaning as defined below has been verified to be
 *	 correct by practical experimentation on Windows NT4 SP6a and is hence
 *	 assumed to be the one and only correct interpretation.
 */
typedef struct {
/*hex ofs*/
/*  0*/	uint64_t parent_directory;	/* Directory this filename is
					   referenced from. */
/*  8*/	int64_t creation_time;		/* Time file was created. */
/* 10*/	int64_t last_data_change_time;	/* Time the data attribute was last
					   modified. */
/* 18*/	int64_t last_mft_change_time;	/* Time this mft record was last
					   modified. */
/* 20*/	int64_t last_access_time;		/* Last time this mft record was
					   accessed. */
/* 28*/	int64_t allocated_size;		/* Byte size of on-disk allocated space
					   for the data attribute.  So for
					   normal $DATA, this is the
					   allocated_size from the unnamed
					   $DATA attribute and for compressed
					   and/or sparse $DATA, this is the
					   compressed_size from the unnamed
					   $DATA attribute.  NOTE: This is a
					   multiple of the cluster size. */
/* 30*/	int64_t data_size;			/* Byte size of actual data in data
					   attribute. */
/* 38*/	uint32_t file_attributes;	/* Flags describing the file. */
/* 3c*/	union {
	/* 3c*/	struct {
		/* 3c*/	uint16_t packed_ea_size;	/* Size of the buffer needed to
						   pack the extended attributes
						   (EAs), if such are present.*/
		/* 3e*/	uint16_t reserved;		/* Reserved for alignment. */
		} __attribute__((__packed__));
	/* 3c*/	uint32_t reparse_point_tag;		/* Type of reparse point,
						   present only in reparse
						   points and only if there are
						   no EAs. */
	} __attribute__((__packed__));
/* 40*/	uint8_t file_name_length;			/* Length of file name in
						   (Unicode) characters. */
/* 41*/	uint8_t file_name_type;	/* Namespace of the file name.*/
/* 42*/	char *file_name[0];			/* File name in Unicode. */
} __attribute__((__packed__)) TD_FILE_NAME_ATTR;


/**
 * struct INDEX_ROOT - Attribute: Index root (0x90).
 *
 * NOTE: Always resident.
 *
 * This is followed by a sequence of index entries (INDEX_ENTRY structures)
 * as described by the index header.
 *
 * When a directory is small enough to fit inside the index root then this
 * is the only attribute describing the directory. When the directory is too
 * large to fit in the index root, on the other hand, two additional attributes
 * are present: an index allocation attribute, containing sub-nodes of the B+
 * directory tree (see below), and a bitmap attribute, describing which virtual
 * cluster numbers (vcns) in the index allocation attribute are in use by an
 * index block.
 *
 * NOTE: The root directory (FILE_root) contains an entry for itself. Other
 * directories do not contain entries for themselves, though.
 */
typedef struct {
/*  0*/	uint32_t type;			/* Type of the indexed attribute. Is
					   $FILE_NAME for directories, zero
					   for view indexes. No other values
					   allowed. */
/*  4*/	uint32_t collation_rule;	/* Collation rule used to sort the
					   index entries. If type is $FILE_NAME,
					   this must be COLLATION_FILE_NAME. */
/*  8*/	uint32_t index_block_size;	/* Size of index block in bytes (in
					   the index allocation attribute). */
/* 12*/	int8_t clusters_per_index_block;/* Size of index block in clusters (in
					   the index allocation attribute), when
					   an index block is >= than a cluster,
					   otherwise sectors per index block. */
/* 13*/	uint8_t reserved[3];		/* Reserved/align to 8-byte boundary. */
/* 16*/	TD_INDEX_HEADER index;		/* Index header describing the
					   following index entries. */
/* sizeof()= 32 bytes */
} __attribute__((__packed__)) TD_INDEX_ROOT;


int check_NTFS(disk_t *disk_car,partition_t *partition,const int verbose,const int dump_ind);
int log_ntfs2_info(const struct ntfs_boot_sector *nh1, const struct ntfs_boot_sector *nh2);
int log_ntfs_info(const struct ntfs_boot_sector *ntfs_header);
int is_ntfs(const partition_t *partition);
int is_part_ntfs(const partition_t *partition);
int recover_NTFS(disk_t *disk_car, const struct ntfs_boot_sector*ntfs_header,partition_t *partition,const int verbose, const int dump_ind, const int backup);
int test_NTFS(const disk_t *disk_car,const struct ntfs_boot_sector*ntfs_header, partition_t *partition,const int verbose, const int dump_ind);
#define NTFS_GETU8(p)      (*(const uint8_t*)(p))
#define NTFS_GETU16(p)     (le16(*(const uint16_t*)(p)))
#define NTFS_GETU32(p)     (le32(*(const uint32_t*)(p)))
#define NTFS_GETU64(p)     (le64(*(const uint64_t*)(p)))
unsigned int ntfs_sector_size(const struct ntfs_boot_sector *ntfs_header);
int rebuild_NTFS_BS(disk_t *disk_car,partition_t *partition, const int verbose, const int interface, const unsigned int expert, char**current_cmd);
const ntfs_attribheader *ntfs_getattributeheaders(const ntfs_recordheader* record);
const ntfs_attribheader* ntfs_findattribute(const ntfs_recordheader* record, uint32_t attrType, const char* end);
const ntfs_attribheader* ntfs_nextattribute(const ntfs_attribheader* attrib, uint32_t attrType, const char* end);
const char* ntfs_getattributedata(const ntfs_attribresident* attrib, const char* end);
long int ntfs_get_first_rl_element(const ntfs_attribnonresident *attrnr, const char* end);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
