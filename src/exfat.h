/*

    file: swap.h

    Copyright (C) 2009 Christophe GRENIER <grenier@cgsecurity.org>
  
    this software is free software; you can redistribute it and/or modify
    it under the terms of the gnu general public license as published by
    the free software foundation; either version 2 of the license, or
    (at your option) any later version.
  
    this program is distributed in the hope that it will be useful,
    but without any warranty; without even the implied warranty of
    merchantability or fitness for a particular purpose.  see the
    gnu general public license for more details.
  
    You should have received a copy of the GNU General Public License along
    with this program; if not, write the Free Software Foundation, Inc., 51
    Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

 */
#ifdef __cplusplus
extern "C" {
#endif

struct exfat_super_block {
        unsigned char   jmp_boot[3];            /* boot strap short or near jump */
        unsigned char   oem_id[8];              /* oem-id */
        unsigned char   unused0;                /* 0x00... */
        uint32_t  	unused1[13];
	uint64_t  	start_sector;           /* 0x40 start sector of partition */
	uint64_t  	nr_sectors;             /* number of sectors of partition */
	uint32_t  	fat_blocknr;            /* 0x50 start blocknr of FAT */
	uint32_t  	fat_block_counts;       /* number of FAT blocks */
	uint32_t  	clus_blocknr;           /* start blocknr of cluster */
	uint32_t  	total_clusters;         /* number of total clusters */
	uint32_t  	rootdir_clusnr;         /* 0x60 start clusnr of rootdir */
	uint32_t  	serial_number;          /* volume serial number */
	unsigned char   xxxx01;                 /* ??? (0x00 or any value (?)) */
	unsigned char   xxxx02;                 /* ??? (0x01 or 0x00 (?)) */
	uint16_t  	state;                  /* state of this volume */
	unsigned char   blocksize_bits;         /* bits of block size */
	unsigned char   block_per_clus_bits;    /* bits of blocks per cluster */
	unsigned char   xxxx03;                 /* ??? (0x01 or 0x00 (?)) */
	unsigned char   xxxx04;                 /* ??? (0x80 or any value (?)) */
	unsigned char   allocated_percent;      /* 0x70 percentage of allocated space (?) */
	unsigned char   xxxx05[397];            /* ??? (0x00...) */
	uint16_t  	signature;              /* 0xaa55 */
} __attribute__ ((__packed__));

int check_EXFAT(disk_t *disk_car, partition_t *partition);
int recover_EXFAT(const disk_t *disk, const struct exfat_super_block *exfat_header, partition_t *partition);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
