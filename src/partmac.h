/*

    File: partmac.c

    Copyright (C) 2005 Christophe GRENIER <grenier@cgsecurity.org>
    Some information has been found in mac-fdisk software
  
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


#define	BLOCK0_SIGNATURE	0x4552	/* Signature value.         */

#define	DPISTRLEN	32
#define	DPME_SIGNATURE	0x504D
#define PBLOCK_SIZE	512


// Physical block zero of the disk has this format
struct Block0 {
    uint16_t 	sbSig;		/* unique value for SCSI block 0 */
    uint16_t 	sbBlkSize;	/* block size of device */
    uint32_t 	sbBlkCount;	/* number of blocks on device */
    uint16_t 	sbDevType;	/* device type */
    uint16_t 	sbDevId;	/* device id */
    uint32_t 	sbData;		/* not used */
    uint16_t 	sbDrvrCount;	/* driver descriptor count */
    uint16_t 	sbMap[247];	/* descriptor map */
};
typedef struct Block0 mac_Block0;

// Where &sbMap[0] is actually an array DDMap[sbDrvrCount]
// kludge to get around alignment junk
struct DDMap {
    uint32_t 	ddBlock;	/* 1st driver's starting block */
    uint16_t 	ddSize;		/* size of 1st driver (512-byte blks) */
    uint16_t 	ddType;		/* system type (1 for Mac+) */
};
typedef struct DDMap mac_DDMap;


// Each partition map entry (blocks 1 through n) has this format
struct dpme {
    uint16_t     dpme_signature          ;
    uint16_t     dpme_reserved_1         ;
    uint32_t     dpme_map_entries        ;
    uint32_t     dpme_pblock_start       ;
    uint32_t     dpme_pblocks            ;
    char    	dpme_name[DPISTRLEN]    ;  /* name of partition */
    char    	dpme_type[DPISTRLEN]    ;  /* type of partition */
    uint32_t     dpme_lblock_start       ;
    uint32_t     dpme_lblocks            ;
    uint32_t     dpme_flags;
#if 0
    uint32_t     dpme_reserved_2    : 23 ;  /* Bit 9 through 31.        */
    uint32_t     dpme_os_specific_1 :  1 ;  /* Bit 8.                   */
    uint32_t     dpme_os_specific_2 :  1 ;  /* Bit 7.                   */
    uint32_t     dpme_os_pic_code   :  1 ;  /* Bit 6.                   */
    uint32_t     dpme_writable      :  1 ;  /* Bit 5.                   */
    uint32_t     dpme_readable      :  1 ;  /* Bit 4.                   */
    uint32_t     dpme_bootable      :  1 ;  /* Bit 3.                   */
    uint32_t     dpme_in_use        :  1 ;  /* Bit 2.                   */
    uint32_t     dpme_allocated     :  1 ;  /* Bit 1.                   */
    uint32_t     dpme_valid         :  1 ;  /* Bit 0.                   */
#endif
    uint32_t     dpme_boot_block         ;
    uint32_t     dpme_boot_bytes         ;
    uint8_t     *dpme_load_addr          ;
    uint8_t     *dpme_load_addr_2        ;
    uint8_t     *dpme_goto_addr          ;
    uint8_t     *dpme_goto_addr_2        ;
    uint32_t     dpme_checksum           ;
    char    	dpme_process_id[16]     ;
    uint32_t     dpme_boot_args[32]      ;
    uint32_t     dpme_reserved_3[62]     ;
};
typedef struct dpme mac_DPME;

int test_structure_mac(list_part_t *list_part);
list_part_t *add_partition_mac_cli(disk_t *disk_car,list_part_t *list_part, char **current_cmd);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
