/*

    File: lang.h

    Copyright (C) 1998-2004 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#define msg_DUMP_HEXA     "Dump Hexa\n"
#define c_YES           'Y'
#define c_NO            'N'
#define msg_TBL_NMARK     "\nPartition sector doesn't have the endmark 0xAA55\n"
#define msg_BAD_S_CYL     "\nWarning: Bad starting cylinder (CHS and LBA don't match)"
#define msg_BAD_S_HEAD    "\nWarning: Bad starting head (CHS and LBA don't match)"
#define msg_BAD_S_SECT    "\nWarning: Bad starting sector (CHS and LBA don't match)"
#define msg_BAD_E_CYL     "\nWarning: Bad ending cylinder (CHS and LBA don't match)"
#define msg_BAD_E_HEAD    "\nWarning: Bad ending head (CHS and LBA don't match)"
#define msg_BAD_E_SECT    "\nWarning: Bad ending sector (CHS and LBA don't match)"
#define msg_END_BFR_START "\nPartition end < start !"
#define msg_BAD_RS        "\nBad relative sector."
#define msg_BAD_SCOUNT    "\nBad sector count."
#define msg_CHKFAT_BAD_JUMP       "check_FAT: Bad jump in FAT partition\n"
#define msg_CHKFAT_SECT_CLUSTER   "check_FAT: Bad number of sectors per cluster\n"
#define msg_CHKFAT_ENTRY  "check_FAT: Bad number of entries in root dir\n"
#define msg_CHKFAT_SIZE   "check_FAT: Incorrect size of partition\n"
#define msg_CHKFAT_SECTPFAT "check_FAT: Incorrect number of sectors per FAT\n"
#define msg_CHKFAT_BADFAT32VERSION "check_FAT: Bad FAT32 version, should be 0.0\n"
#define msg_PART_HEADER   	"     Partition\t\t     Start        End    Size in sectors\n"
#define msg_PART_HEADER_LONG   	"     Partition\t\t\tStart        End    Size in sectors\n"
#define msg_PART_RD_ERR   "\nPartition: Read error\n"
#define msg_PART_WR_ERR   "\nPartition: Write error\n"
#define msg_ONLY_ONE_DOS  "Partition Table contains two or more Primary DOS FAT partitions\n"
#define msg_ONLY_ONE_EXT  "Partition Table may contain only one Extended partition\n"
#define msg_NO_BOOTABLE   "No partition is bootable\n"
#define msg_ONLY1MUSTBOOT "Only one partition must be bootable\n"
#define msg_SAME_SPACE    "Space conflict between the following two partitions\n"
#define msg_WRITE_CLEAN_TABLE     "Clear MBR partition table by writing zero bytes to it? (Y/N) "
#define msg_WRITE_MBR_CODE    "Write a new copy of MBR code to first sector? (Y/N) "
#define msg_STRUCT_BAD    	"Structure: Bad."
#define msg_STRUCT_OK           "Structure: Ok. "
#define msg_MBR_ORDER             "MBR order - Use 1234 to change the order and ENTER to continue"
#define msg_MBR_ORDER_GOOD        "Partitions order: Ok "
#define msg_MBR_ORDER_BAD "Partitions order: Bad"
#define msg_NO_EXT_PART   "No extended partition\n"
