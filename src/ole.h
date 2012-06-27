/*

    File: common.c

    Copyright (C) 2006 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#define SPECIAL_BLOCK	- 3
#define END_OF_CHAIN	- 2
#define UNUSED			- 1

#define NO_ENTRY		0
#define STORAGE			1
#define STREAM			2
#define ROOT			5
#define SHORT_BLOCK		3

#define FAT_START		0x4c
#define OUR_BLK_SIZE	512
#define DIRS_PER_BLK	4

struct OLE_HDR
{
	char		magic[8];				/*0*/
	char		clsid[16];				/*8*/
	uint16_t	uMinorVersion;			/*24*/
	uint16_t	uDllVersion;			/*26*/
	uint16_t	uByteOrder;				/*28*/
	uint16_t	uSectorShift;			/*30*/
	uint16_t	uMiniSectorShift;		/*32*/
	uint16_t	reserved;				/*34*/
	uint32_t	reserved1;				/*36*/
	uint32_t	csectDir;			/*40 Number of sectors in directory chains for 4KB sectors */
	uint32_t	num_FAT_blocks;			/*44*/
	uint32_t	root_start_block;		/*48*/
	uint32_t	dfsignature;			/*52*/
	uint32_t	miniSectorCutoff;		/*56*/
	uint32_t	MiniFat_block;			/*60 first sec in the mini fat chain*/
	uint32_t	csectMiniFat;			/*64 number of sectors in the minifat */
	uint32_t	FAT_next_block;			/*68*/
	uint32_t	num_extra_FAT_blocks;	/*72*/
	/* FAT block list starts here !! first 109 entries  */
} __attribute__ ((__packed__));

struct OLE_DIR
{
	char		name[64];	// 0
	uint16_t	namsiz;		// 64
	char		type;		// 66
	char		bflags;		// 67: 0 or 1
	uint32_t	prev_dirent;	// 68
	uint32_t	next_dirent;	// 72
	uint32_t	sidChild;	// 76
	char		clsid[16];	// 80
	uint32_t	userFlags;	// 96
	int32_t		secs1;		// 100
	int32_t		days1;		// 104
	int32_t		secs2;		// 108
	int32_t		days2;		// 112
	uint32_t	start_block;	// 116 starting SECT of stream
	uint32_t	size;		// 120
	int16_t			reserved;	// 124 must be 0
	int16_t			padding;	// 126 must be 0
} __attribute__ ((__packed__));

struct DIRECTORY
{
	char	name[64];
	int32_t		type;
	int32_t		level;
	int32_t		start_block;
	int32_t		size;
	int32_t		next;
	int32_t		prev;
	int32_t		dir;
	int32_t		s1;
	int32_t		s2;
	int32_t		d1;
	int32_t		d2;
};

