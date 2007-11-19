/*

    File: common.h

    Copyright (C) 1998-2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifndef _COMMON_H
#define _COMMON_H
typedef struct efi_guid_s efi_guid_t;
struct efi_guid_s
{
  uint32_t time_low;
  uint16_t time_mid;
  uint16_t time_hi_and_version;
  uint8_t  clock_seq_hi_and_reserved;
  uint8_t  clock_seq_low;
  uint8_t  node[6];
} __attribute__ ((__packed__));

#define DEFAULT_SECTOR_SIZE     0x200

#define MAX_CYLINDERS 65535
#define MAX_HEADS 255
#define MAX_SECTORS 63

#define DISKNAME_MAX	64
#define DISKDESCRIPTION_MAX	128
#define TAB_PART 0x1BE
/* PARTITION TYPE */
#define P_NO_OS         0x00
#define P_12FAT         0x01
#define P_16FAT         0x04
#define P_EXTENDED      0x05
#define P_16FATBD       0x06
#define P_NTFS          0x07
#define P_HPFS          0x07
#define P_OS2MB         0x0A
#define P_32FAT         0x0B
#define P_32FAT_LBA     0x0C
#define P_16FATBD_LBA   0x0E
#define P_EXTENDX       0x0F
#define P_12FATH        0x11
#define P_16FATH        0x14
#define P_16FATBDH      0x16
#define P_NTFSH         0x17
#define P_32FATH        0x1B
#define P_32FAT_LBAH    0x1C
#define P_16FATBD_LBAH  0x1E
#define P_SYSV		0x63
#define P_NETWARE	0x65
#define P_OLDLINUX      0x81
#define P_LINSWAP       0x82
#define P_LINUX         0x83
#define P_LINUXEXTENDX  0x85
#define P_LVM		0x8E
#define P_FREEBSD       0xA5
#define P_OPENBSD       0xA6
#define P_NETBSD        0xA9
#define P_HFS		0xAF
#define P_HFSP		0xAF
#define P_SUN		0xBF
#define P_BEOS          0xEB
#define P_RAID		0xFD
#define P_UNK		255
#define NO_ORDER 	255
/* Partition SUN */
#define PSUN_BOOT	1
#define PSUN_ROOT	2
#define PSUN_SWAP	3
#define PSUN_USR	4
#define PSUN_WHOLE_DISK	5
#define PSUN_STAND	6
#define PSUN_VAR	7
#define PSUN_HOME	8
#define PSUN_ALT	9
#define PSUN_CACHEFS	10
#define PSUN_LINSWAP	P_LINSWAP
#define PSUN_LINUX	P_LINUX
#define PSUN_LVM	P_LVM
#define PSUN_RAID	P_RAID
#define PSUN_UNK	255

#define PMAC_DRIVER43 	1
#define PMAC_DRIVERATA 	2
#define PMAC_DRIVERIO 	3
#define PMAC_FREE	4
#define PMAC_FWDRIVER	5
#define PMAC_SWAP	0x82
#define PMAC_LINUX	0x83
#define PMAC_HFS	0xAF
#define PMAC_MAP	6
#define PMAC_PATCHES	7
#define PMAC_UNK	8
#define PMAC_NewWorld	9
#define PMAC_DRIVER	10
#define PMAC_MFS	11
#define PMAC_PRODOS	12
#define PMAC_FAT32      13

#define PXBOX_UNK	0
#define PXBOX_FATX	1

#define	GPT_ENT_TYPE_UNUSED		\
	((efi_guid_t){le32(0x00000000),le16(0x0000),le16(0x0000),0x00,0x00,{0x00,0x00,0x00,0x00,0x00,0x00}})
#define	GPT_ENT_TYPE_EFI		\
	((efi_guid_t){le32(0xc12a7328),le16(0xf81f),le16(0x11d2),0xba,0x4b,{0x00,0xa0,0xc9,0x3e,0xc9,0x3b}})
#define	GPT_ENT_TYPE_MBR		\
	((efi_guid_t){le32(0x024dee41),le16(0x33e7),le16(0x11d3),0x9d,0x69,{0x00,0x08,0xc7,0x81,0xf3,0x9f}})
#define	GPT_ENT_TYPE_FREEBSD		\
	((efi_guid_t){le32(0x516e7cb4),le16(0x6ecf),le16(0x11d6),0x8f,0xf8,{0x00,0x02,0x2d,0x09,0x71,0x2b}})
#define	GPT_ENT_TYPE_FREEBSD_SWAP	\
	((efi_guid_t){le32(0x516e7cb5),le16(0x6ecf),le16(0x11d6),0x8f,0xf8,{0x00,0x02,0x2d,0x09,0x71,0x2b}})
#define	GPT_ENT_TYPE_FREEBSD_UFS	\
	((efi_guid_t){le32(0x516e7cb6),le16(0x6ecf),le16(0x11d6),0x8f,0xf8,{0x00,0x02,0x2d,0x09,0x71,0x2b}})
/*
 * The following is unused but documented here to avoid reuse.
 *
 * GPT_ENT_TYPE_FREEBSD_UFS2	\
 *	((efi_guid_t){le32(0x516e7cb7),le16(0x6ecf),le16(0x11d6),0x8f,0xf8,{0x00,0x02,0x2d,0x09,0x71,0x2b}})
 */

#define	GPT_ENT_TYPE_FREEBSD_VINUM	\
	((efi_guid_t){le32(0x516e7cb8),le16(0x6ecf),le16(0x11d6),0x8f,0xf8,{0x00,0x02,0x2d,0x09,0x71,0x2b}})


#define	GPT_ENT_TYPE_MS_RESERVED	\
	((efi_guid_t){le32(0xe3c9e316),le16(0x0b5c),le16(0x4db8),0x81,0x7d,{0xf9,0x2d,0xf0,0x02,0x15,0xae}})
#define	GPT_ENT_TYPE_MS_BASIC_DATA	\
	((efi_guid_t){le32(0xebd0a0a2),le16(0xb9e5),le16(0x4433),0x87,0xc0,{0x68,0xb6,0xb7,0x26,0x99,0xc7}})
#define	GPT_ENT_TYPE_MS_LDM_METADATA	\
	((efi_guid_t){le32(0x5808c8aa),le16(0x7e8f),le16(0x42e0),0x85,0xd2,{0xe1,0xe9,0x04,0x34,0xcf,0xb3}})
#define	GPT_ENT_TYPE_MS_LDM_DATA	\
	((efi_guid_t){le32(0xaf9b60a0),le16(0x1431),le16(0x4f62),0xbc,0x68,{0x33,0x11,0x71,0x4a,0x69,0xad}})

#define	GPT_ENT_TYPE_LINUX_DATA		GPT_ENT_TYPE_MS_BASIC_DATA
#define	GPT_ENT_TYPE_LINUX_RAID		\
	((efi_guid_t){le32(0xa19d880f),le16(0x05fc),le16(0x4d3b),0xa0,0x06,{0x74,0x3f,0x0f,0x84,0x91,0x1e}})
#define	GPT_ENT_TYPE_LINUX_SWAP		\
	((efi_guid_t){le32(0x0657fd6d),le16(0xa4ab),le16(0x43c4),0x84,0xe5,{0x09,0x33,0xc8,0x4b,0x4f,0x4f}})
#define	GPT_ENT_TYPE_LINUX_LVM		\
	((efi_guid_t){le32(0xe6d6d379),le16(0xf507),le16(0x44c2),0xa2,0x3c,{0x23,0x8f,0x2a,0x3d,0xf9,0x28}})
#define GPT_ENT_TYPE_LINUX_RESERVED	\
	((efi_guid_t){le32(0x8da63339),le16(0x0007),le16(0x60c0),0xc4,0x36,{0x08,0x3a,0xc8,0x23,0x09,0x08}})


#define GPT_ENT_TYPE_HPUX_DATA	\
	((efi_guid_t){le32(0x75894c1e),le16(0x3aeb),le16(0x11d3),0xb7,0xc1,{0x7b,0x03,0xa0,0x00,0x00,0x00}})
#define GPT_ENT_TYPE_HPUX_SERVICE \
	((efi_guid_t){le32(0xe2a1e728),le16(0x32e3),le16(0x11d6),0xa6,0x82,{0x7b,0x03,0xa0,0x00,0x00,0x00}})

#define GPT_ENT_TYPE_MAC_HFS		\
	((efi_guid_t){le32(0x48465300),le16(0x0000),le16(0x11aa),0xaa,0x11,{0x00,0x30,0x65,0x43,0xec,0xac}})
#define GPT_ENT_TYPE_MAC_UFS		\
	((efi_guid_t){le32(0x55465300),le16(0x0000),le16(0x11aa),0xaa,0x11,{0x00,0x30,0x65,0x43,0xec,0xac}})
#define GPT_ENT_TYPE_MAC_RAID	\
	((efi_guid_t){le32(0x52414944),le16(0x0000),le16(0x11aa),0xaa,0x11,{0x00,0x30,0x65,0x43,0xec,0xac}})
#define GPT_ENT_TYPE_MAC_RAID_OFFLINE 	\
	((efi_guid_t){le32(0x52414944),le16(0x5f4f),le16(0x11aa),0xaa,0x11,{0x00,0x30,0x65,0x43,0xec,0xac}})
#define GPT_ENT_TYPE_MAC_BOOT	\
	((efi_guid_t){le32(0x426f6f74),le16(0x0000),le16(0x11aa),0xaa,0x11,{0x00,0x30,0x65,0x43,0xec,0xac}})
#define GPT_ENT_TYPE_MAC_LABEL 	\
	((efi_guid_t){le32(0x4c616265),le16(0x6c00),le16(0x11aa),0xaa,0x11,{0x00,0x30,0x65,0x43,0xec,0xac}})
#define GPT_ENT_TYPE_MAC_TV_RECOVERY  	\
	((efi_guid_t){le32(0x5265636f),le16(0x7665),le16(0x11aa),0xaa,0x11,{0x00,0x30,0x65,0x43,0xec,0xac}})

#define GPT_ENT_TYPE_SOLARIS_BOOT  	\
	((efi_guid_t){le32(0x6a82cb45),le16(0x1dd2),le16(0x11b2),0x99,0xa6,{0x08,0x00,0x20,0x73,0x66,0x31}})
#define GPT_ENT_TYPE_SOLARIS_ROOT  	\
	((efi_guid_t){le32(0x6a85cf4d),le16(0x1dd2),le16(0x11b2),0x99,0xa6,{0x08,0x00,0x20,0x73,0x66,0x31}})
#define GPT_ENT_TYPE_SOLARIS_SWAP  	\
	((efi_guid_t){le32(0x6a87c46f),le16(0x1dd2),le16(0x11b2),0x99,0xa6,{0x08,0x00,0x20,0x73,0x66,0x31}})
#define GPT_ENT_TYPE_SOLARIS_BACKUP  	\
	((efi_guid_t){le32(0x6a8b642b),le16(0x1dd2),le16(0x11b2),0x99,0xa6,{0x08,0x00,0x20,0x73,0x66,0x31}})
#define GPT_ENT_TYPE_SOLARIS_USR  	\
	((efi_guid_t){le32(0x6a898cc3),le16(0x1dd2),le16(0x11b2),0x99,0xa6,{0x08,0x00,0x20,0x73,0x66,0x31}})
#define GPT_ENT_TYPE_SOLARIS_VAR  	\
	((efi_guid_t){le32(0x6a8ef2e9),le16(0x1dd2),le16(0x11b2),0x99,0xa6,{0x08,0x00,0x20,0x73,0x66,0x31}})
#define GPT_ENT_TYPE_SOLARIS_HOME  	\
	((efi_guid_t){le32(0x6a90ba39),le16(0x1dd2),le16(0x11b2),0x96,0xa6,{0x08,0x00,0x20,0x73,0x66,0x31}})
#define GPT_ENT_TYPE_SOLARIS_EFI_ALTSCTR \
	((efi_guid_t){le32(0x6a9283a5),le16(0x1dd2),le16(0x11b2),0x96,0xa6,{0x08,0x00,0x20,0x73,0x66,0x31}})
#define GPT_ENT_TYPE_SOLARIS_RESERVED1	\
	((efi_guid_t){le32(0x6a945a3b),le16(0x1dd2),le16(0x11b2),0x96,0xa6,{0x08,0x00,0x20,0x73,0x66,0x31}})
#define GPT_ENT_TYPE_SOLARIS_RESERVED2	\
	((efi_guid_t){le32(0x6a9630d1),le16(0x1dd2),le16(0x11b2),0x96,0xa6,{0x08,0x00,0x20,0x73,0x66,0x31}})
#define GPT_ENT_TYPE_SOLARIS_RESERVED3	\
	((efi_guid_t){le32(0x6a980767),le16(0x1dd2),le16(0x11b2),0x96,0xa6,{0x08,0x00,0x20,0x73,0x66,0x31}})
#define GPT_ENT_TYPE_SOLARIS_RESERVED4	\
	((efi_guid_t){le32(0x6a96237f),le16(0x1dd2),le16(0x11b2),0x96,0xa6,{0x08,0x00,0x20,0x73,0x66,0x31}})
#define GPT_ENT_TYPE_SOLARIS_RESERVED5	\
	((efi_guid_t){le32(0x6a8d2ac7),le16(0x1dd2),le16(0x11b2),0x96,0xa6,{0x08,0x00,0x20,0x73,0x66,0x31}})

#define TESTDISK_O_RDONLY     00
#define TESTDISK_O_RDWR	      02
#define TESTDISK_O_DIRECT 040000
#define TESTDISK_O_READAHEAD_8K 04
#define TESTDISK_O_READAHEAD_32K 010
#define TESTDISK_O_ALL		020

enum upart_type { UP_UNK, UP_BEOS, UP_CRAMFS, UP_EXT2, UP_EXT3, UP_EXTENDED, UP_FAT12, UP_FAT16, UP_FAT32, UP_FATX, UP_FREEBSD,  UP_HFS, UP_HFSP, UP_HFSX, UP_HPFS, UP_JFS, UP_LINSWAP, UP_LINSWAP2, UP_LUKS, UP_LVM, UP_LVM2, UP_MD, UP_MD1, UP_NETWARE, UP_NTFS, UP_OPENBSD, UP_OS2MB, UP_RFS, UP_RFS2, UP_RFS3, UP_RFS4, UP_SUN, UP_SYSV4, UP_UFS, UP_UFS2, UP_XFS, UP_XFS2, UP_XFS3, UP_XFS4};
typedef enum upart_type upart_type_t;
enum status_type { STATUS_DELETED, STATUS_PRIM, STATUS_PRIM_BOOT, STATUS_LOG, STATUS_EXT, STATUS_EXT_IN_EXT};
typedef enum status_type status_type_t;
enum errcode_type {BAD_NOERR, BAD_SS, BAD_ES, BAD_SH, BAD_EH, BAD_EBS, BAD_RS, BAD_SC, BAD_EC, BAD_SCOUNT};
typedef enum errcode_type errcode_type_t;
enum aff_part_type {AFF_PART_NONL, AFF_PART_ORDER, AFF_PART_SHORT};
typedef enum aff_part_type aff_part_type_t;

typedef struct param_disk_struct disk_t;
typedef struct partition_struct partition_t;
typedef struct CHS_struct CHS_t;

struct CHS_struct
{
  unsigned int cylinder;
  unsigned int head;
  unsigned int sector;
};

typedef struct list_part_struct list_part_t;
struct list_part_struct
{
  partition_t *part;
  list_part_t *prev;
  list_part_t *next;
  int to_be_removed;
};

typedef struct list_disk_struct list_disk_t;
struct list_disk_struct
{
  disk_t *disk;
  list_disk_t *prev;
  list_disk_t *next;
};

struct systypes {
  const unsigned int part_type;
  const char *name;
};

struct arch_fnct_struct
{
  const char *part_name;
  const char *part_name_option;
  const char *msg_part_type;
  list_part_t *(*read_part)(disk_t *disk_car, const int verbose,const int saveheader);
  int (*write_part)(disk_t *disk_car, const list_part_t *list_part, const int ro, const int verbose, const int align);
  list_part_t *(*init_part_order)(const disk_t *disk_car, list_part_t *list_part);
  /* geometry must be initialized to 0,0,0 in get_geometry_from_mbr()*/
  int (*get_geometry_from_mbr)(const unsigned char *buffer, const int verbose, CHS_t *geometry);
  int (*check_part)(disk_t *disk_car,const int verbose,partition_t *partition, const int saveheader);
  int (*write_MBR_code)(disk_t *disk_car);
  list_part_t *(*add_partition)(disk_t *disk_car,list_part_t *list_part, const int verbose, char **current_cmd);
  void (*set_prev_status)(const disk_t *disk_car, partition_t *partition);
  void (*set_next_status)(const disk_t *disk_car, partition_t *partition);
  int (*test_structure)(list_part_t *list_part);
  unsigned int (*get_part_type)(const partition_t *partition);
  int (*set_part_type)(partition_t *partition, unsigned int part_type);
  void (*init_structure)(const disk_t *disk_car,list_part_t *list_part, const int verbose);
  int (*erase_list_part)(disk_t *disk_car);
  const char *(*get_partition_typename)(const partition_t *partition);
  int (*is_part_known)(const partition_t *partition);
};

typedef struct arch_fnct_struct arch_fnct_t;

struct param_disk_struct
{
  uint64_t disk_size;
  CHS_t CHS;	/* logical CHS */
  int halt_on_errors;
  int write_used;
  int autodetect;
  int access_mode;
  unsigned int sector_size;
  char *device;
  char description_txt[DISKDESCRIPTION_MAX];
  char description_short_txt[DISKDESCRIPTION_MAX];
  const char *(*description)(disk_t *disk_car);
  const char *(*description_short)(disk_t *disk_car);
  int (*read)(disk_t *disk_car,const unsigned int nbr_sector, void *nom_buffer, const uint64_t offset);
  int (*write)(disk_t *disk_car,const unsigned int nbr_sector, const void *nom_buffer, const uint64_t offset);
  int (*clean)(disk_t *disk_car);
  const arch_fnct_t *arch;
  void *data;
  uint64_t disk_real_size;
};

struct partition_struct
{
  uint64_t      part_offset;
  uint64_t      part_size;
  uint64_t      sborg_offset;
  uint64_t      sb_offset;
  unsigned int  sb_size;
  unsigned int  blocksize;
  unsigned int  part_type_i386;
  unsigned int  part_type_sun;
  unsigned int  part_type_mac;
  unsigned int  part_type_xbox;
  efi_guid_t    part_type_gpt;
  efi_guid_t    part_uuid;
  upart_type_t  upart_type;
  status_type_t status;
  unsigned int  order;
  errcode_type_t errcode;
  char          fsname[80];
  char          partname[80];
  char          info[80];
  const arch_fnct_t *arch;
};

typedef struct my_data_struct my_data_t;
struct my_data_struct
{
  disk_t *disk_car;
  const partition_t *partition;
  uint64_t offset;
};

void dup_partition_t(partition_t *dest, const partition_t *src);
int read_line(void);
char read_char(const char *);
void *MALLOC(size_t size);
char read_key(void);
char test_key(void);
unsigned int up2power(const unsigned int number);
void my_sort(void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *));
int check_volume_name(const char *name,const unsigned int max_size);
void set_part_name(partition_t *partition,const char *src,const int max_size);
int rebuild_FAT_BS(disk_t *disk_car,partition_t *partition, const int verbose, const int dump_ind,const int interface, const unsigned int expert, char**current_cmd);
#ifndef BSD_MAXPARTITIONS
#define	BSD_MAXPARTITIONS	8
#endif
#ifndef OPENBSD_MAXPARTITIONS
#define	OPENBSD_MAXPARTITIONS	16
#endif

#ifdef TESTDISK_LSB
#define le16(x)  (x)             /* x as little endian */
#define be16(x)  ((((x)&0xff00)>>8)                      | \
    (((x)&0x00ff)<<8))
#define le24(x)  (x)
#define le32(x)  (x)
#define be32(x)  ((((x)&0xff000000L)>>24)                | \
    (((x)&0x00ff0000L)>>8)                  | \
    (((x)&0x0000ff00L)<<8)                  | \
    (((x)&0x000000ffL)<<24))
#define le64(x)  (x)
#define be64(x)  ((((x)&0xff00000000000000LL)>>56)       | \
    (((x)&0x00ff000000000000LL)>>40)        | \
    (((x)&0x0000ff0000000000LL)>>24)        | \
    (((x)&0x000000ff00000000LL)>>8)         | \
    (((x)&0x00000000ff000000LL)<<8)         | \
    (((x)&0x0000000000ff0000LL)<<24)        | \
    (((x)&0x000000000000ff00LL)<<40)        | \
    (((x)&0x00000000000000ffLL)<<56))
#else /* bigendian */
#define le16(x)  ((((x)&0xff00)>>8)                      | \
    (((x)&0x00ff)<<8))
#define be16(x)  (x)
#define be24(x)  (x)
#define le24(x) ((((x) & 0x000000ffUL) << 16) | \
    ((x) & 0x0000ff00UL)        | \
    (((x) & 0x00ff0000UL) >> 16))
#define le32(x)  ((((x)&0xff000000L)>>24)                | \
    (((x)&0x00ff0000L)>>8)                  | \
    (((x)&0x0000ff00L)<<8)                  | \
    (((x)&0x000000ffL)<<24))
#define be32(x)  (x)
#define le64(x)  ((((x)&0xff00000000000000LL)>>56)       | \
    (((x)&0x00ff000000000000LL)>>40)        | \
    (((x)&0x0000ff0000000000LL)>>24)        | \
    (((x)&0x000000ff00000000LL)>>8)         | \
    (((x)&0x00000000ff000000LL)<<8)         | \
    (((x)&0x0000000000ff0000LL)<<24)        | \
    (((x)&0x000000000000ff00LL)<<40)        | \
    (((x)&0x00000000000000ffLL)<<56))
#define be64(x)  (x)
#endif
#ifndef HAVE_SNPRINTF
int snprintf(char *str, size_t size, const char *format, ...);
#endif
#ifndef HAVE_VSNPRINTF
#include <stdarg.h>
int vsnprintf(char *str, size_t size, const char *format, va_list ap);
#endif
#ifndef HAVE_STRNCASECMP
int strncasecmp(const char * s1, const char * s2, size_t len);
#endif
void create_dir(const char *dir_name, const unsigned int is_dir_name);
unsigned int filename_convert(char *dst, const char*src, const unsigned int n);

#ifdef DJGPP
    #define TESTDISK_OS "Dos version"
#elif defined(TARGET_BSD)
    #define TESTDISK_OS "BSD version"
#elif defined(TARGET_LINUX)
    #define TESTDISK_OS "Linux version"
#elif defined(TARGET_SOLARIS)
    #define TESTDISK_OS "Solaris version"
#elif defined(__CYGWIN__) || defined(__MINGW32__)
    #define TESTDISK_OS "Windows version"
#elif defined(__APPLE__)
    #define TESTDISK_OS "Apple version"
#elif defined(__OS2__)
    #define TESTDISK_OS "OS2 version"
#else
    #define TESTDISK_OS "Undefined OS"
#endif
#endif
