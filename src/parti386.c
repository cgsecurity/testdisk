/*

    File: parti386.c

    Copyright (C) 1998-2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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


#if !defined(SINGLE_PARTITION_TYPE) || defined(SINGLE_PARTITION_I386)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
 
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <ctype.h>      /* tolower */
#include <assert.h>
#include "types.h"
#include "common.h"
#include "fnctdsk.h"
#include "lang.h"
#include "intrf.h"
#include "chgtype.h"
#include "savehdr.h"
#ifndef DISABLED_FOR_FRAMAC
#include "analyse.h"
#include "bfs.h"
#include "bsd.h"
#include "exfat.h"
#include "fat.h"
#include "hfs.h"
#include "hfsp.h"
#include "lvm.h"
#include "md.h"
#include "netware.h"
#include "ntfs.h"
#include "sun.h"
#include "swap.h"
#endif
#include "log.h"
#include "parti386.h"
#include "partgpt.h"
#include "partxbox.h"

#define TAB_PART 0x1BE

/*@
  @ assigns \nothing;
  @*/
static int is_extended(const unsigned int part_type);

/*@
  @ requires list_part == \null || \valid_read(list_part);
  @*/
static int test_structure_i386(const list_part_t *list_part);

#define pt_offset_const(b, n) ((const struct partition_dos *)((b) + 0x1be + \
      (n) * sizeof(struct partition_dos)))
#define pt_offset(b, n) ((struct partition_dos *)((b) + 0x1be + \
      (n) * sizeof(struct partition_dos)))

struct partition_dos {
    unsigned char boot_ind;         /* 0x80 - active */
    unsigned char head;             /* starting head */
    unsigned char sector;           /* starting sector */
    unsigned char cyl;              /* starting cylinder */
    unsigned char sys_ind;          /* What partition type */
    unsigned char end_head;         /* end head */
    unsigned char end_sector;       /* end sector */
    unsigned char end_cyl;          /* end cylinder */
    unsigned char start4[4];        /* starting sector counting from 0 */
    unsigned char size4[4];         /* nr of sectors in partition */
};


#define s_cyl(p) (((p)->cyl & (unsigned)0xff) | (((p)->sector << 2) & (unsigned)0x300))
#define s_sect(p) ((p)->sector & (unsigned)0x3f)
#define e_cyl(p) (((p)->end_cyl & (unsigned)0xff) | (((p)->end_sector << 2) & (unsigned)0x300))
#define e_sect(p) ((p)->end_sector & (unsigned)0x3f)
static void log_dos_entry(const struct partition_dos*);

/*@
  @ requires \valid_read(buffer + (0 .. 0x200-1));
  @ requires \valid(geometry);
  @ requires \separated(buffer + (0 .. 0x200-1), geometry);
  @ requires geometry->cylinders==0;
  @ requires geometry->heads_per_cylinder==0;
  @ requires geometry->sectors_per_head==0;
  @*/
// assigns geometry->sectors_per_head, geometry->heads_per_cylinder, geometry->bytes_per_sector;
static int get_geometry_from_i386mbr(const unsigned char *buffer, const int verbose, CHSgeometry_t *geometry);

/*@
  @ requires \valid(disk_car);
  @ requires list_part == \null || \valid(list_part);
  @ requires separation: \separated(disk_car, list_part);
  @*/
static list_part_t *get_ext_data_i386(disk_t *disk_car, list_part_t *list_part, const int verbose, const int saveheader);

/*@
  @ requires list_part == \null || \valid(list_part);
  @*/
static void test_MBR_data(const list_part_t *list_part);

/*@
  @ requires \valid(disk_car);
  @ requires list_part == \null || \valid(list_part);
  @*/
static int test_MBR_over(const disk_t *disk_car, const list_part_t *list_part);

/*@
  @ requires \valid(disk_car);
  @ requires list_part == \null || \valid(list_part);
  @ requires separation: \separated(disk_car, list_part);
  @*/
static int write_mbr_i386(disk_t *disk_car, const list_part_t *list_part, const int ro, const int verbose);

/*@
  @ requires \valid(disk_car);
  @ requires list_part == \null || \valid(list_part);
  @ requires separation: \separated(disk_car, list_part);
  @*/
static int write_all_log_i386(disk_t *disk_car, const list_part_t *list_part, const int ro , const int verbose);

static int diff(const unsigned char buffer[DEFAULT_SECTOR_SIZE], const unsigned char buffer_org[DEFAULT_SECTOR_SIZE]);

/*@
  @ requires \valid(disk_car);
  @ requires valid_disk(disk_car);
  @ ensures  valid_list_part(\result);
  @*/
static list_part_t *read_part_i386(disk_t *disk_car, const int verbose, const int saveheader);

/*@
  @ requires \valid(disk_car);
  @ requires list_part == \null || \valid(list_part);
  @ requires separation: \separated(disk_car, list_part);
  @*/
static int write_part_i386(disk_t *disk_car, const list_part_t *list_part, const int ro , const int verbose);

/*@
  @ requires \valid(disk_car);
  @ requires list_part == \null || \valid(list_part);
  @ requires separation: \separated(disk_car, list_part);
  @*/
static list_part_t *init_part_order_i386(const disk_t *disk_car, list_part_t *list_part);

/*@
  @ requires \valid(disk_car);
  @*/
static int write_MBR_code_i386(disk_t *disk_car);

static int write_MBR_code_i386_aux(unsigned char *buffer);

/*@
  @ requires \valid_read(disk_car);
  @ requires \valid(partition);
  @ requires separation: \separated(disk_car, partition);
  @ assigns partition->status;
  @*/
static void set_prev_status_i386(const disk_t *disk_car, partition_t *partition);

/*@
  @ requires \valid_read(disk_car);
  @ requires \valid(partition);
  @ requires separation: \separated(disk_car, partition);
  @ assigns partition->status;
  @*/
static void set_next_status_i386(const disk_t *disk_car, partition_t *partition);

/*@
  @ requires \valid(partition);
  @ assigns partition->part_type_i386;
  @*/
static int set_part_type_i386(partition_t *partition, unsigned int part_type);

/*@
  @ requires \valid(partition);
  @ assigns \nothing;
  @*/
static int is_part_known_i386(const partition_t *partition);

/*@
  @ requires \valid_read(disk_car);
  @ requires list_part == \null || \valid(list_part);
  @ requires separation: \separated(disk_car, list_part);
  @*/
static void init_structure_i386(const disk_t *disk_car, list_part_t *list_part, const int verbose);

/*@
  @ requires \valid(disk_car);
  @*/
static int erase_list_part_i386(disk_t *disk_car);

/*@
  @ requires \valid(disk_car);
  @ requires \valid(partition);
  @ requires separation: \separated(disk_car, partition);
  @*/
static int check_part_i386(disk_t *disk_car, const int verbose, partition_t *partition, const int saveheader);

/*@
  @ requires \valid_read(disk_car);
  @ requires \valid_read(partition);
  @ requires \valid(p);
  @ requires \separated(disk_car, partition, p);
  @*/
static void partition2_i386_entry(const disk_t *disk_car, const uint64_t pos, const partition_t *partition, struct partition_dos *p);

/*@
  @ requires \valid(disk_car);
  @ requires \valid(partition);
  @ requires \valid_read(p);
  @ requires separation: \separated(disk_car, partition, p);
  @*/
static int i386_entry2partition(disk_t *disk_car, const uint64_t offset, partition_t *partition, const struct partition_dos *p, const status_type_t status, const unsigned int order, const int verbose, const int saveheader);
static const char* errmsg_i386_entry2partition(const errcode_type_t errcode);

/*@
  @ requires \valid_read(partition);
  @ assigns \nothing;
  @*/
static const char *get_partition_typename_i386(const partition_t *partition);

/*@
  @ assigns \nothing;
  @*/
static const char *get_partition_typename_i386_aux(const unsigned int part_type_i386);

/*@
  @ requires \valid_read(partition);
  @ assigns \nothing;
  @*/
static unsigned int get_part_type_i386(const partition_t *partition);

/*@
  @ requires \valid_read(disk_car);
  @ assigns \nothing;
  @*/
static uint64_t C_H_S2offset(const disk_t *disk_car, const unsigned int C, const unsigned int H, const unsigned int S);

static const struct systypes i386_sys_types[] = {
  {P_NO_OS,		"No partition"},
  {P_12FAT,		"FAT12"},
  {0x02,		"XENIX root"},
  {0x03,		"XENIX /usr"},
  {P_16FAT,		"FAT16 <32M"},
  {P_EXTENDED,		"extended"},
  {P_16FATBD,		"FAT16 >32M"},
  {P_NTFS,		"HPFS - NTFS"},
  {0x09,		"AIX data"},
  {P_OS2MB,		"OS/2 Boot Manager"},
  {P_32FAT,		"FAT32"},
  {P_32FAT_LBA,		"FAT32 LBA"},
  {P_16FATBD_LBA,	"FAT16 LBA"},
  {P_EXTENDX,		"extended LBA"},
  {0x10,		"OPUS"},
  {P_12FATH,		"hid. FAT12"},
  {0x12,		"Compaq Diagnostics"},
  {P_16FATH,		"hid. FAT16 <32M"},
  {P_16FATBDH,		"hid. FAT16 >32M"},
  {P_NTFSH,		"hid. HPFS/NTFS"},
  {0x18,		"AST swap"},
  {0x19,		"Willowtech Photon"},
  {P_32FATH,		"hid. FAT32"},
  {P_32FAT_LBAH,	"hid. FAT32 LBA"},
  {P_16FATBD_LBAH,	"hid. FAT16 LBA"},
  {0x20,		"Willowsoft OFS1"},
  {0x24,		"NEC MS-DOS 3.x"},
  {0x27,		"Windows RE(store)"},
  {0x38,		"Theos"},
  {0x3c,		"PMagic recovery"},
  {0x40,		"VENIX 80286"},
  {0x41,		"PPC PReP Boot"},
  {0x42,		"W2K Dynamic/SFS"},
  {0x50,		"OnTrack DM RO"},
  {0x51,		"OnTrack DM RW-NOVEL"},
  {0x52,		"CP/M-Microport V/386"},
  {0x53,		"OnTrack DM WO ???"},
  {0x54,		"OnTrack DM DDO"},
  {0x55,		"EZ-Drive"},
  {0x56,		"GoldenBow VFeature"},
  {0x61,		"SpeedStor"},
  {P_SYSV,		"Unixware, HURD, SCO"},
  {0x64,		"NetWare 286"},
  {P_NETWARE,		"NetWare 3.11+"},
  {0x67,		"Novell"},
  {0x68,		"Novell"},
  {0x69,		"Novell"},
  {0x70,		"DiskSecure MB"},
  {0x75,		"PC/IX"},
  {0x80,		"Minix v1.1-1.4a"},
  {P_OLDLINUX,		"Minix / old Linux"},
  {P_LINSWAP,		"Linux Swap"},
  {P_LINUX,		"Linux"},
  {P_LINUXEXTENDX,	"Linux extended"},
  {0x86,		"NT FAT16 V/S set"},
  {0x87,		"HPFS FT mirror-V/S set"},
  {P_LVM,		"Linux LVM"},
  {0x93,		"Amoeba"},
  {0x94,		"Amoeba bad block"},
  {0xa0,		"NoteBIOS save2disk"},
  {P_FREEBSD,		"FreeBSD"},
  {P_OPENBSD,		"OpenBSD"},
  {0xa8,		"Darwin UFS"},
  {P_NETBSD,		"NetBSD"},
  {0xab,		"Darwin boot"},
  {P_HFS,		"HFS"},
  {0xb7,		"BSDI"},
  {0xb8,		"BSDI swap"},
  {0xbc,		"Acronis"},
  {0xbe,		"Solaris boot"},
  {P_SUN,		"Solaris"},
  {0xc1,		"secured FAT12"},
  {0xc4,		"secured FAT16"},
  {0xc6,		"sec. Huge-bad FAT16"},
  {0xc7,		"Syrinx Boot-bad NTFS"},
  {0xd8,		"CP/M-86"},
  {0xdb,		"CP/M"},
  {0xde,		"Dell Utility"},
  {0xe1,		"SpeedStor FAT12 ext"},
  {0xe3,		"DOS RO"},
  {0xe4,		"SpeedStor FAT16 ext"},
  {0xea,		"Boot (BLS)"},
  {P_BEOS,		"BeFS"},
  {0xee,		"EFI GPT"},          /* Intel EFI GUID Partition Table */
  {0xef,		"EFI (FAT-12/16/32)"},/* Intel EFI System Partition */
  {0xf0,		"Linux/PA-RISC boot"},/* Linux/PA-RISC boot loader */
  {0xf1,		"Storage Dimensions"},
  {0xf2,		"DOS secondary"},
  {0xf4,		"SpeedStor"},
  {P_VMFS,		"VMFS"},
  {P_RAID,		"Linux RAID"},
  {0xfe,		"LANstep"},
  {0xff,		"Xenix bad block"},
  {P_NO_OS,		NULL }
};

arch_fnct_t arch_i386= {
  .part_name="Intel",
  .part_name_option="partition_i386",
  .msg_part_type="*=Primary bootable  P=Primary  L=Logical  E=Extended  D=Deleted",
  .read_part=&read_part_i386,
  .write_part=&write_part_i386,
  .init_part_order=&init_part_order_i386,
  .get_geometry_from_mbr=&get_geometry_from_i386mbr,
  .check_part=&check_part_i386,
  .write_MBR_code=&write_MBR_code_i386,
  .set_prev_status=&set_prev_status_i386,
  .set_next_status=&set_next_status_i386,
  .test_structure=&test_structure_i386,
  .get_part_type=&get_part_type_i386,
  .set_part_type=&set_part_type_i386,
  .init_structure=&init_structure_i386,
  .erase_list_part=&erase_list_part_i386,
  .get_partition_typename=&get_partition_typename_i386,
  .is_part_known=&is_part_known_i386
};

static uint64_t C_H_S2offset(const disk_t *disk_car,const unsigned int C, const unsigned int H, const unsigned int S)
{
  return (((uint64_t)C * disk_car->geom.heads_per_cylinder + H) *
      disk_car->geom.sectors_per_head + S - 1) * disk_car->sector_size;
}

static unsigned int get_part_type_i386(const partition_t *partition)
{
  return partition->part_type_i386;
}

/*@
  @ requires \valid(cp);
  @ assigns  cp[0 .. 3];
  @*/
static void store4_little_endian(unsigned char *cp, unsigned int val)
{
  cp[0] = (val & 0xff);
  cp[1] = ((val >> 8) & 0xff);
  cp[2] = ((val >> 16) & 0xff);
  cp[3] = ((val >> 24) & 0xff);
}

/*@
  @ requires \valid_read(cp);
  @ assigns  \nothing;
  @*/
static unsigned int read4_little_endian(const unsigned char *cp)
{
  return (unsigned int)(cp[0]) + ((unsigned int)(cp[1]) << 8) + ((unsigned int)(cp[2]) << 16) + ((unsigned int)(cp[3]) << 24);
}

/*@
  @ requires \valid_read(p);
  @ assigns \nothing;
  @*/
static uint64_t get_start_sect(const struct partition_dos *p)
{
  return read4_little_endian(p->start4);
}

/*@
  @ requires \valid_read(p);
  @ assigns \nothing;
  @*/
static uint64_t get_nr_sects(const struct partition_dos *p)
{
  return read4_little_endian(p->size4);
}

/*@
  @ requires \valid(p);
  @ assigns p->size4[0 .. 3];
  @*/
static void set_nr_sects(struct partition_dos *p, unsigned int nr_sects)
{
  store4_little_endian(p->size4, nr_sects);
}

/*@
  @ requires \valid(p);
  @ assigns p->start4[0 .. 3];
  @*/
static void set_start_sect(struct partition_dos *p, unsigned int start_sect)
{
  store4_little_endian(p->start4, start_sect);
}

static int get_geometry_from_i386mbr(const unsigned char *buffer, const int verbose, CHSgeometry_t *geometry)
{
  unsigned int i;
#ifndef DISABLED_FOR_FRAMAC
  if(verbose>1)
  {
    log_trace("get_geometry_from_i386mbr\n");
  }
#endif
  if((buffer[0x1FE]!=(unsigned char)0x55)||(buffer[0x1FF]!=(unsigned char)0xAA))
  {
    return 1;
  }
  /*@ loop assigns i, geometry->cylinders, geometry->heads_per_cylinder, geometry->sectors_per_head; */
  for(i=0;i<4;i++)
  {
    const struct partition_dos *p=pt_offset_const(buffer,i);
    if(p->sys_ind!=0)
    {
      if(geometry->cylinders<e_cyl(p)+1)
	geometry->cylinders=e_cyl(p)+1;
      if(geometry->heads_per_cylinder < (unsigned int)p->end_head+1)
	geometry->heads_per_cylinder= (unsigned int)p->end_head+1;
      if(geometry->sectors_per_head<e_sect(p))
	geometry->sectors_per_head=e_sect(p);
    }
  }
  if(geometry->sectors_per_head==32 ||
      (geometry->sectors_per_head==63 &&
       ( geometry->heads_per_cylinder==16 ||
	 geometry->heads_per_cylinder==32 ||
	 geometry->heads_per_cylinder==64 ||
	 geometry->heads_per_cylinder==128 ||
	 geometry->heads_per_cylinder==240 ||
	 geometry->heads_per_cylinder==255)))
  {
#ifndef DISABLED_FOR_FRAMAC
    log_info("Geometry from i386 MBR: head=%u sector=%u\n",
	geometry->heads_per_cylinder, geometry->sectors_per_head);
#endif
  }
  else
  {
#ifndef DISABLED_FOR_FRAMAC
    if(geometry->sectors_per_head>0)
      log_warning("Geometry from i386 MBR: head=%u sector=%u\n",geometry->heads_per_cylinder, geometry->sectors_per_head);
#endif
    /* Don't trust the geometry */
    geometry->cylinders=0;
    geometry->heads_per_cylinder=0;
    geometry->sectors_per_head=0;
  }
  return 0;
}

static list_part_t *init_part_order_i386(const disk_t *disk_car, list_part_t *list_part)
{
  int nbr_log=0;
  int nbr_prim=0;
  list_part_t *element;
  for(element=list_part;element!=NULL;element=element->next)
  {
    switch(element->part->status)
    {
      case STATUS_PRIM:
      case STATUS_PRIM_BOOT:
      case STATUS_EXT:
	element->part->order=++nbr_prim;
	break;
      case STATUS_LOG:
	element->part->order=(++nbr_log)+4;
	break;
      default:
	log_critical("init_part_order_i386: severe error\n");
	break;
    }
  }
  return list_part;
}


static list_part_t *read_part_i386(disk_t *disk_car, const int verbose, const int saveheader)
{
  unsigned int i;
  CHSgeometry_t geometry;
  list_part_t *new_list_part=NULL;
  unsigned char *buffer=(unsigned char *)MALLOC(disk_car->sector_size);
  /*@ assert valid_list_part(new_list_part); */
  screen_buffer_reset();
  if((unsigned)disk_car->pread(disk_car, buffer, disk_car->sector_size, (uint64_t)0) != disk_car->sector_size)
  {
    screen_buffer_add( msg_PART_RD_ERR);
    free(buffer);
    return NULL;
  }
  geometry.cylinders=0;
  geometry.heads_per_cylinder=0;
  geometry.sectors_per_head=0;
  if(get_geometry_from_i386mbr(buffer,verbose,&geometry)!=0)
  {
    screen_buffer_add(msg_TBL_NMARK);
    free(buffer);
    return NULL;
  }
  /*@
    @ loop invariant valid_list_part(new_list_part);
    @*/
  for(i=0;i<4;i++)
  {
    const struct partition_dos *p=pt_offset(buffer,i);
    status_type_t status;
    switch(p->sys_ind)
    {
      case P_EXTENDX:
      case P_EXTENDED:
      case P_LINUXEXTENDX:
	status=STATUS_EXT;
	break;
      default:
	status=STATUS_PRIM;
	break;
    }
    if(p->sys_ind != P_NO_OS)
    {
      int insert_error=0;
      partition_t *new_partition=partition_new(&arch_i386);
      i386_entry2partition(disk_car, (uint64_t)0, new_partition, p, status,i+1,verbose,saveheader);
      if(verbose>1)
	log_dos_entry(p);
      aff_part_buffer(AFF_PART_ORDER|AFF_PART_STATUS,disk_car,new_partition);
      if(new_partition->errcode!=BAD_NOERR)
      {
	screen_buffer_add("%s\n",errmsg_i386_entry2partition(new_partition->errcode));
      }
      new_list_part=insert_new_partition(new_list_part,new_partition, 0, &insert_error);
      if(insert_error>0)
	free(new_partition);
    }
  }
  test_MBR_data(new_list_part);
  test_MBR_over(disk_car,new_list_part);
  new_list_part=get_ext_data_i386(disk_car,new_list_part,verbose,saveheader);
  get_geometry_from_list_part(disk_car, new_list_part, verbose);
  free(buffer);
  return new_list_part;
}

static void test_MBR_data(const list_part_t *list_part)
{
  const list_part_t *element;
  unsigned int nb_dos=0, nb_hidden=0, nb_mb=0, nb_ext=0, nb_boot=0;
  for(element=list_part;element!=NULL;element=element->next)
  {
    const partition_t *partition=element->part;
    switch(partition->status)
    {
      case STATUS_PRIM:
      case STATUS_PRIM_BOOT:
	if(partition->status == STATUS_PRIM_BOOT)
	  nb_boot++;
	switch(partition->part_type_i386)
	{
	  case P_12FAT:
	  case P_16FAT:
	  case P_16FATBD:
	    nb_dos++;
	    break;
	  case P_16FATBDH:
	  case P_16FATH:
	  case P_NTFSH:
	    nb_hidden++;
	    break;
	  case P_OS2MB:
	    nb_mb++;
	    break;
	}
	break;
      case STATUS_EXT:
	nb_ext++;
	break;
      default:
	log_critical("test_MBR_data: severe error\n");
	break;
    }
  }
  if(nb_dos>1)
    screen_buffer_add(msg_ONLY_ONE_DOS);
  if(nb_ext>1)
    screen_buffer_add(msg_ONLY_ONE_EXT);
  /* S'il y a des partitions caches, il faut un MB */
  /* Obsolete
  if(nb_hidden>0 && nb_mb==0)
    screen_buffer_add(msg_NO_OS2MB);
    */
  /* Nombre de partition bootable */
  if(nb_boot==0)
    screen_buffer_add(msg_NO_BOOTABLE);
  else
    if(nb_boot>1)
      screen_buffer_add(msg_ONLY1MUSTBOOT);
}

static partition_t *get_ext_partition_i386(const list_part_t *list_part)
{
  const list_part_t *element;
  for(element=list_part; element!=NULL; element=element->next)
  {
    if(element->part->status==STATUS_EXT)
      return element->part;
  }
  return NULL;
}

static list_part_t *get_ext_data_i386(disk_t *disk_car, list_part_t *list_part, const int verbose, const int saveheader)
{
  partition_t *partition_main_ext;
  partition_t *partition_ext;
  partition_t *partition_next_ext;
  unsigned int order=5;
  unsigned int nbr_part=0;
  if((partition_main_ext=get_ext_partition_i386(list_part))==NULL)
    return list_part;
  for(partition_ext=partition_main_ext;
      partition_ext!=NULL && nbr_part<32;
      partition_ext=partition_next_ext)
  {
    unsigned char buffer[DEFAULT_SECTOR_SIZE];
    int nb_hidden=0, nb_mb=0, nb_part=0, nb_ext=0, nb_boot=0;
    unsigned int i;
    partition_next_ext=NULL;
    if(partition_ext->part_offset==0)
      return list_part;
    if(disk_car->pread(disk_car, &buffer, sizeof(buffer), partition_ext->part_offset) != sizeof(buffer))
      return list_part;
    if((buffer[0x1FE]!=(unsigned char)0x55)||(buffer[0x1FF]!=(unsigned char)0xAA))
    {
      screen_buffer_add("\ntest_logical: " msg_TBL_NMARK);
      return list_part;
    }
    for(i=0;i<4;i++)
    {
      const struct partition_dos *p=pt_offset(buffer,i);
      if(p->boot_ind==(unsigned char)0x80)
	nb_boot++;
      switch(p->sys_ind)
      {
	case P_16FATBDH:
	case P_16FATH:
	case P_NTFSH:
	  nb_hidden++;
	  break;
	case P_OS2MB:
	  nb_mb++;
	  break;
	case P_EXTENDX:
	case P_EXTENDED:
	case P_LINUXEXTENDX:
	  nb_ext++;
	  break;
	case P_NO_OS:
	  break;
	default:
	  nb_part++;
      }
    }
    if(nb_hidden>0)
      screen_buffer_add("Partition must not be hidden\n");
    if(nb_mb>0)
      screen_buffer_add("Multiboot must be a primary partition, not a logical\n");
    if(nb_ext>1)
      screen_buffer_add("A logical partition must not have more than one link to another logical partition\n");
    if(nb_part>1)
      screen_buffer_add("A logical partition must contain only one partition\n");
    if(nb_boot>0)
      screen_buffer_add("Logical partition must not be bootable\n");
    for(i=0;i<4;i++)
    {
      const struct partition_dos *p=pt_offset(buffer,i);
      if(p->sys_ind!=0)
      {
	int insert_error=0;
	partition_t *new_partition=partition_new(&arch_i386);
	new_partition->order=order;
	if(verbose>1)
	  log_dos_entry(p);
	if(is_extended(p->sys_ind))
	{
	  i386_entry2partition(disk_car, partition_main_ext->part_offset, new_partition, p, STATUS_EXT_IN_EXT,order,verbose,saveheader);
	  aff_part_buffer(AFF_PART_ORDER|AFF_PART_STATUS,disk_car,new_partition);
	  if(new_partition->errcode!=BAD_NOERR)
	  {
	    screen_buffer_add("%s\n",errmsg_i386_entry2partition(new_partition->errcode));
	  }
	  {
	    if((new_partition->part_offset<=partition_main_ext->part_offset) ||
		(new_partition->part_offset+new_partition->part_size-1 > partition_main_ext->part_offset+partition_main_ext->part_size-1))
	    {	/* Must be IN partition_main_ext */
	      screen_buffer_add("Must be in extended partition\n");
	      aff_part_buffer(AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition_main_ext);
	      aff_part_buffer(AFF_PART_ORDER|AFF_PART_STATUS,disk_car,new_partition);
	    }
	    else
	    {
	      list_part_t *element;
	      for(element=list_part;element!=NULL;element=element->next)
	      {
		partition_t *partition=element->part;
		if(partition->status==STATUS_EXT_IN_EXT)
		{
		  if(((partition->part_offset>=new_partition->part_offset) && (partition->part_offset<=new_partition->part_offset+new_partition->part_size-1)) ||
		      ((partition->part_offset+partition->part_size-1>=new_partition->part_offset) && (partition->part_offset+partition->part_size-1<=new_partition->part_offset+partition->part_size-1)))
		  { /* New Partition start or end mustn't been in partition */
		    screen_buffer_add( "Logical partition must be in its own extended partition\n");
		    aff_part_buffer(AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition);
		    aff_part_buffer(AFF_PART_ORDER|AFF_PART_STATUS,disk_car,new_partition);
		  }
		}
	      }
	    }
	  }
	}
	else
	{
	  i386_entry2partition(disk_car,partition_ext->part_offset, new_partition, p, STATUS_LOG,order,verbose,saveheader);
	  order++;
	  if(verbose>1)
	    log_dos_entry(p);
	  aff_part_buffer(AFF_PART_ORDER|AFF_PART_STATUS,disk_car,new_partition);
	  if(new_partition->errcode!=BAD_NOERR)
	  {
	    screen_buffer_add("%s\n",errmsg_i386_entry2partition(new_partition->errcode));
	  }
	  {
	    if((new_partition->part_offset<=partition_main_ext->part_offset) ||
		(new_partition->part_offset+new_partition->part_size-1 > partition_main_ext->part_offset+partition_main_ext->part_size-1))
	    {	/* Must be IN partition_main_ext */
	      screen_buffer_add( msg_SAME_SPACE);
	      aff_part_buffer(AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition_main_ext);
	      aff_part_buffer(AFF_PART_ORDER|AFF_PART_STATUS,disk_car,new_partition);
	    }
	  }
	}
	list_part=insert_new_partition(list_part, new_partition, 0, &insert_error);
	if(insert_error>0)
	  free(new_partition);
	else
	{
	  nbr_part++;
	  if(is_extended(p->sys_ind))
	    partition_next_ext=new_partition;
	}
      }
    }
  }
  return list_part;
}

int recover_i386_logical(disk_t *disk, const unsigned char *buffer, partition_t *partition)
{
  const struct partition_dos *p=pt_offset_const(buffer,0);
  if(partition->arch!=&arch_i386)
    return 1;
  if(is_extended(p->sys_ind))
    p=pt_offset_const(buffer,1);
  switch(p->sys_ind)
  {
    case P_12FAT:
    case P_16FAT:
    case P_16FATBD:
    case P_16FATBD_LBA:
    case P_NTFS:
    case P_32FAT:
    case P_32FAT_LBA:
      break;
    default:
      return 1;
  }
  if(partition->part_offset==0)
    return 1;
  i386_entry2partition(disk, partition->part_offset, partition, p, STATUS_DELETED, 0, 0, 0);
  partition->order=NO_ORDER;
  return 0;
}

static int test_MBR_over(const disk_t *disk_car, const list_part_t *list_part)
{/* Test if partitions overlap */
  int res=0;
  const list_part_t *element;
  for(element=list_part;element!=NULL;element=element->next)
    if(element->next!=NULL &&
	element->part->part_offset + element->part->part_size - 1 >= element->next->part->part_offset)
    {
      res=1;
      screen_buffer_add( msg_SAME_SPACE);
      aff_part_buffer(AFF_PART_ORDER|AFF_PART_STATUS,disk_car,element->part);
      aff_part_buffer(AFF_PART_ORDER|AFF_PART_STATUS,disk_car,element->next->part);
    }
  return res;
}

static int write_part_i386(disk_t *disk_car, const list_part_t *list_part, const int ro, const int verbose)
{
  int res=0;
  res+=write_mbr_i386(disk_car,list_part,ro,verbose);
  res+=write_all_log_i386(disk_car,list_part,ro,verbose);
  disk_car->sync(disk_car);
  return res;
}

static int write_mbr_i386(disk_t *disk_car, const list_part_t *list_part, const int ro, const int verbose)
{
  const list_part_t *element;
  unsigned char *buffer;
  unsigned char *buffer_org;
  if(disk_car->sector_size < DEFAULT_SECTOR_SIZE)
    return 0;
  buffer=(unsigned char *)MALLOC(disk_car->sector_size);
  buffer_org=(unsigned char *)MALLOC(disk_car->sector_size);
  if(verbose>0)
  {
    log_trace("\nwrite_mbr_i386: starting...\n");
  }
  if(disk_car->pread(disk_car, buffer_org, DEFAULT_SECTOR_SIZE, (uint64_t)0) != DEFAULT_SECTOR_SIZE)
  {
    log_error(msg_PART_RD_ERR);
    memset(buffer_org,0,DEFAULT_SECTOR_SIZE);
  }
  memset(buffer,0,DEFAULT_SECTOR_SIZE);
  if((buffer_org[0x1FE]==0x55) && (buffer_org[0x1FF]==0xAA))
  {
    memcpy(buffer,buffer_org,TAB_PART);
    buffer[0x1FE]=0x55;
    buffer[0x1FF]=0xAA;
  } else {
    if(verbose>0)
      log_info("Store new MBR code\n");
    write_MBR_code_i386_aux(buffer);
  }
  /* Remove Mac signature */
  if(buffer[0]==0x45 && buffer[1]==0x52)
    buffer[0]=0;
  /* Remove Sun signature */
  if(buffer[0x1fc]==0xda && buffer[0x1fd]==0xbe)
    buffer[0x1fc]=0;
  for(element=list_part;element!=NULL;element=element->next)
  {
    switch(element->part->status)
    {
      case STATUS_PRIM:
      case STATUS_PRIM_BOOT:
      case STATUS_EXT:
	if((element->part->order>=1) && (element->part->order<=4))
	{
	  partition2_i386_entry(disk_car,(uint64_t)0,element->part, 
	      pt_offset(buffer,element->part->order-1));
	}
	break;
      case STATUS_LOG:
	break;
      default:
	log_critical("write_mbr_i386: severe error\n");
	break;
    }
  }
  if(verbose>1)
  {
    int i;
    for(i=0;i<4;i++)
    {
      const struct partition_dos *p=pt_offset(buffer,i);
      log_dos_entry(p);
    }
    diff(buffer, buffer_org);
  }
  if(ro==0)
  {
    if(disk_car->pwrite(disk_car, buffer, DEFAULT_SECTOR_SIZE, (uint64_t)0) != DEFAULT_SECTOR_SIZE)
    {
      free(buffer_org);
      free(buffer);
      return 1;
    }
  }
  free(buffer_org);
  free(buffer);
  return 0;
}

static int write_all_log_i386(disk_t *disk_car, const list_part_t *list_part, const int ro, const int verbose)
{
  const list_part_t *element;
  const list_part_t *pos_ext=NULL;
  uint64_t current_pos;
  partition_t *bloc_nextext;
  int res=0;
  if(verbose>0)
    log_trace("write_all_log_i386: starting...\n");
  for(element=list_part;element!=NULL;element=element->next)
  {
    if(element->part->status==STATUS_EXT)
    {
      if(is_extended(element->part->part_type_i386))
      {
        if(pos_ext!=NULL)
          log_critical("write_all_log_i386: pos_ext already defined\n");
        pos_ext=element;
      }
      else
      {
        log_critical("write_all_log_i386: STATUS_EXT with bad part_type\n");
      }
    }
  }
  if(pos_ext==NULL)
  {
    log_info(msg_NO_EXT_PART);
    return 0;
  }
  current_pos=pos_ext->part->part_offset;
  bloc_nextext=(partition_t *)MALLOC(sizeof(*bloc_nextext));
  bloc_nextext->part_type_i386=P_EXTENDED;       /* Never P_EXTENDX */
  if(pos_ext->next==NULL || (pos_ext->next->part->status!=STATUS_LOG))
  {
    unsigned char buffer[DEFAULT_SECTOR_SIZE];
    unsigned char buffer_org[DEFAULT_SECTOR_SIZE];
    if(verbose>0)
    {
      log_info("write_all_log_i386: CHS: %u/%u/%u,lba=%lu\n", offset2cylinder(disk_car,current_pos), offset2head(disk_car,current_pos), offset2sector(disk_car,current_pos),(long unsigned)(current_pos/disk_car->sector_size));
    }
    if(disk_car->pread(disk_car, &buffer_org, sizeof(buffer_org), current_pos) != sizeof(buffer_org))
    {
      memset(buffer_org,0,DEFAULT_SECTOR_SIZE);
    }
    memset(buffer,0,DEFAULT_SECTOR_SIZE);
    memcpy(buffer,buffer_org,TAB_PART);
    buffer[0x1FE]=0x55;
    buffer[0x1FF]=0xAA;
    if(ro)
    {
      if(verbose>1)
        diff(buffer, buffer_org);
    }
    else
    {
      if(disk_car->pwrite(disk_car, &buffer, sizeof(buffer), current_pos) != sizeof(buffer))
      {
        res=1;
      }
    }
  }
  else
  {
    for(element=pos_ext->next;(element!=NULL) && (element->part->status==STATUS_LOG);element=element->next)
    {
      unsigned char buffer[DEFAULT_SECTOR_SIZE];
      unsigned char buffer_org[DEFAULT_SECTOR_SIZE];
      if(verbose>0)
      {
        log_info("write_all_log_i386: CHS: %u/%u/%u,lba=%lu\n", offset2cylinder(disk_car,current_pos), offset2head(disk_car,current_pos), offset2sector(disk_car,current_pos),(long unsigned)(current_pos/disk_car->sector_size));
      }
      if(disk_car->pread(disk_car, &buffer_org, sizeof(buffer_org), current_pos) != sizeof(buffer_org))
      {
        memset(buffer_org,0,DEFAULT_SECTOR_SIZE);
      }
      memset(buffer,0,DEFAULT_SECTOR_SIZE);
      memcpy(buffer,buffer_org,TAB_PART);
      buffer[0x1FE]=0x55;
      buffer[0x1FF]=0xAA;
      partition2_i386_entry(disk_car,current_pos,element->part, pt_offset(buffer,0));
      if(element->next!=NULL && (element->next->part->status==STATUS_LOG))
      { /* Construit le pointeur vers la prochaine partition logique */
        CHS_t nextext_start;
        bloc_nextext->part_offset=element->next->part->part_offset-disk_car->sector_size;
        offset2CHS(disk_car,bloc_nextext->part_offset,&nextext_start);
        if(nextext_start.sector!=disk_car->geom.sectors_per_head)
        {
          if(nextext_start.head>0)
            nextext_start.head--;
          else
          {
            nextext_start.head=disk_car->geom.heads_per_cylinder-1;
            nextext_start.cylinder--;
          }
        }
        nextext_start.sector=1;
        if(verbose>1)
          log_verbose("nextext_start %lu/%u/%u %lu ? %lu\n", nextext_start.cylinder,nextext_start.head,nextext_start.sector,
              (long unsigned)(CHS2offset(disk_car,&nextext_start)/disk_car->sector_size),
              (long unsigned)((element->part->part_offset+element->part->part_size-1)/disk_car->sector_size));
        if(CHS2offset(disk_car,&nextext_start)<=element->part->part_offset+element->part->part_size-1)
        {
          offset2CHS(disk_car,bloc_nextext->part_offset,&nextext_start);
          nextext_start.sector=1;
          if(verbose>1)
            log_verbose("nextext_start %lu/%u/%u %lu ? %lu\n", nextext_start.cylinder,nextext_start.head,nextext_start.sector,
                (long unsigned)(CHS2offset(disk_car,&nextext_start)/disk_car->sector_size),
                (long unsigned)((element->part->part_offset+element->part->part_size-1)/disk_car->sector_size));
          if(CHS2offset(disk_car,&nextext_start)<=element->part->part_offset+element->part->part_size-1)
          {
            offset2CHS(disk_car,bloc_nextext->part_offset,&nextext_start);
          }
        }
        if(verbose>1)
          log_verbose("nextext_start %lu/%u/%u %lu ? %lu\n", nextext_start.cylinder,nextext_start.head,nextext_start.sector,
              (long unsigned)(CHS2offset(disk_car,&nextext_start)/disk_car->sector_size),
              (long unsigned)((element->part->part_offset+element->part->part_size-1)/disk_car->sector_size));
        bloc_nextext->part_offset=CHS2offset(disk_car,&nextext_start);
        /*      log_debug("table[i]->next=%p table[i+1]=%p\n",table[i]->next,table[i+1]); */
        bloc_nextext->part_size=(uint64_t)element->next->part->part_offset+element->next->part->part_size-bloc_nextext->part_offset;
        partition2_i386_entry(disk_car,pos_ext->part->part_offset,bloc_nextext, pt_offset(buffer,1));
      }
      if(ro)
      {
        if(verbose>1)
        {
	  int j;
          for(j=0;j<4;j++)
          {
            const struct partition_dos *p=pt_offset(buffer,j);
            if(p->sys_ind!=0)
              log_dos_entry(p);
          }
          diff(buffer, buffer_org);
        }
      }
      else
      {
        if(disk_car->pwrite(disk_car, &buffer, sizeof(buffer), current_pos) != sizeof(buffer))
        {
          res=1;
        }
      }
      current_pos=bloc_nextext->part_offset;
    }
  }
  free(bloc_nextext);
  return res;
}

static int diff(const unsigned char buffer[DEFAULT_SECTOR_SIZE], const unsigned char buffer_org[DEFAULT_SECTOR_SIZE])
{
  if(memcmp(buffer,buffer_org,DEFAULT_SECTOR_SIZE))
  {
    unsigned int j;
    log_info("\nSectors are different.\n");
    log_info("buffer_org\n");
    for(j=0;j<4;j++)
    {
      const struct partition_dos *p=pt_offset_const(buffer_org,j);
      if(p->sys_ind!=0)
	log_dos_entry(p);
    }
    log_info("buffer\n");
    for(j=0;j<4;j++)
    {
      const struct partition_dos *p=pt_offset_const(buffer,j);
      if(p->sys_ind!=0)
	log_dos_entry(p);
    }
    for(j=0;j<DEFAULT_SECTOR_SIZE;j++)
      if(buffer_org[j]!=buffer[j])
	log_info("%02X %02X %02X\n", j, buffer_org[j], buffer[j]);
    log_info("\n");
  }
  return 0;
}

static int write_MBR_code_i386(disk_t *disk_car)
{
  unsigned char buffer[DEFAULT_SECTOR_SIZE];
  if(disk_car->pread(disk_car, buffer, DEFAULT_SECTOR_SIZE, (uint64_t)0) != DEFAULT_SECTOR_SIZE)
  {
    log_error(msg_PART_RD_ERR);
    memset(buffer,0,sizeof(buffer));
  }
  write_MBR_code_i386_aux(buffer);
  if(disk_car->pwrite(disk_car, buffer, DEFAULT_SECTOR_SIZE, (uint64_t)0) != DEFAULT_SECTOR_SIZE)
  {
    return 1;
  }
  disk_car->sync(disk_car);
  return 0;
}

static int write_MBR_code_i386_aux(unsigned char *buffer)
{
  /* od -t x1 -v testdisk.b
     Thanks to Neil Turton for writing it */
  const unsigned char mbr_code_testdisk[DEFAULT_SECTOR_SIZE]={
    0xfc, 0x31, 0xc0, 0x8e, 0xd0, 0x31, 0xe4, 0x8e, 0xd8, 0x8e, 0xc0, 0xbe, 0x00, 0x7c, 0xbf, 0x00,
    0x06, 0xb9, 0x00, 0x01, 0xf3, 0xa5, 0xbe, 0xee, 0x07, 0xb0, 0x08, 0xea, 0x20, 0x06, 0x00, 0x00,
    0x80, 0x3e, 0xb3, 0x07, 0xff, 0x75, 0x04, 0x88, 0x16, 0xb3, 0x07, 0x80, 0x3c, 0x00, 0x74, 0x04,
    0x08, 0x06, 0xaf, 0x07, 0x83, 0xee, 0x10, 0xd0, 0xe8, 0x73, 0xf0, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xbe, 0xbe,
    0x07, 0xb0, 0x00, 0xb9, 0x04, 0x00, 0x80, 0x3c, 0x00, 0x75, 0x6e, 0xfe, 0xc0, 0x83, 0xc6, 0x10,
    0xe2, 0xf4, 0x31, 0xdb, 0xb4, 0x0e, 0xbe, 0x9d, 0x07, 0x8a, 0x0e, 0xaf, 0x07, 0xac, 0xd0, 0xe9,
    0x73, 0x02, 0xcd, 0x10, 0x08, 0xc9, 0x75, 0xf5, 0xb0, 0x3a, 0xcd, 0x10, 0x31, 0xc0, 0xcd, 0x16,
    0x3c, 0x00, 0x74, 0xf8, 0xbe, 0x8b, 0x07, 0xb9, 0x02, 0x00, 0xe8, 0xba, 0x00, 0x3c, 0x0d, 0x74,
    0xb4, 0x3c, 0x61, 0x72, 0x06, 0x3c, 0x7a, 0x77, 0x02, 0x2c, 0x20, 0x88, 0xc3, 0xbe, 0x9d, 0x07,
    0x8a, 0x0e, 0xaf, 0x07, 0xac, 0xd0, 0xe9, 0x73, 0x04, 0x38, 0xc3, 0x74, 0x06, 0x08, 0xc9, 0x75,
    0xf3, 0xeb, 0xaf, 0xb8, 0x0d, 0x0e, 0x31, 0xdb, 0xcd, 0x10, 0x8d, 0x84, 0x62, 0x00, 0x3c, 0x07,
    0x75, 0x07, 0xb0, 0x1f, 0xa2, 0xaf, 0x07, 0xeb, 0x99, 0x31, 0xd2, 0xb9, 0x01, 0x00, 0x3c, 0x04,
    0x74, 0x11, 0x73, 0xf3, 0x30, 0xe4, 0xb1, 0x04, 0xd2, 0xe0, 0xbe, 0xbe, 0x07, 0x01, 0xc6, 0x8a,
    0x16, 0xb3, 0x07, 0xbf, 0x05, 0x00, 0x56, 0xf6, 0xc2, 0x80, 0x74, 0x31, 0xb4, 0x41, 0xbb, 0xaa,
    0x55, 0x52, 0xcd, 0x13, 0x5a, 0x5e, 0x56, 0x72, 0x1e, 0x81, 0xfb, 0x55, 0xaa, 0x75, 0x18, 0xf6,
    0xc1, 0x01, 0x74, 0x13, 0x8b, 0x44, 0x08, 0x8b, 0x5c, 0x0a, 0xbe, 0x8d, 0x07, 0x89, 0x44, 0x08,
    0x89, 0x5c, 0x0a, 0xb4, 0x42, 0xeb, 0x0c, 0x8a, 0x74, 0x01, 0x8b, 0x4c, 0x02, 0xb8, 0x01, 0x02,
    0xbb, 0x00, 0x7c, 0x50, 0xc6, 0x06, 0x8f, 0x07, 0x01, 0xcd, 0x13, 0x58, 0x5e, 0x73, 0x05, 0x4f,
    0x75, 0xb4, 0xeb, 0x93, 0x81, 0x3e, 0xfe, 0x7d, 0x55, 0xaa, 0x75, 0xf6, 0xea, 0x00, 0x7c, 0x00,
    0x00, 0xbe, 0x83, 0x07, 0xb9, 0x0a, 0x00, 0x50, 0xb4, 0x0e, 0x31, 0xdb, 0xac, 0xcd, 0x10, 0xe2,
    0xfb, 0x58, 0xc3,  'T',  'e',  's',  't',  'D',  'i',  's',  'k', 0x0d, 0x0a, 0x10, 0x00, 0x01,
    0x00, 0x00, 0x7c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  '1',  '2',  '3',
     '4',  'F', 0x00, 0x00, 0x41,  'N',  'D',  'T',  'm',  'b',  'r', 0x00, 0x02, 0x02, 0x02, 0x1f,
    0xc7, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa5, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0xaa
  };
  /* don't overwrite the disk signature at 0x1b8 */
  memcpy(buffer, &mbr_code_testdisk, 0x1b8);
  buffer[0x1FE]=(unsigned char)0x55;
  buffer[0x1FF]=(unsigned char)0xAA;
  return 0;
}

static void partition2_i386_entry(const disk_t *disk_car, const uint64_t pos, const partition_t *partition, struct partition_dos *p)
{
  CHS_t start,end;
  offset2CHS(disk_car,partition->part_offset,&start);
  offset2CHS(disk_car,partition->part_offset+partition->part_size-disk_car->sector_size,&end);
  if(partition->status==STATUS_PRIM_BOOT)
    p->boot_ind=0x80;
  else
    p->boot_ind=0;             /* Non bootable */
  p->sys_ind=partition->part_type_i386;
  if(((partition->part_offset-pos)/disk_car->sector_size)<=0xFFFFFFFF)
    set_start_sect(p,(partition->part_offset-pos)/disk_car->sector_size);
  else
    set_start_sect(p,0xFFFFFFFF);
  if(start.cylinder>1023)
  { /* Partition Magic 5 uses CHS=(1023,0,1) if extended or last logical *
     * Linux fdisk and TestDisk use CHS=(1023,lastH,lastS)               */
    p->head=(disk_car->geom.heads_per_cylinder-1)&0xff;
    p->sector=(disk_car->geom.sectors_per_head | ((1023>>8)<<6))&0xff;
    p->cyl=1023&0xff;
  }
  else
  {
    p->head=start.head&0xff;
    p->sector=(start.sector|((start.cylinder>>8)<<6))&0xff;
    p->cyl=start.cylinder&0xff;
  }
  if(end.cylinder>1023)
  {
    p->end_head=(disk_car->geom.heads_per_cylinder-1)&0xff;
    p->end_sector=(disk_car->geom.sectors_per_head | ((1023>>8)<<6))&0xff;
    p->end_cyl=1023&0xff;
  }
  else
  {
    p->end_head=end.head&0xff;
    p->end_sector=(end.sector|((end.cylinder>>8)<<6))&0xff;
    p->end_cyl=end.cylinder&0xff;
  }
  if((partition->part_size/disk_car->sector_size)<=0xFFFFFFFF)
    set_nr_sects(p,partition->part_size/disk_car->sector_size);
  else
    set_nr_sects(p,0xFFFFFFFF);
}

static int i386_entry2partition(disk_t *disk_car, const uint64_t offset, partition_t *partition, const struct partition_dos *p, const status_type_t status,const unsigned int order,const int verbose, const int saveheader)
{
  CHS_t start,end;
  CHS_t start_calculated,end_calculated;
  partition_reset(partition, &arch_i386);
  partition->part_type_i386=p->sys_ind;
  partition->part_offset=offset+(uint64_t)get_start_sect(p)*disk_car->sector_size;
  partition->order=order;
  partition->part_size=(uint64_t)get_nr_sects(p)*disk_car->sector_size;

  offset2CHS(disk_car,partition->part_offset,&start_calculated);
  offset2CHS(disk_car,partition->part_offset+partition->part_size-disk_car->sector_size,&end_calculated);


  start.cylinder=s_cyl(p);
  start.head=p->head;
  start.sector=s_sect(p);
  end.cylinder=e_cyl(p);
  end.head=p->end_head;
  end.sector=e_sect(p);
  switch(status)
  {
    case STATUS_PRIM:
      if(is_extended(partition->part_type_i386))
      {
	partition->status=STATUS_EXT;
	partition->upart_type=UP_EXTENDED;
      }
      else
	if(p->boot_ind!=0)
	  partition->status=STATUS_PRIM_BOOT;
	else
	  partition->status=status;
      break;
    default:
      partition->status=status;
      break;
  }
  /* Check CHS */
  if(start.sector==0 || start.sector > disk_car->geom.sectors_per_head)
  {
    if(partition->errcode==BAD_NOERR)
      partition->errcode=BAD_SS;
  }
  if(end.sector==0 || end.sector > disk_car->geom.sectors_per_head)
  {
    if(partition->errcode==BAD_NOERR)
      partition->errcode=BAD_ES;
  }
  if(start.head >= disk_car->geom.heads_per_cylinder)
  {
    if(partition->errcode==BAD_NOERR)
      partition->errcode=BAD_SH;
  }
  if(start.cylinder >= disk_car->geom.cylinders)
  {
    if(partition->errcode==BAD_NOERR)
      partition->errcode=BAD_SC;
  }
  if(end.head >= disk_car->geom.heads_per_cylinder)
  {
    if(partition->errcode==BAD_NOERR)
      partition->errcode=BAD_EH;
  }
  if(end.cylinder >= disk_car->geom.cylinders)
  {
    if(partition->errcode==BAD_NOERR)
      partition->errcode=BAD_EC;
  }
  if(((start_calculated.cylinder<=1023)&& (C_H_S2offset(disk_car,start.cylinder,start.head,start.sector)!=partition->part_offset))
    || ((start_calculated.cylinder>1023)&&(start.cylinder!=1023)&&(start.cylinder!=(start_calculated.cylinder&1023))))
  {
    log_error("BAD_RS LBA=%lu %lu\n",
	(long unsigned)(partition->part_offset/disk_car->sector_size),
	C_H_S2LBA(disk_car, start.cylinder, start.head, start.sector));
    if(partition->errcode==BAD_NOERR)
      partition->errcode=BAD_RS;
  }
  if(((end_calculated.cylinder<=1023)&& (C_H_S2offset(disk_car,end.cylinder,end.head,end.sector)!=partition->part_offset+partition->part_size-disk_car->sector_size))
     || ((end_calculated.cylinder>1023)&&(end.cylinder!=1023)&&(end.cylinder!=(end_calculated.cylinder&1023))))
  {
    if(partition->errcode==BAD_NOERR)
      partition->errcode=BAD_SCOUNT;
  }
  /* Check partition and load partition name */
  check_part_i386(disk_car,verbose,partition,saveheader);
  return 0;
}

static const char* errmsg_i386_entry2partition(const errcode_type_t errcode)
{
  switch(errcode)
  {
    case BAD_SS: return msg_BAD_S_SECT;
    case BAD_ES: return msg_BAD_E_SECT;
    case BAD_SH: return msg_BAD_S_HEAD;
    case BAD_EH: return msg_BAD_E_HEAD;
    case BAD_EBS: return msg_END_BFR_START;
    case BAD_RS: return msg_BAD_RS;
    case BAD_SC: return msg_BAD_S_CYL;
    case BAD_EC: return msg_BAD_E_CYL;
    case BAD_SCOUNT: return msg_BAD_SCOUNT;
    case BAD_NOERR: return "";
  }
  log_critical("errmsg_i386_entry2partition: unhandled error\n");
  return "";
}

static void log_dos_entry(const struct partition_dos *entree)
{
  if(get_partition_typename_i386_aux(entree->sys_ind)!=NULL)
    log_info(" %-20s ", get_partition_typename_i386_aux(entree->sys_ind));
  else
    log_info(" Sys=%02X               ", entree->sys_ind);
  log_info("%4u %3u %2u"
	 " %4u %3u %2u"
	 " %10lu"
	 " %10lu\n",
	  s_cyl(entree), entree->head, s_sect(entree),
	  e_cyl(entree), entree->end_head, e_sect(entree),
	  (long unsigned)get_start_sect(entree),(long unsigned)get_nr_sects(entree));
}

int parti386_can_be_ext(const disk_t *disk_car, const partition_t *partition)
{
  return((offset2head(disk_car,partition->part_offset)>0)&&
      (offset2cylinder(disk_car,partition->part_offset)!=0 ||
       offset2head(disk_car,partition->part_offset)!=1 ||
       offset2sector(disk_car,partition->part_offset)!=1));
}

static int test_structure_i386(const list_part_t *list_part)
{ /* Return 1 if bad*/
  int nbr_prim=0, nbr_prim_boot=0, nbr_log_block=0;
  const list_part_t *first_log=NULL;
  list_part_t *new_list_part=NULL;
  const list_part_t *element;
  int res;
  for(element=list_part;element!=NULL;element=element->next)
  {
    switch(element->part->status)
    {
      case STATUS_LOG:
	if(first_log==NULL)
	{
	  first_log=element;
	  nbr_log_block++;
	}
	if(is_extended(element->part->part_type_i386))
	{
          return 1;
	}
	break;
      case STATUS_PRIM_BOOT:
	if(nbr_prim_boot++)
	  return 1;
	nbr_prim++;
	first_log=NULL;
	break;
      case STATUS_PRIM:
	nbr_prim++;
	first_log=NULL;
	break;
      case STATUS_DELETED:
	break;
      default:
	log_critical("test_structure_i386: severe error\n");
	break;
    }
  }
  if(nbr_log_block>1 || nbr_log_block+nbr_prim>4)
    return 1;
  new_list_part=gen_sorted_partition_list(list_part);
  res=is_part_overlapping(new_list_part);
  part_free_list_only(new_list_part);
  return res;
}

static int is_extended(const unsigned int part_type)
{
  return (part_type==(const unsigned char)P_EXTENDX || part_type==(const unsigned char)P_EXTENDED || part_type==(const unsigned char)P_LINUXEXTENDX);
}

list_part_t *add_partition_i386_cli(disk_t *disk_car, list_part_t *list_part, char **current_cmd)
{
  CHS_t start,end;
  partition_t *new_partition=partition_new(&arch_i386);
  assert(current_cmd!=NULL);
  start.cylinder=0;
  start.head=0;
  start.sector=1;
  end.cylinder=disk_car->geom.cylinders-1;
  end.head=disk_car->geom.heads_per_cylinder-1;
  end.sector=disk_car->geom.sectors_per_head;
  /*@
    @ loop invariant valid_list_part(list_part);
    @ loop invariant valid_read_string(*current_cmd);
    @ */
  while(1)
  {
    skip_comma_in_command(current_cmd);
    if(check_command(current_cmd,"c,",2)==0)
    {
      start.cylinder=ask_number_cli(current_cmd, start.cylinder,
	  0, disk_car->geom.cylinders-1, "Enter the starting cylinder ");
    }
    else if(check_command(current_cmd,"h,",2)==0)
    {
      start.head=ask_number_cli(current_cmd, start.head,
	  0, disk_car->geom.heads_per_cylinder-1, "Enter the starting head ");
    }
    else if(check_command(current_cmd,"s,",2)==0)
    {
      start.sector=ask_number_cli(current_cmd, start.sector,
	  1, disk_car->geom.sectors_per_head, "Enter the starting sector ");
    }
    else if(check_command(current_cmd,"C,",2)==0)
    {
      end.cylinder=ask_number_cli(current_cmd, end.cylinder,
	  start.cylinder, disk_car->geom.cylinders-1, "Enter the ending cylinder ");
    }
    else if(check_command(current_cmd,"H,",2)==0)
    {
      end.head=ask_number_cli(current_cmd, end.head,
	  0, disk_car->geom.heads_per_cylinder-1, "Enter the ending head ");
    }
    else if(check_command(current_cmd,"S,",2)==0)
    {
      end.sector=ask_number_cli(current_cmd, end.sector,
	  1, disk_car->geom.sectors_per_head-1, "Enter the ending sector ");
    }
    else if(check_command(current_cmd,"T,",2)==0)
    {
      change_part_type_cli(disk_car,new_partition,current_cmd);
    }
    else if((CHS2offset(disk_car,&end)>new_partition->part_offset) &&
	new_partition->part_offset>0 &&
	new_partition->part_type_i386!=P_NO_OS)
    {
      int insert_error=0;
      list_part_t *new_list_part=insert_new_partition(list_part, new_partition, 0, &insert_error);
      /*@ assert valid_list_part(new_list_part); */
      if(insert_error>0)
      {
	free(new_partition);
	/*@ assert valid_read_string(*current_cmd); */
	/*@ assert valid_list_part(new_list_part); */
	return new_list_part;
      }
      if(test_structure_i386(list_part)==0)
      { /* Check if the partition can be Logical, Bootable or Primary */
	if(parti386_can_be_ext(disk_car,new_partition)!=0)
	{
	  new_partition->status=STATUS_LOG;
	  if(test_structure_i386(new_list_part)==0)
	  {
	    /*@ assert valid_read_string(*current_cmd); */
	    /*@ assert valid_list_part(new_list_part); */
	    return new_list_part;
	  }
	}
	new_partition->status=STATUS_PRIM_BOOT;
	if(test_structure_i386(new_list_part)==0)
	{
	  /*@ assert valid_read_string(*current_cmd); */
	  /*@ assert valid_list_part(new_list_part); */
	  return new_list_part;
	}
	new_partition->status=STATUS_PRIM;
	if(test_structure_i386(new_list_part)==0)
	{
	  /*@ assert valid_read_string(*current_cmd); */
	  /*@ assert valid_list_part(new_list_part); */
	  return new_list_part;
	}
      }
      new_partition->status=STATUS_DELETED;
      /*@ assert valid_read_string(*current_cmd); */
      /*@ assert valid_list_part(new_list_part); */
      return new_list_part;
    }
    else
    {
      free(new_partition);
      /*@ assert valid_read_string(*current_cmd); */
      /*@ assert valid_list_part(list_part); */
      return list_part;
    }
  }
}

static void set_next_status_i386(const disk_t *disk_car, partition_t *partition)
{
  /* STATUS_DELETED, STATUS_PRIM, STATUS_PRIM_BOOT, STATUS_LOG */
  switch(partition->status)
  {
    case STATUS_PRIM_BOOT:
      if(parti386_can_be_ext(disk_car,partition)!=0)
	partition->status=STATUS_LOG;
      else
	partition->status=STATUS_DELETED;
      break;
    case STATUS_LOG:		partition->status=STATUS_DELETED; break;
    case STATUS_DELETED:	partition->status=STATUS_PRIM; break;
    default:			partition->status=STATUS_PRIM_BOOT; break;
  }
}

static void set_prev_status_i386(const disk_t *disk_car, partition_t *partition)
{
  switch(partition->status)
  {
    case STATUS_DELETED:
      if(parti386_can_be_ext(disk_car,partition)!=0)
	partition->status=STATUS_LOG;
      else
	partition->status=STATUS_PRIM_BOOT;
      break;
    case STATUS_LOG:		partition->status=STATUS_PRIM_BOOT; break;
    case STATUS_PRIM_BOOT:	partition->status=STATUS_PRIM; break;
    default:			partition->status=STATUS_DELETED; break;
  }
}

static int set_part_type_i386(partition_t *partition, unsigned int part_type)
{
  if(part_type!=P_NO_OS && part_type <= 255 && is_extended(part_type)==0)
  {
    partition->part_type_i386=part_type;
    return 0;
  }
  return 1;
}

static int is_part_known_i386(const partition_t *partition)
{
  return (partition->part_type_i386!=P_NO_OS && partition->part_type_i386!=P_UNK);
}

static void init_structure_i386(const disk_t *disk_car,list_part_t *list_part, const int verbose)
{
  unsigned int vista_partition=0;
  list_part_t *element;
  list_part_t *new_list_part=NULL;
  /* Create new list */
  for(element=list_part;element!=NULL;element=element->next)
    element->to_be_removed=0;
  for(element=list_part;element!=NULL;element=element->next)
  {
    list_part_t *element2;
    if(element->part->arch!=NULL && element->part->arch!=disk_car->arch)
    {
      element->to_be_removed=1;
    }
    else
    {
      if(element->part->part_offset%(2048*512)==0 && element->part->part_size%(2048*512)==0)
	vista_partition=1;
      for(element2=element->next;element2!=NULL;element2=element2->next)
	if(element->part->part_offset+element->part->part_size-1 >= element2->part->part_offset)
	{
	  element->to_be_removed=1;
	  element2->to_be_removed=1;
	}
    }
    if(element->to_be_removed==0)
    {
      int insert_error=0;
      new_list_part=insert_new_partition(new_list_part,element->part, 0, &insert_error);
    }
  }

/* Set primary, extended, logical */
  if(vista_partition==0)
  {
    /* log_block_size must be 0 or 1 for a valid partition table */
    unsigned int log_block_size=0;
    unsigned int nbr_log_block=0;
    unsigned int biggest_log_block_size=0;
    unsigned int nbr_prim=0;
    list_part_t *end_log_block=NULL;
    list_part_t *end_biggest_log_block=NULL;
    /* Verify */
    for(element=new_list_part;element!=NULL;element=element->next)
    {
      if(parti386_can_be_ext(disk_car,element->part)==0)
      {
	nbr_prim++;
	if((end_log_block!=NULL) && (end_log_block->next==element))
	{
	  if(log_block_size>biggest_log_block_size)
	  {
	    biggest_log_block_size=log_block_size;
	    end_biggest_log_block=end_log_block;
	  }
	  nbr_log_block++;
	  end_log_block=NULL;
	}
      }
      else
      {
	log_block_size++;
	end_log_block=element;
      }
    }
    /* Verification */
    if((end_log_block!=NULL) && (end_log_block->next==NULL))
    {
      if(log_block_size>biggest_log_block_size)
      {
	end_biggest_log_block=end_log_block;
      }
      nbr_log_block++;
    }
    if(verbose>1)
      log_info("\nRes: nbr_prim %u, nbr_log_block %u, vista_partition=%u\n", nbr_prim, nbr_log_block, vista_partition);
    if(nbr_prim+nbr_log_block<=4)
    {
      int set_prim_bootable_done=0;
      for(element=end_biggest_log_block;element!=NULL && parti386_can_be_ext(disk_car,element->part);element=element->prev)
      {
	element->part->status=STATUS_LOG;
      }
      for(element=new_list_part;element!=NULL;element=element->next)
      {
	if(element->part->status!=STATUS_LOG)
	{
	  /* The first primary partition is bootable unless it's a swap */
	  if(set_prim_bootable_done==0 &&
	      element->part->upart_type!=UP_LINSWAP && element->part->upart_type!=UP_LVM && element->part->upart_type!=UP_LVM2)
	  {
	    element->part->status=STATUS_PRIM_BOOT;
	    set_prim_bootable_done=1;
	  }
	  else
	    element->part->status=STATUS_PRIM;
	}
      }
    }
  }
  if(vista_partition>0 || test_structure_i386(new_list_part))
  { /* Handle Vista partition */
    unsigned int i;
    int set_prim_bootable_done=0;
    for(element=new_list_part,i=0;element!=NULL;element=element->next,i++)
    {
      if(i<3)
      {
	/* The first primary partition is bootable unless it's a swap */
	if(set_prim_bootable_done==0 &&
	    element->part->upart_type!=UP_LINSWAP && element->part->upart_type!=UP_LVM && element->part->upart_type!=UP_LVM2)
	{
	  element->part->status=STATUS_PRIM_BOOT;
	  set_prim_bootable_done=1;
	}
	else
	  element->part->status=STATUS_PRIM;
      }
      else
	element->part->status=STATUS_LOG;
    }
  }
  if(test_structure_i386(new_list_part))
  {
    for(element=new_list_part;element!=NULL;element=element->next)
      element->part->status=STATUS_DELETED;
  }
  part_free_list_only(new_list_part);
}

static int erase_list_part_i386(disk_t *disk)
{
  unsigned char buffer[DEFAULT_SECTOR_SIZE];
  if(disk->pread(disk, buffer, DEFAULT_SECTOR_SIZE, (uint64_t)0) != DEFAULT_SECTOR_SIZE)
  {
    log_error(msg_PART_RD_ERR);
    memset(buffer,0,sizeof(buffer));
  }
  memset(buffer+TAB_PART,0,0x40);
  /* Remove Mac signature */
  if(buffer[0]==0x45 && buffer[1]==0x52)
    buffer[0]=0;
  /* Remove Sun signature */
  if(buffer[0x1fc]==0xda && buffer[0x1fd]==0xbe)
    buffer[0x1fc]=0;
  if(disk->pwrite(disk, buffer, DEFAULT_SECTOR_SIZE, (uint64_t)0) != DEFAULT_SECTOR_SIZE)
  {
    return 1;
  }
  {
    /* Erase XBOX signature if present */
    struct xbox_partition *xboxlabel=(struct xbox_partition*)MALLOC(0x800);
    if((unsigned)disk->pread(disk, xboxlabel, 0x800, 0) == 0x800)
    {
      if (memcmp(xboxlabel->magic,"BRFR",4)==0)
      {
	memset(xboxlabel->magic, 0, 4);
	disk->pwrite(disk, xboxlabel, 0x800, 0);
      }
    }
    free(xboxlabel);
  }
  {
    /* Erase EFI GPT signature if present */
    struct gpt_hdr *gpt=(struct gpt_hdr*)MALLOC(disk->sector_size);
    if((unsigned)disk->pread(disk, gpt, disk->sector_size, disk->sector_size) == disk->sector_size)
    {
      if(memcmp(gpt->hdr_sig, GPT_HDR_SIG, 8)==0)
      {
	memset(gpt->hdr_sig, 0, 8);
	disk->pwrite(disk, gpt, disk->sector_size, disk->sector_size);
      }
    }
    free(gpt);
  }
  disk->sync(disk);
  return 0;
}

static int check_part_i386(disk_t *disk_car,const int verbose,partition_t *partition, const int saveheader)
{
  int ret=0;
  switch(partition->part_type_i386)
  {
    case P_BEOS:
      ret=check_BeFS(disk_car,partition);
      break;
    case P_12FAT:
    case P_16FAT:
    case P_16FATBD:
    case P_32FAT:
    case P_32FAT_LBA:
    case P_16FATBD_LBA:
    case P_12FATH:
    case P_16FATH:
    case P_16FATBDH:
    case P_32FATH:
    case P_32FAT_LBAH:
    case P_16FATBD_LBAH:
      ret=check_FAT(disk_car,partition,verbose);
      if(ret!=0)
      { screen_buffer_add("Invalid FAT boot sector\n"); }
      break;
    case P_FREEBSD:
      ret=check_BSD(disk_car,partition,verbose,BSD_MAXPARTITIONS);
      if(ret!=0)
      { screen_buffer_add("Invalid BSD disklabel\n"); }
      break;
    case P_HFS:
      ret=check_HFS(disk_car, partition, verbose);
      if(ret!=0)
	ret=check_HFSP(disk_car, partition, verbose);
      if(ret!=0)
	screen_buffer_add("No HFS or HFS+ structure\n");
      break;
    case P_LINUX:
      ret=check_linux(disk_car, partition, verbose);
      if(ret!=0)
	screen_buffer_add("No ext2, JFS, Reiser, cramfs or XFS marker\n");
      break;
    case P_LINSWAP:
      ret=check_Linux_SWAP(disk_car, partition);
      break;
    case P_LVM:
      ret=check_LVM(disk_car,partition,verbose);
      if(ret!=0)
	ret=check_LVM2(disk_car,partition,verbose);
      if(ret!=0)
	screen_buffer_add("No LVM or LVM2 structure\n");
      break;
    case P_NETBSD:
      ret=check_BSD(disk_car,partition,verbose,BSD_MAXPARTITIONS);
      break;
    case P_NTFS:
    case P_NTFSH:
      ret=check_NTFS(disk_car,partition,verbose,0);
      if(ret!=0)
      {
	ret=check_exFAT(disk_car, partition);
      }
      if(ret!=0)
      { screen_buffer_add("Invalid NTFS or exFAT boot\n"); }
      break;
    case P_OPENBSD:
      ret=check_BSD(disk_car,partition,verbose,OPENBSD_MAXPARTITIONS);
      break;
    case P_RAID:
      ret=check_MD(disk_car,partition,verbose);
      if(ret!=0)
	screen_buffer_add("Invalid RAID superblock\n");
      break;
    case P_SUN:
      ret=check_sun_i386(disk_car,partition,verbose);
      break;
    case P_EXTENDED:
    case P_EXTENDX:
    case P_LINUXEXTENDX:
      break;
    case P_NETWARE:
      /* res=check_netware(disk_car, partition); */
      break;
    default:
      if(verbose>0)
      {
	log_warning("check_part_i386 %u type %02X: no test\n",partition->order,partition->part_type_i386);
      }
      if(saveheader>0)
      {
	save_header(disk_car,partition,verbose);
      }
      break;
  }
  if(ret!=0)
  {
    log_error("check_part_i386 failed for partition type %02X\n", partition->part_type_i386);
    aff_part_buffer(AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition);
    if(saveheader>0)
    {
      save_header(disk_car,partition,verbose);
    }
  }
  return ret;
}

static const char *get_partition_typename_i386_aux(const unsigned int part_type_i386)
{
  int i;
  /*@ loop assigns i; */
  for (i=0; i386_sys_types[i].name!=NULL; i++)
    if (i386_sys_types[i].part_type == part_type_i386)
      return i386_sys_types[i].name;
  return NULL;
}

static const char *get_partition_typename_i386(const partition_t *partition)
{
  return get_partition_typename_i386_aux(partition->part_type_i386);
}
#endif
