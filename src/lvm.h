/*
     File: lvm.h, TestDisk

    Copyright (C) 2003-2008 Christophe GRENIER <grenier@cgsecurity.org>
    Same wunderfull license.
 */   
/* gm_hmlvm.h -- gpart Linux LVM physical volume guessing module header
 * 
 * gpart (c) 1999-2001 Michail Brzitwa <mb@ichabod.han.de>
 * Guess PC-type hard disk partitions.
 *
 * gpart is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2, or (at your
 * option) any later version.
 *
 * Created:   29.08.1999 <mb@ichabod.han.de>
 * Modified:  
 *
 */

#ifndef _LVM_H
#define _LVM_H
#ifdef __cplusplus
extern "C" {
#endif

/*
 * structs & defines gathered from LVM 0.7/0.9 lvm.h and liblvm.h
 */

/*
 * Status flags
 */

/* physical volume */
#define PV_ACTIVE		0x01	/* pv_status */
#define PV_ALLOCATABLE		0x02	/* pv_allocatable */


#define LVM_PV_DISK_BASE	0L
/* real size is 464 */
#define LVM_PV_DISK_SIZE	1024L
#define NAME_LEN		128	/* don't change!!! */
#define UUID_LEN		16	/* don't change!!! */
#define LVM_MAX_SIZE		( 1024LU * 1024 * 1024 * 2)	/* 1TB[sectors] */
#define LVM_ID			"HM"
#define LVM_DIR_PREFIX		"/dev/"
#define MAX_LV			256
#define LVM_MIN_PE_SIZE		( 8L * 2)	/* 8 KB in sectors */
#define LVM_MAX_PE_SIZE		( 16L * 1024L * 1024L * 2)	/* 16GB in sectors */

/* disk stored pe information */
typedef struct {
	uint16_t lv_num;
	uint16_t le_num;
} disk_pe_t;

/* disk stored PV, VG, LV and PE size and offset information */
typedef struct {
	uint32_t base;
	uint32_t size;
} lvm_disk_data_t;

/*
 * Structure Physical Volume (PV) Version 2
 */

/* disk */
typedef struct {
	uint8_t id[2];		/* Identifier */
	uint16_t version;		/* HM lvm version */
	lvm_disk_data_t pv_on_disk;
	lvm_disk_data_t vg_on_disk;
	lvm_disk_data_t pv_uuidlist_on_disk;
	lvm_disk_data_t lv_on_disk;
	lvm_disk_data_t pe_on_disk;
	uint8_t pv_uuid[NAME_LEN];
	uint8_t vg_name[NAME_LEN];
	uint8_t system_id[NAME_LEN];	/* for vgexport/vgimport */
	uint32_t pv_major;
	uint32_t pv_number;
	uint32_t pv_status;
	uint32_t pv_allocatable;
	uint32_t pv_size;		/* HM */
	uint32_t lv_cur;
	uint32_t pe_size;
	uint32_t pe_total;
	uint32_t pe_allocated;
} pv_disk_v2_t;

#define pv_disk_t pv_disk_v2_t
int check_LVM(disk_t *disk_car,partition_t *partition,const int verbose);
int recover_LVM(disk_t *disk_car, const pv_disk_t *pv,partition_t *partition,const int verbose, const int dump_ind);

#define LVM2_LABEL	"LVM2 001"
#define LABEL_ID 	"LABELONE"

struct lvm2_label_header {
  uint8_t id[8];          /* 0x00 LABELONE */
  uint64_t sector_xl;     /* 0x08 Sector number of this label */
  uint32_t crc_xl;        /* 0x10 From next field to end of sector */
  uint32_t offset_xl;     /* 0x14 Offset from start of struct to contents */
  uint8_t type[8];        /* 0x18 LVM2 001 */
} __attribute__ ((packed));

struct lvm2_disk_locn {
  uint64_t offset;        /* Offset in bytes to start sector */
  uint64_t size;          /* Bytes */
} __attribute__ ((packed));
                                                                                                                             

struct lvm2_pv_header {
  uint8_t pv_uuid[32];
  uint64_t device_size_xl;        /* Bytes */
  /* NULL-terminated list of data areas followed by */
  /* NULL-terminated list of metadata area headers */
  struct lvm2_disk_locn disk_areas_xl[0];      /* Two lists */
} __attribute__ ((packed));

int check_LVM2(disk_t *disk_car,partition_t *partition,const int verbose);
int recover_LVM2(disk_t *disk_car, const unsigned char *buf,partition_t *partition,const int verbose, const int dump_ind);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif /* _LVM_H */
