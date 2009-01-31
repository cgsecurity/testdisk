/*

    File: analyse.c

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
#include "types.h"
#include "common.h"
#include "fnctdsk.h"
#include "analyse.h"
#include "intrf.h"
#include "savehdr.h"
#include "lang.h"
#include "bfs.h"
#include "bsd.h"
#include "cramfs.h"
#include "ext2.h"
#include "fat.h"
#include "fatx.h"
#include "hfs.h"
#include "hfsp.h"
#include "jfs_superblock.h"
#include "jfs.h"
#include "luks.h"
#include "lvm.h"
#include "md.h"
#include "netware.h"
#include "ntfs.h"
#include "rfs.h"
#include "sun.h"
#include "swap.h"
#include "sysv.h"
#include "ufs.h"
#include "xfs.h"
#include "log.h"

int search_NTFS_backup(unsigned char *buffer, disk_t *disk_car,partition_t *partition, const int verbose, const int dump_ind)
{
//  assert(sizeof(struct ntfs_boot_sector)<=DEFAULT_SECTOR_SIZE);
  if(disk_car->pread(disk_car, buffer, DEFAULT_SECTOR_SIZE, partition->part_offset) != DEFAULT_SECTOR_SIZE)
    return -1;
  /* NTFS recovery using backup sector */
  if(recover_NTFS(disk_car,(const struct ntfs_boot_sector*)buffer,partition,verbose,dump_ind,1)==0)
    return 1;
  return 0;
}

int search_HFS_backup(unsigned char *buffer, disk_t *disk_car,partition_t *partition, const int verbose, const int dump_ind)
{
//  assert(sizeof(hfs_mdb_t)<=0x400);
//  assert(sizeof(struct hfsp_vh)==0x200);
  if(disk_car->pread(disk_car, buffer, 0x400, partition->part_offset) != 0x400)
    return -1;
  /* HFS recovery using backup sector */
  if(recover_HFS(disk_car,(const hfs_mdb_t*)buffer,partition,verbose,dump_ind,1)==0)
  {
    strncpy(partition->info,"HFS found using backup sector!",sizeof(partition->info));
    return 1;
  }
  if(recover_HFSP(disk_car,(const struct hfsp_vh*)buffer,partition,verbose,dump_ind,1)==0)
  {
    strncpy(partition->info,"HFS+ found using backup sector!",sizeof(partition->info));
    return 1;
  }
  return 0;
}

int search_FAT_backup(unsigned char *buffer, disk_t *disk_car,partition_t *partition, const int verbose, const int dump_ind)
{
//  assert(sizeof(struct fat_boot_sector)==DEFAULT_SECTOR_SIZE);
  if(disk_car->pread(disk_car, buffer, DEFAULT_SECTOR_SIZE, partition->part_offset) != DEFAULT_SECTOR_SIZE)
    return -1;
  /* FAT32 recovery using backup sector */
  if(recover_FAT(disk_car,(const struct fat_boot_sector*)buffer,partition,verbose,dump_ind,1)==0)
  {
    strncpy(partition->info,"FAT found using backup sector!",sizeof(partition->info));
    return 1;
  }
  return 0;
}

int search_type_0(unsigned char *buffer,disk_t *disk_car,partition_t *partition, const int verbose, const int dump_ind)
{
//  assert(sizeof(union swap_header)<=8*DEFAULT_SECTOR_SIZE);
//  assert(sizeof(pv_disk_t)<=8*DEFAULT_SECTOR_SIZE);
//  assert(sizeof(struct fat_boot_sector)<=8*DEFAULT_SECTOR_SIZE);
//  assert(sizeof(struct ntfs_boot_sector)<=8*DEFAULT_SECTOR_SIZE);
//  assert(sizeof(struct disk_netware)<=8*DEFAULT_SECTOR_SIZE);
//  assert(sizeof(struct xfs_sb)<=8*DEFAULT_SECTOR_SIZE);
//  assert(sizeof(struct disk_fatx)<=8*DEFAULT_SECTOR_SIZE);
  if(verbose>2)
  {
    log_trace("search_type_0 lba=%lu\n",(long unsigned)(partition->part_offset/disk_car->sector_size));
  }
  if(disk_car->pread(disk_car, buffer, 8 * DEFAULT_SECTOR_SIZE, partition->part_offset) != 8 * DEFAULT_SECTOR_SIZE)
    return -1;
  if(recover_Linux_SWAP(disk_car,(const union swap_header *)buffer,partition,verbose,dump_ind)==0) return 1;
  if(recover_LVM(disk_car,(const pv_disk_t*)buffer,partition,verbose,dump_ind)==0) return 1;
  if(recover_FAT(disk_car,(const struct fat_boot_sector*)buffer,partition,verbose,dump_ind,0)==0) return 1;
  if(recover_HPFS(disk_car,(const struct fat_boot_sector*)buffer,partition,verbose,dump_ind)==0) return 1;
  if(recover_OS2MB(disk_car,(const struct fat_boot_sector*)buffer,partition,verbose,dump_ind)==0) return 1;
  if(recover_NTFS(disk_car,(const struct ntfs_boot_sector*)buffer,partition,verbose,dump_ind,0)==0) return 1;
  if(recover_netware(disk_car,(const struct disk_netware *)buffer,partition)==0) return 1;
  if(recover_xfs(disk_car,(const struct xfs_sb*)buffer,partition,verbose,dump_ind)==0) return 1;
  if(recover_FATX(disk_car,(const struct disk_fatx*)buffer,partition,verbose,dump_ind)==0) return 1;
  if(recover_LUKS(disk_car,(const struct luks_phdr*)buffer,partition,verbose,dump_ind)==0) return 1;
  { /* MD 1.1 */
    const struct mdp_superblock_1 *sb1=(const struct mdp_superblock_1 *)buffer;
    if(le32(sb1->major_version)==1 &&
        recover_MD(disk_car,(const struct mdp_superblock_s*)buffer,partition,verbose,dump_ind)==0)
    {
      partition->part_offset-=le64(sb1->super_offset)*512;
      return 1;
    }
  }
  return 0;
}

int search_type_1(unsigned char *buffer, disk_t *disk_car,partition_t *partition,const int verbose, const int dump_ind)
{
//  assert(sizeof(struct disklabel)<=2*0x200);
//  assert(sizeof(struct disk_super_block)<=0x200);
//  assert(sizeof(struct cramfs_super)<=2*0x200);
//  assert(sizeof(struct sysv4_super_block)<=2*0x200);
//  assert(sizeof(sun_partition_i386)<=2*0x200);
  if(verbose>2)
  {
    log_trace("search_type_1 lba=%lu\n",(long unsigned)(partition->part_offset/disk_car->sector_size));
  }
  if(disk_car->pread(disk_car, buffer, 8 * DEFAULT_SECTOR_SIZE, partition->part_offset) != 8 * DEFAULT_SECTOR_SIZE)
    return -1;
  if(recover_BSD(disk_car,(const struct disklabel *)(buffer+0x200),partition,verbose,dump_ind)==0) return 1;
  if(recover_BeFS(disk_car,(const struct disk_super_block *)(buffer+0x200),partition,verbose,dump_ind)==0) return 1;
  if(recover_cramfs(disk_car,(const struct cramfs_super*)(buffer+0x200),partition,verbose,dump_ind)==0) return 1;
  if(recover_sysv(disk_car,(const struct sysv4_super_block*)(buffer+0x200),partition,verbose,dump_ind)==0) return 1;
  if(recover_LVM2(disk_car,(const unsigned char*)(buffer+0x200),partition,verbose,dump_ind)==0) return 1;
  if(recover_sun_i386(disk_car,(const sun_partition_i386*)(buffer+0x200),partition,verbose,dump_ind)==0) return 1;
  return 0;
}

int search_type_2(unsigned char *buffer, disk_t *disk_car,partition_t *partition,const int verbose, const int dump_ind)
{
//  assert(sizeof(struct ext2_super_block)<=1024);
//  assert(sizeof(hfs_mdb_t)<=1024);
//  assert(sizeof(struct hfsp_vh)<=1024);
  if(verbose>2)
  {
    log_trace("search_type_2 lba=%lu\n",(long unsigned)(partition->part_offset/disk_car->sector_size));
  }
  if(disk_car->pread(disk_car, (buffer + 0x400), 1024, partition->part_offset + 1024) != 1024)
    return -1;
  if(recover_EXT2(disk_car,(const struct ext2_super_block*)(buffer+0x400),partition,verbose,dump_ind)==0) return 1;
  if(recover_HFS(disk_car,(const hfs_mdb_t*)(buffer+0x400),partition,verbose,dump_ind,0)==0) return 1;
  if(recover_HFSP(disk_car,(const struct hfsp_vh*)(buffer+0x400),partition,verbose,dump_ind,0)==0) return 1;
  return 0;
}

int search_type_8(unsigned char *buffer, disk_t *disk_car,partition_t *partition,const int verbose, const int dump_ind)
{
  if(verbose>2)
  {
    log_trace("search_type_8 lba=%lu\n",(long unsigned)(partition->part_offset/disk_car->sector_size));
  }
  if(disk_car->pread(disk_car, buffer, 4096, partition->part_offset + 4096) != 4096)
    return -1;
  { /* MD 1.2 */
    const struct mdp_superblock_1 *sb1=(const struct mdp_superblock_1 *)buffer;
    if(le32(sb1->major_version)==1 &&
        recover_MD(disk_car,(const struct mdp_superblock_s*)buffer,partition,verbose,dump_ind)==0)
    {
      partition->part_offset-=(uint64_t)le64(sb1->super_offset)*512-4096;
      return 1;
    }
  }
  return 0;
}

int search_type_16(unsigned char *buffer, disk_t *disk_car,partition_t *partition,const int verbose, const int dump_ind)
{
//  assert(sizeof(struct ufs_super_block)<=3*DEFAULT_SECTOR_SIZE);
  if(verbose>2)
  {
    log_trace("search_type_16 lba=%lu\n",(long unsigned)(partition->part_offset/disk_car->sector_size));
  }
  if(disk_car->pread(disk_car, buffer, 3 * DEFAULT_SECTOR_SIZE, partition->part_offset + 16 * 512) != 3 * DEFAULT_SECTOR_SIZE) /* 8k offset */
    return -1;
  /* Test UFS */
  if(recover_ufs(disk_car,(const struct ufs_super_block*)buffer,partition,verbose,dump_ind)==0) return 1;
  return 0;
}

int search_type_64(unsigned char *buffer, disk_t *disk_car,partition_t *partition,const int verbose, const int dump_ind)
{
//  assert(sizeof(struct jfs_superblock)<=2*DEFAULT_SECTOR_SIZE);
  if(verbose>2)
  {
    log_trace("search_type_64 lba=%lu\n",(long unsigned)(partition->part_offset/disk_car->sector_size));
  }
  /* Test JFS */
  if(disk_car->pread(disk_car, buffer, 3 * DEFAULT_SECTOR_SIZE, partition->part_offset + 63 * 512) != 3 * DEFAULT_SECTOR_SIZE) /* 32k offset */
    return -1;
  if(recover_JFS(disk_car,(const struct jfs_superblock*)(buffer+0x200),partition,verbose,dump_ind)==0) return 1;
  return 0;
}

int search_type_128(unsigned char *buffer, disk_t *disk_car,partition_t *partition,const int verbose, const int dump_ind)
{
  /* Reiserfs4 need to read the master superblock and the format40 superblock => 4096 */
//  assert(sizeof(struct reiserfs_super_block)<=9*DEFAULT_SECTOR_SIZE);
//  assert(4096+sizeof(struct format40_super)<=9*DEFAULT_SECTOR_SIZE);
//  assert(sizeof(struct ufs_super_block)<=9*DEFAULT_SECTOR_SIZE);
  if(verbose>2)
  {
    log_trace("search_type_128 lba=%lu\n",(long unsigned)(partition->part_offset/disk_car->sector_size));
  }
  /* Test ReiserFS */
  if(disk_car->pread(disk_car, buffer, 11 * DEFAULT_SECTOR_SIZE, partition->part_offset + 126 * 512) != 11 * DEFAULT_SECTOR_SIZE) /* 64k offset */
    return -1;
  if(recover_rfs(disk_car,(const struct reiserfs_super_block*)(buffer+0x400),partition,verbose,dump_ind)==0) return 1;
  /* Test UFS2 */
  if(recover_ufs(disk_car,(const struct ufs_super_block*)(buffer+0x400),partition,verbose,dump_ind)==0) return 1;
  return 0;
}
