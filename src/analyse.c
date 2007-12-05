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
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
//#include <assert.h>
#include "types.h"
#include "common.h"
#include "fnctdsk.h"
#include "analyse.h"
#include "intrf.h"
#include "intrfn.h"
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
  if(disk_car->read(disk_car,DEFAULT_SECTOR_SIZE, buffer, partition->part_offset)!=0)
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
  if(disk_car->read(disk_car,0x400, buffer, partition->part_offset)!=0)
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
  if(disk_car->read(disk_car,DEFAULT_SECTOR_SIZE, buffer, partition->part_offset)!=0)
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
  if(disk_car->read(disk_car,8*DEFAULT_SECTOR_SIZE, buffer, partition->part_offset)!=0)
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
  if(disk_car->read(disk_car,8*DEFAULT_SECTOR_SIZE, buffer, partition->part_offset)!=0)
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
  if(disk_car->read(disk_car,1024, (buffer+0x400), partition->part_offset+1024)!=0)
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
  if(disk_car->read(disk_car,4096, buffer, partition->part_offset+4096)!=0)
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
  if(disk_car->read(disk_car,3*DEFAULT_SECTOR_SIZE, buffer, partition->part_offset+16*512)!=0) /* 8k offset */
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
#if 0
  if(disk_car->read(disk_car,2*DEFAULT_SECTOR_SIZE, buffer, partition->part_offset+64*512)!=0) /* 32k offset */
    return -1;
  if(recover_JFS(disk_car,(const struct jfs_superblock*)buffer,partition,verbose,dump_ind)==0) return 1;
#else
  if(disk_car->read(disk_car,3*DEFAULT_SECTOR_SIZE, buffer, partition->part_offset+63*512)!=0) /* 32k offset */
    return -1;
  if(recover_JFS(disk_car,(const struct jfs_superblock*)(buffer+0x200),partition,verbose,dump_ind)==0) return 1;
#endif
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
#if 0
  /* Test ReiserFS */
  if(disk_car->read(disk_car,9*DEFAULT_SECTOR_SIZE, buffer, partition->part_offset+128*512)!=0) /* 64k offset */
    return -1;
  if(recover_rfs(disk_car,(const struct reiserfs_super_block*)buffer,partition,verbose,dump_ind)==0) return 1;
  /* Test UFS2 */
  if(recover_ufs(disk_car,(const struct ufs_super_block*)buffer,partition,verbose,dump_ind)==0) return 1;
#else
  /* Test ReiserFS */
  if(disk_car->read(disk_car,11*DEFAULT_SECTOR_SIZE, buffer, partition->part_offset+126*512)!=0) /* 64k offset */
    return -1;
  if(recover_rfs(disk_car,(const struct reiserfs_super_block*)(buffer+0x400),partition,verbose,dump_ind)==0) return 1;
  /* Test UFS2 */
  if(recover_ufs(disk_car,(const struct ufs_super_block*)(buffer+0x400),partition,verbose,dump_ind)==0) return 1;
#endif
  return 0;
}

list_part_t *search_superblock(disk_t *disk_car, const partition_t *partition, const int verbose, const int dump_ind, const int interface)
{
  unsigned char *buffer=MALLOC(2*0x200);
  uint64_t hd_offset;
  int nbr_sb=0;
  list_part_t *list_part=NULL;
  int ind_stop=0;
  unsigned long int old_percent=0;
  struct ext2_super_block *sb=(struct ext2_super_block *)buffer;
  partition_t *new_partition=partition_new(disk_car->arch);
  log_trace("search_superblock\n");
#ifdef HAVE_NCURSES
  if(interface>0)
  {
    aff_copy(stdscr);
    wmove(stdscr,4,0);
    wprintw(stdscr,"%s",disk_car->description(disk_car));
    mvwaddstr(stdscr,5,0,msg_PART_HEADER_LONG);
    wmove(stdscr,6,0);
    aff_part(stdscr,AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition);
    wmove(stdscr,22,0);
    wattrset(stdscr, A_REVERSE);
    waddstr(stdscr,"  Stop  ");
    wattroff(stdscr, A_REVERSE);
  }
#endif
  for(hd_offset=0;hd_offset<partition->part_size && nbr_sb<10 && ind_stop==0;hd_offset+=DEFAULT_SECTOR_SIZE)
  {
#ifdef HAVE_NCURSES
    unsigned long int percent;
    percent=hd_offset*100/partition->part_size;
    if(interface>0 && percent!=old_percent)
    {
      wmove(stdscr,9,0);
      wclrtoeol(stdscr);
      wprintw(stdscr,"Search EXT2/EXT3 superblock %10lu/%lu %lu%%", (long unsigned)(hd_offset/disk_car->sector_size),
	  (long unsigned)(partition->part_size/disk_car->sector_size),percent);
      wrefresh(stdscr);
      ind_stop|=check_enter_key_or_s(stdscr);
      old_percent=percent;
    }
#endif
    /* EXT2/EXT3 */
    if( hd_offset==(EXT2_MIN_BLOCK_SIZE<<0) ||
	hd_offset==(EXT2_MIN_BLOCK_SIZE<<1) ||
	hd_offset==(EXT2_MIN_BLOCK_SIZE<<2) ||
      hd_offset==(1*(EXT2_MIN_BLOCK_SIZE<<0)*8*(EXT2_MIN_BLOCK_SIZE<<0)+2*512) ||
      hd_offset==(1*(EXT2_MIN_BLOCK_SIZE<<1)*8*(EXT2_MIN_BLOCK_SIZE<<1)) ||
      hd_offset==(1*(EXT2_MIN_BLOCK_SIZE<<2)*8*(EXT2_MIN_BLOCK_SIZE<<2)) ||
      hd_offset%(3*(EXT2_MIN_BLOCK_SIZE<<0)*8*(EXT2_MIN_BLOCK_SIZE<<0)+2*512)==0 ||
      hd_offset%(5*(EXT2_MIN_BLOCK_SIZE<<0)*8*(EXT2_MIN_BLOCK_SIZE<<0)+2*512)==0 ||
      hd_offset%(7*(EXT2_MIN_BLOCK_SIZE<<0)*8*(EXT2_MIN_BLOCK_SIZE<<0)+2*512)==0 ||
      hd_offset%(3*(EXT2_MIN_BLOCK_SIZE<<1)*8*(EXT2_MIN_BLOCK_SIZE<<1))==0 ||
      hd_offset%(5*(EXT2_MIN_BLOCK_SIZE<<1)*8*(EXT2_MIN_BLOCK_SIZE<<1))==0 ||
      hd_offset%(7*(EXT2_MIN_BLOCK_SIZE<<1)*8*(EXT2_MIN_BLOCK_SIZE<<1))==0 ||
      hd_offset%(3*(EXT2_MIN_BLOCK_SIZE<<2)*8*(EXT2_MIN_BLOCK_SIZE<<2))==0 ||
      hd_offset%(5*(EXT2_MIN_BLOCK_SIZE<<2)*8*(EXT2_MIN_BLOCK_SIZE<<2))==0 ||
      hd_offset%(7*(EXT2_MIN_BLOCK_SIZE<<2)*8*(EXT2_MIN_BLOCK_SIZE<<2))==0)
    {
      if(disk_car->read(disk_car,1024, buffer, partition->part_offset+hd_offset)==0)
      {
	if(le16(sb->s_magic)==EXT2_SUPER_MAGIC)
	{
	  dup_partition_t(new_partition,partition);
	  new_partition->part_offset+=hd_offset;
	  if(recover_EXT2(disk_car,sb,new_partition,verbose,dump_ind)==0)
	  {
	    int insert_error=0;
	    if(hd_offset<=(EXT2_MIN_BLOCK_SIZE<<2))
	      new_partition->part_offset-=hd_offset;
	    log_info("Ext2 superblock found at sector %llu (block=%llu, blocksize=%u)\n",
		(long long unsigned) hd_offset/DEFAULT_SECTOR_SIZE,
		(long long unsigned) hd_offset>>(EXT2_MIN_BLOCK_LOG_SIZE+le32(sb->s_log_block_size)),
		EXT2_MIN_BLOCK_SIZE<<le32(sb->s_log_block_size));
#ifdef HAVE_NCURSES
	    wmove(stdscr,10+nbr_sb,0);
	    wprintw(stdscr,"Ext2 superblock found at sector %llu (block=%llu, blocksize=%u)        \n",
		(long long unsigned) hd_offset/DEFAULT_SECTOR_SIZE,
		(long long unsigned) hd_offset>>(EXT2_MIN_BLOCK_LOG_SIZE+le32(sb->s_log_block_size)),
                EXT2_MIN_BLOCK_SIZE<<le32(sb->s_log_block_size));
#endif
	    list_part=insert_new_partition(list_part, new_partition, 1, &insert_error);
	    new_partition=partition_new(disk_car->arch);
	    nbr_sb++;
	  }
	}
      }
    }
  }
  free(new_partition);
  free(buffer);
  return list_part;
}

