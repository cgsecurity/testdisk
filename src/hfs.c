/*

    File: hfs.c

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
#include "hfs.h"
#include "fnctdsk.h"
#include "log.h"

static void set_HFS_info(partition_t *partition, const hfs_mdb_t *hfs_mdb);

int check_HFS(disk_t *disk_car,partition_t *partition,const int verbose)
{
  unsigned char *buffer=(unsigned char*)MALLOC(HFS_SUPERBLOCK_SIZE);
  if(disk_car->pread(disk_car, buffer, HFS_SUPERBLOCK_SIZE, partition->part_offset + 0x400) != HFS_SUPERBLOCK_SIZE)
  {
    free(buffer);
    return 1;
  }
  if(test_HFS(disk_car,(hfs_mdb_t *)buffer,partition,verbose,0)!=0)
  {
    free(buffer);
    return 1;
  }
  set_HFS_info(partition,(hfs_mdb_t *)buffer);
  free(buffer);
  return 0;
}

int recover_HFS(disk_t *disk_car, const hfs_mdb_t *hfs_mdb,partition_t *partition,const int verbose, const int dump_ind, const int backup)
{
  uint64_t part_size;
  if(test_HFS(disk_car,hfs_mdb,partition,verbose,dump_ind)!=0)
    return 1;
  /* The extra 0x400 bytes are for the backup MDB */
  part_size=(uint64_t)be16(hfs_mdb->drNmAlBlks)*be32(hfs_mdb->drAlBlkSiz)+be16(hfs_mdb->drAlBlSt)*512+0x400;
  partition->sborg_offset=0x400;
  partition->sb_size=HFS_SUPERBLOCK_SIZE;
  if(backup>0)
  {
    if(partition->part_offset+2*disk_car->sector_size<part_size)
      return 1;
    partition->sb_offset=part_size-0x400;
    partition->part_offset=partition->part_offset+2*disk_car->sector_size-part_size;
  }
  partition->part_size=part_size;
  set_HFS_info(partition,hfs_mdb);
  partition->part_type_i386=P_HFS;
  partition->part_type_mac=PMAC_HFS;
  partition->part_type_gpt=GPT_ENT_TYPE_MAC_HFS;
  if(verbose>0)
  {
    log_info("part_size %lu\n",(long unsigned)(partition->part_size/disk_car->sector_size));
  }
  return 0;
}

int test_HFS(disk_t *disk_car, const hfs_mdb_t *hfs_mdb, const partition_t *partition, const int verbose, const int dump_ind)
{
  /* Check for HFS signature */
  if (hfs_mdb->drSigWord!=be16(HFS_SUPER_MAGIC))
    return 1;
  /* Blocksize must be a multiple of 512 */
  if(be32(hfs_mdb->drAlBlkSiz)<512 ||
      ((be32(hfs_mdb->drAlBlkSiz)-1) & be32(hfs_mdb->drAlBlkSiz))!=0)
    return 1;
  /* Check for valid number of allocation blocks */
  if(be16(hfs_mdb->drNmAlBlks)==0)
    return 1;
  /* Check for coherent block numbers */
  if(be16(hfs_mdb->drFreeBks) > be16(hfs_mdb->drNmAlBlks))
    return 1;
  /* Size must be less than 2TB (tolerate a little bit more)*/
  if((uint64_t)be16(hfs_mdb->drNmAlBlks)*be32(hfs_mdb->drAlBlkSiz)+be16(hfs_mdb->drAlBlSt)*512+0x400 > (uint64_t)2049*1024*1024*1024)
    return 1;
  if(verbose>0 || dump_ind!=0)
  {
    log_info("\nHFS magic value at %u/%u/%u\n", offset2cylinder(disk_car,partition->part_offset),offset2head(disk_car,partition->part_offset),offset2sector(disk_car,partition->part_offset));
  }
  if(dump_ind!=0)
  {
    /* There is a little offset ... */
    dump_log(hfs_mdb,DEFAULT_SECTOR_SIZE);
  }
  if(verbose>1)
  {
    log_info("drNmAlBlks %u\n",(unsigned) be16(hfs_mdb->drNmAlBlks));
    log_info("drAlBlkSiz %u\n",(unsigned) be32(hfs_mdb->drAlBlkSiz));
    log_info("drAlBlSt %u\n",(unsigned) be16(hfs_mdb->drAlBlSt));
    log_info("drFreeBks %u\n",(unsigned) be16(hfs_mdb->drFreeBks));
  }
  return 0;
}

static void set_HFS_info(partition_t *partition, const hfs_mdb_t *hfs_mdb)
{
  unsigned int name_size=sizeof(hfs_mdb->drVN)-1;
  partition->upart_type=UP_HFS;
  partition->blocksize=be32(hfs_mdb->drAlBlkSiz);
  snprintf(partition->info, sizeof(partition->info),
      "HFS blocksize=%u", partition->blocksize);
  if(name_size>hfs_mdb->drVN[0])
    name_size=hfs_mdb->drVN[0];
  memcpy(partition->fsname,&hfs_mdb->drVN[0]+1,name_size);
}

