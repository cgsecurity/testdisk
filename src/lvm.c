/*

    File: lvm.c

    Copyright (C) 2003-2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include "lvm.h"
#include "fnctdsk.h"
#include "log.h"
#include "guid_cpy.h"

static void set_LVM_info(partition_t *partition);
static int test_LVM(disk_t *disk_car, const pv_disk_t *pv, const partition_t *partition,const int verbose, const int dump_ind);

static void set_LVM2_info(partition_t*partition);
static int test_LVM2(disk_t *disk_car, const struct lvm2_label_header *lh, const partition_t *partition, const int verbose, const int dump_ind);

int check_LVM(disk_t *disk_car,partition_t *partition,const int verbose)
{
  unsigned char *buffer=(unsigned char*)MALLOC(LVM_PV_DISK_SIZE);
  if(disk_car->pread(disk_car, buffer, LVM_PV_DISK_SIZE, partition->part_offset) != LVM_PV_DISK_SIZE)
  {
    free(buffer);
    return 1;
  }
  if(test_LVM(disk_car,(pv_disk_t *)buffer,partition,verbose,0)!=0)
  {
    free(buffer);
    return 1;
  }
  set_LVM_info(partition);
  free(buffer);
  return 0;
}

int recover_LVM(disk_t *disk_car, const pv_disk_t *pv,partition_t *partition,const int verbose, const int dump_ind)
{
  if(test_LVM(disk_car,pv,partition,verbose,dump_ind)!=0)
    return 1;
  set_LVM_info(partition);
  partition->part_type_i386=P_LVM;
  partition->part_type_sun=PSUN_LVM;
  partition->part_type_gpt=GPT_ENT_TYPE_LINUX_LVM;
  partition->part_size=(uint64_t)le32(pv->pv_size)*disk_car->sector_size;
  /* pv_uuid is bigger than part_uuid */
  guid_cpy(&partition->part_uuid, (const efi_guid_t *)&pv->pv_uuid);
  if(verbose>0)
  {
    log_info("part_size %lu\n",(long unsigned)(partition->part_size/disk_car->sector_size));
  }
  return 0;
}

static int test_LVM(disk_t *disk_car, const pv_disk_t *pv, const partition_t *partition, const int verbose, const int dump_ind)
{
  if ((memcmp((const char *)pv->id,LVM_ID,sizeof(pv->id)) == 0) && (le16(pv->version) == 1 || le16(pv->version) == 2))
  {
    uint32_t size;
    if(verbose>0 || dump_ind!=0)
    {
      log_info("\nLVM magic value at %u/%u/%u\n", offset2cylinder(disk_car,partition->part_offset),offset2head(disk_car,partition->part_offset),offset2sector(disk_car,partition->part_offset));
    }
    if(dump_ind!=0)
    {
      /* There is a little offset ... */
      dump_log(pv,DEFAULT_SECTOR_SIZE);
    }
    if (le32(pv->pv_size) > LVM_MAX_SIZE)
      return (1);
    if (le32(pv->pv_status) != 0 && le32(pv->pv_status) != PV_ACTIVE)
      return (1);
    if (le32(pv->pv_allocatable) != 0 && le32(pv->pv_allocatable) != PV_ALLOCATABLE)
      return (1);
    if (le32(pv->lv_cur) > MAX_LV)
      return (1);
    if (strlen((const char *)pv->vg_name) > NAME_LEN / 2)
      return (1);
    size = le32(pv->pe_size) / LVM_MIN_PE_SIZE * LVM_MIN_PE_SIZE;
    if ((le32(pv->pe_size) != size) ||
	(le32(pv->pe_size) < LVM_MIN_PE_SIZE) ||
	(le32(pv->pe_size) > LVM_MAX_PE_SIZE))
      return (1);

    if (le32(pv->pe_total) > ( pv->pe_on_disk.size / sizeof ( disk_pe_t)))
      return (1);
    if (le32(pv->pe_allocated) > le32(pv->pe_total))
      return (1);
    return 0;
  }
  return 1;
}

static void set_LVM_info(partition_t *partition)
{
  partition->upart_type=UP_LVM;
  partition->fsname[0]='\0';
  partition->info[0]='\0';
  snprintf(partition->info,sizeof(partition->info),"LVM");
}

int check_LVM2(disk_t *disk_car,partition_t *partition,const int verbose)
{
  unsigned char *buffer=(unsigned char *)MALLOC(DEFAULT_SECTOR_SIZE);
  if(disk_car->pread(disk_car, buffer, DEFAULT_SECTOR_SIZE, partition->part_offset + 0x200) != DEFAULT_SECTOR_SIZE)
  {
    free(buffer);
    return 1;
  }
  if(test_LVM2(disk_car,(const struct lvm2_label_header *)buffer,partition,verbose,0)!=0)
  {
    free(buffer);
    return 1;
  }
  set_LVM2_info(partition);
  free(buffer);
  return 0;
}

int recover_LVM2(disk_t *disk_car, const unsigned char *buf,partition_t *partition,const int verbose, const int dump_ind)
{
  const struct lvm2_label_header *lh=(const struct lvm2_label_header *)buf;
  if(test_LVM2(disk_car,lh,partition,verbose,dump_ind)!=0)
    return 1;
  set_LVM2_info(partition);
  partition->part_type_i386=P_LVM;
  partition->part_type_sun=PSUN_LVM;
  partition->part_type_gpt=GPT_ENT_TYPE_LINUX_LVM;
  {
    const struct lvm2_pv_header *pvhdr;
    pvhdr=(const struct lvm2_pv_header *) (buf + le32(lh->offset_xl));
    partition->part_size=le64(pvhdr->device_size_xl);
  }
  if(verbose>0)
  {
    log_info("part_size %lu\n",(long unsigned)(partition->part_size/disk_car->sector_size));
  }
  return 0;
}

static int test_LVM2(disk_t *disk_car, const struct lvm2_label_header *lh, const partition_t *partition, const int verbose, const int dump_ind)
{
  if (memcmp((const char *)lh->type,LVM2_LABEL,sizeof(lh->type)) == 0)
  {
    if(verbose>0 || dump_ind!=0)
    {
      log_info("\nLVM2 magic value at %u/%u/%u\n", offset2cylinder(disk_car,partition->part_offset),offset2head(disk_car,partition->part_offset),offset2sector(disk_car,partition->part_offset));
    }
    if(le32(lh->offset_xl)>400)
      return 1;
    if(dump_ind!=0)
    {
      /* There is a little offset ... */
      dump_log(lh,DEFAULT_SECTOR_SIZE);
    }
    return 0;
  }
  return 1;
}

static void set_LVM2_info(partition_t*partition)
{
  partition->upart_type=UP_LVM2;
  partition->fsname[0]='\0';
  partition->info[0]='\0';
  snprintf(partition->info,sizeof(partition->info),"LVM2");
}
