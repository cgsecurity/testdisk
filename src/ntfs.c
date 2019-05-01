/*

    File: ntfs.c

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
/*
#define NTFS_DEBUG 1
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
#include <ctype.h>
#include "types.h"
#include "common.h"
#include "intrf.h"
#include "ntfs.h"
#include "fnctdsk.h"
#include "lang.h"
#include "log.h"
/* #include "guid_cmp.h" */
extern const arch_fnct_t arch_i386;

static void set_NTFS_info(disk_t *disk_car, const struct ntfs_boot_sector*ntfs_header, partition_t *partition);
static void ntfs_get_volume_name(disk_t *disk_car, partition_t *partition, const struct ntfs_boot_sector*ntfs_header);

unsigned int ntfs_sector_size(const struct ntfs_boot_sector *ntfs_header)
{ return (ntfs_header->sector_size[1]<<8)+ntfs_header->sector_size[0]; }

int check_NTFS(disk_t *disk_car, partition_t *partition, const int verbose, const int dump_ind)
{
  unsigned char *buffer=(unsigned char*)MALLOC(DEFAULT_SECTOR_SIZE);
/*  log_trace("check_NTFS part_offset=%llu\n",(long long unsigned)partition->part_offset); */
  if(disk_car->pread(disk_car, buffer, DEFAULT_SECTOR_SIZE, partition->part_offset) != DEFAULT_SECTOR_SIZE)
  {
    free(buffer);
    return 1;
  }
  if(test_NTFS(disk_car,(struct ntfs_boot_sector*)buffer,partition,verbose,dump_ind)!=0)
  {
    free(buffer);
    return 1;
  }
  set_NTFS_info(disk_car, (struct ntfs_boot_sector*)buffer, partition);
  free(buffer);
  return 0;
}

int recover_NTFS(disk_t *disk_car, const struct ntfs_boot_sector*ntfs_header,partition_t *partition,const int verbose, const int dump_ind, const int backup)
{
  uint64_t part_size;
  if(test_NTFS(disk_car,ntfs_header,partition,verbose,dump_ind)!=0)
    return 1;
  if(verbose>0)
  {
    log_ntfs_info(ntfs_header);
  }
  part_size=(uint64_t)(le64(ntfs_header->sectors_nbr)+1)*ntfs_sector_size(ntfs_header);
  partition->sborg_offset=0;
  partition->sb_size=512;
  if(backup>0)
  {
    if(partition->part_offset+disk_car->sector_size<part_size)
    {
      log_warning("NTFS part_offset=%llu, part_size=%llu, sector_size=%u\n",
	  (long long unsigned)partition->part_offset, (long long unsigned)part_size,
	  disk_car->sector_size);
      log_warning("NTFS partition cannot be added (part_offset<part_size).\n");
      return 1;
    }
    if(verbose>1)
      log_info("NTFS part_offset=%llu, part_size=%llu, sector_size=%u\n",
	  (long long unsigned)partition->part_offset, (long long unsigned)part_size,
	  disk_car->sector_size);
    partition->sb_offset=part_size-disk_car->sector_size;
    partition->part_offset-=partition->sb_offset;
    if(verbose>1)
      log_info("part_offset=%llu\n",(long long unsigned)partition->part_offset);
  }
  partition->part_size=part_size;
  partition->part_type_i386=P_NTFS;
  partition->part_type_gpt=GPT_ENT_TYPE_MS_BASIC_DATA;
  set_NTFS_info(disk_car, ntfs_header, partition);
  return 0;
}

static void set_NTFS_info(disk_t *disk_car, const struct ntfs_boot_sector*ntfs_header, partition_t *partition)
{
  partition->upart_type=UP_NTFS;
  partition->fsname[0]='\0';
  partition->blocksize=ntfs_header->sectors_per_cluster*ntfs_sector_size(ntfs_header);
  if(partition->sb_offset==0)
    snprintf(partition->info, sizeof(partition->info), "NTFS, blocksize=%u", partition->blocksize);
  else
    snprintf(partition->info, sizeof(partition->info), "NTFS found using backup sector, blocksize=%u", partition->blocksize);
  ntfs_get_volume_name(disk_car, partition, ntfs_header);
}

int test_NTFS(const disk_t *disk_car, const struct ntfs_boot_sector*ntfs_header, const partition_t *partition, const int verbose, const int dump_ind)
{
  if(le16(ntfs_header->marker)!=0xAA55 ||
      le16(ntfs_header->reserved)>0 ||
      ntfs_header->fats>0 ||
      ntfs_header->dir_entries[0]!=0 || ntfs_header->dir_entries[1]!=0 ||
      ntfs_header->sectors[0]!=0 || ntfs_header->sectors[1]!=0 ||
      le16(ntfs_header->fat_length)!=0 || le32(ntfs_header->total_sect)!=0 ||
      memcmp(ntfs_header->system_id,"NTFS",4)!=0 ||
      le64(ntfs_header->sectors_nbr)==0)
    return 1;
  switch(ntfs_header->sectors_per_cluster)
  {
    case 1: case 2: case 4: case 8: case 16: case 32: case 64: case 128:
      break;
    default:
      return 1;
  }
  if(verbose>0 || dump_ind!=0)
  {
    log_info("NTFS at %u/%u/%u\n", offset2cylinder(disk_car,partition->part_offset),offset2head(disk_car,partition->part_offset),offset2sector(disk_car,partition->part_offset));
  }
  if(le16(ntfs_header->heads)!=disk_car->geom.heads_per_cylinder)
  {
    screen_buffer_add("Warning: number of heads/cylinder mismatches %u (NTFS) != %u (HD)\n",
	le16(ntfs_header->heads), disk_car->geom.heads_per_cylinder);
    log_warning("heads/cylinder %u (NTFS) != %u (HD)\n",
	le16(ntfs_header->heads), disk_car->geom.heads_per_cylinder);
  }
  if(le16(ntfs_header->secs_track)!=disk_car->geom.sectors_per_head)
  {
    screen_buffer_add("Warning: number of sectors per track mismatches %u (NTFS) != %u (HD)\n",
	le16(ntfs_header->secs_track), disk_car->geom.sectors_per_head);
    log_warning("sect/track %u (NTFS) != %u (HD)\n",
	le16(ntfs_header->secs_track), disk_car->geom.sectors_per_head);
  }
  if(ntfs_sector_size(ntfs_header)!=disk_car->sector_size)
  {
    screen_buffer_add("Warning: number of bytes per sector mismatches %u (NTFS) != %u (HD)\n",
	ntfs_sector_size(ntfs_header), disk_car->sector_size);
    log_warning("Warning: number of bytes per sector mismatches %u (NTFS) != %u (HD)\n",
	ntfs_sector_size(ntfs_header), disk_car->sector_size);
  }

  if(partition->part_size>0)
  {
    uint64_t part_size;
    part_size=le64(ntfs_header->sectors_nbr)+1;

    if(part_size*ntfs_sector_size(ntfs_header)>partition->part_size)
    {
      screen_buffer_add("Error: size boot_sector %lu > partition %lu\n",(long unsigned)part_size,(long unsigned)(partition->part_size/disk_car->sector_size));
      log_error("Error: size boot_sector %lu > partition %lu\n",(long unsigned)part_size,(long unsigned)(partition->part_size/disk_car->sector_size));
      return 1;
    }
    if(verbose>0 && (part_size!=partition->part_size/disk_car->sector_size))
    {
      log_info("Info: size boot_sector %lu, partition %lu\n",(long unsigned)part_size,(long unsigned)(partition->part_size/disk_car->sector_size));
    }
  }
  return 0;
}

static const ntfs_attribheader *ntfs_getattributeheaders(const ntfs_recordheader* record)
{
  const char* location = (const char*)record;
  if(le32(record->magic)!=NTFS_Magic ||
      le16(record->attrs_offset)%8!=0 ||
      le16(record->attrs_offset)<42)
    return NULL;
  location += le16(record->attrs_offset);
  return (const ntfs_attribheader *)location;
}

static const ntfs_attribheader* ntfs_searchattribute(const ntfs_attribheader* attrib, uint32_t attrType, const char* end, int skip)
{
  if(attrib==NULL)
    return NULL;
  /* Now we should be at attributes */
  while((const char *)attrib + sizeof(ntfs_attribheader) < end &&
      le32(attrib->type)!= -1)
  {
    const unsigned int attr_len=le32(attrib->cbAttribute);
    if(attr_len%8!=0 || attr_len<0x18 || attr_len>0x10000000 ||
      (const char *)attrib + attr_len >= end)
      return NULL;
    if(!skip)
    {
      if(attrib->type == attrType)
	return attrib;
    }
    else
      skip = 0;
    attrib=(const ntfs_attribheader*)((const char*)attrib + attr_len);
  }
  return NULL;
}

const ntfs_attribheader* ntfs_findattribute(const ntfs_recordheader* record, uint32_t attrType, const char* end)
{
  const ntfs_attribheader *attrib = ntfs_getattributeheaders(record);
  return ntfs_searchattribute(attrib, attrType, end, 0);
}

#if 0
static const ntfs_attribheader* ntfs_nextattribute(const ntfs_attribheader* attrib, uint32_t attrType, const char* end)
{
  return ntfs_searchattribute(attrib, attrType, end, 1);
}
#endif

const char* ntfs_getattributedata(const ntfs_attribresident* attrib, const char* end)
{
  const char* data = ((const char*)attrib) + le16(attrib->offAttribData);
  if(le16(attrib->offAttribData)+le32(attrib->cbAttribData) > le32(attrib->header.cbAttribute) ||
      data > end)
    return NULL;
  return data;
}

long int ntfs_get_first_rl_element(const ntfs_attribnonresident *attrnr, const char* end)
{
  /* return first element of the run_list */
  /* buf must be unsigned! */
  const unsigned char *buf;
  uint8_t b;                   	/* Current byte offset in buf. */
  const unsigned char*attr_end;     /* End of attribute. */
  int64_t deltaxcn = (int64_t)-1;	/* Change in [vl]cn. */
  buf=(const unsigned char*)attrnr + le16(attrnr->offDataRuns);
  attr_end = (const unsigned char*)attrnr + le32(attrnr->header.cbAttribute);
  if((const char *)attr_end > end)
    return 0;
  b = *buf & 0xf;
  if(b==0)
  {
    log_error("Missing length entry in mapping pairs array.\n");
    return 0;
  }
  if (buf + b > attr_end)
  {
    log_error("Attribut AT_DATA: bad size\n");
    return 0;
  }
  for (deltaxcn = (int8_t)buf[b--]; b; b--)
    deltaxcn = (deltaxcn << 8) + (uint8_t)buf[b];
  /* Assume a negative length to indicate data corruption */
  if (deltaxcn < 0)
  {
    log_error("Invalid length in mapping pairs array.\n");
    return 0;
  }
  if (!(*buf & 0xf0))
  {
    log_info("LCN_HOLE\n");
    return 0;
  }
  {
    /* Get the lcn change which really can be negative. */
    const uint8_t b2 = *buf & 0xf;
    long lcn=0;
    b = b2 + ((*buf >> 4) & 0xf);
    if (buf + b > attr_end)
    {
      log_error("Attribut AT_DATA: bad size\n");
      return 0;
    }
    for (deltaxcn = (int8_t)buf[b--]; b > b2; b--)
      deltaxcn = (deltaxcn << 8) + (uint8_t)buf[b];
    /* Change the current lcn to it's new value. */
    lcn += deltaxcn;
    /* Check lcn is not below -1. */
    if (lcn < -1) {
      log_error("Invalid LCN < -1 in mapping pairs array.");
      return 0;
    }
    return lcn;
  }
}

static void ntfs_get_volume_name(disk_t *disk_car, partition_t *partition, const struct ntfs_boot_sector*ntfs_header)
{
  unsigned char *buffer;
  uint64_t mft_pos;
  unsigned int mft_record_size;
  if(ntfs_header->clusters_per_mft_record>0)
    mft_record_size=ntfs_header->clusters_per_mft_record * ntfs_header->sectors_per_cluster * ntfs_sector_size(ntfs_header);
  else
    mft_record_size=1<<(-ntfs_header->clusters_per_mft_record);
  mft_pos=partition->part_offset+(uint64_t)(le16(ntfs_header->reserved)+le64(ntfs_header->mft_lcn)*ntfs_header->sectors_per_cluster)*ntfs_sector_size(ntfs_header);
  /* Record 3 = $Volume */
  mft_pos+=3*mft_record_size;
#ifdef NTFS_DEBUG
  log_info("NTFS MFT cluster = %lu\n",le64(ntfs_header->mft_lcn));
  log_info("NTFS cluster size =    %5u sectors\n",ntfs_header->sectors_per_cluster);
  log_info("NTFS MFT_record_size = %5u bytes\n",mft_record_size);
  log_info("NTFS sector size =     %5u bytes\n", ntfs_sector_size(ntfs_header));
#endif
  if(mft_record_size < 42)
  {
    log_error("Invalid MFT record size or NTFS sector size\n");
    return;
  }
  buffer=(unsigned char *)MALLOC(mft_record_size);
  if((unsigned)disk_car->pread(disk_car, buffer, mft_record_size, mft_pos) != mft_record_size)
  {
    log_error("NTFS: Can't read MFT\n");
    free(buffer);
    return;
  }
  {
    const ntfs_attribresident *attrib=(const ntfs_attribresident *)ntfs_findattribute((const ntfs_recordheader*)buffer, 0x60, (char*)buffer+mft_record_size);
    if(attrib && attrib->header.bNonResident==0)	/* attribute is resident */
    {
      char *dest=partition->fsname;
      const char *name_it;
      unsigned int volume_name_length=le32(attrib->cbAttribData);
      volume_name_length/=2;	/* Unicode */
      if(volume_name_length>sizeof(partition->fsname)-1)
	volume_name_length=sizeof(partition->fsname)-1;
      for(name_it=ntfs_getattributedata(attrib, (char*)(buffer+mft_record_size));
	  volume_name_length>0 && *name_it!='\0' && name_it[1]=='\0';
	  name_it+=2,volume_name_length--)
	*dest++=*name_it;
      *dest='\0'; /* 27 january 2003: Correct a bug found by Andreas du Plessis-Denz */
    }
  }
  free(buffer);
  return;
}

int is_part_ntfs(const partition_t *partition)
{
  if(partition->arch==&arch_i386)
  {
    switch(partition->part_type_i386)
    {
      case P_NTFS:
      case P_NTFSH:
        return 1;
      default:
        break;
    }
  }
  /*
  else if(partition->arch==&arch_gpt)
  {
    if(guid_cmp(partition->part_type_gpt,GPT_ENT_TYPE_MS_BASIC_DATA)==0)
      return 1;
  }
  */
  return 0;
}

int is_ntfs(const partition_t *partition)
{
  return(is_part_ntfs(partition) || partition->upart_type==UP_NTFS);
}

int log_ntfs_info(const struct ntfs_boot_sector *ntfs_header)
{
  log_info("filesystem size           %llu\n", (long long unsigned)le64(ntfs_header->sectors_nbr)+1);
  log_info("sectors_per_cluster       %u\n", ntfs_header->sectors_per_cluster);
  log_info("mft_lcn                   %lu\n", (long unsigned int)le64(ntfs_header->mft_lcn));
  log_info("mftmirr_lcn               %lu\n", (long unsigned int)le64(ntfs_header->mftmirr_lcn));
  log_info("clusters_per_mft_record   %d\n", ntfs_header->clusters_per_mft_record);
  log_info("clusters_per_index_record %d\n", ntfs_header->clusters_per_index_record);
  return 0;
}
