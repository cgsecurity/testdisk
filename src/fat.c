/*

    File: fat.c

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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
 
#include <stdio.h>
#include <ctype.h>
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#include "types.h"
#include "common.h"
#include "fat.h"
#include "lang.h"
#include "fnctdsk.h"
#include "intrf.h"
#include "log.h"
#include "log_part.h"
#include "dir.h"
#include "fat_dir.h"

#if !defined(SINGLE_PARTITION_TYPE) || defined(SINGLE_PARTITION_I386)
extern const arch_fnct_t arch_i386;
#endif
#if !defined(SINGLE_PARTITION_TYPE) || defined(SINGLE_PARTITION_MAC)
extern const arch_fnct_t arch_mac;
#endif

/*@
  @ requires \valid_read(partition);
  @ assigns  \nothing;
  @*/
static int is_fat12(const partition_t *partition);

/*@
  @ requires \valid_read(partition);
  @ assigns  \nothing;
  @*/
static int is_fat16(const partition_t *partition);

/*@
  @ requires \valid_read(partition);
  @ assigns  \nothing;
  @*/
static int is_fat32(const partition_t *partition);

/*@
  @ requires \valid(disk_car);
  @ requires valid_disk(disk_car);
  @ requires \valid(partition);
  @ requires valid_partition(partition);
  @ requires \valid_read(fat_header);
  @ requires \separated(disk_car, partition, fat_header);
  @ decreases 0;
  @*/
static int fat32_set_part_name(disk_t *disk_car, partition_t *partition, const struct fat_boot_sector*fat_header)
{
  partition->fsname[0]='\0';
  if((fat_header->sectors_per_cluster>0)&&(fat_header->sectors_per_cluster<=128))
  {
    const unsigned int cluster_size=fat_header->sectors_per_cluster*disk_car->sector_size;
    unsigned char *buffer=(unsigned char*)MALLOC(cluster_size);
    if((unsigned)disk_car->pread(disk_car, buffer, cluster_size,
	  partition->part_offset + (le16(fat_header->reserved) + fat_header->fats * le32(fat_header->fat32_length) + (uint64_t)(le32(fat_header->root_cluster) - 2) * fat_header->sectors_per_cluster) * disk_car->sector_size) != cluster_size)
    {
#ifndef DISABLED_FOR_FRAMAC
      log_error("fat32_set_part_name() cannot read FAT32 root cluster.\n");
#endif
    }
    else
    {
      int i;
      int stop=0;
      for(i=0;(i<16*fat_header->sectors_per_cluster)&&(stop==0);i++)
      { /* Test attribut volume name and check if the volume name is erased or not */
        if(((buffer[i*0x20+0xB] & ATTR_EXT) !=ATTR_EXT) && ((buffer[i*0x20+0xB] & ATTR_VOLUME) !=0) && (buffer[i*0x20]!=0xE5))
        {
          set_part_name_chomp(partition, (const char *)&buffer[i*0x20],11);
          if(check_VFAT_volume_name(partition->fsname, 11))
            partition->fsname[0]='\0';
        }
        if(buffer[i*0x20]==0)
        {
          stop=1;
        }
      }
    }
    free(buffer);
  }
  if(partition->fsname[0]=='\0')
  {
#ifndef DISABLED_FOR_FRAMAC
    log_info("set_FAT_info: name from BS used\n");
#endif
    set_part_name_chomp(partition, (const char*)fat_header + FAT32_PART_NAME, 11);
    if(check_VFAT_volume_name(partition->fsname, 11))
      partition->fsname[0]='\0';
  }
  return 0;
}

/*@
  @ requires \valid(disk_car);
  @ requires \valid_read(fat_header);
  @ requires \valid(partition);
  @ requires \separated(disk_car, fat_header, partition);
  @*/
static void set_FAT_info(disk_t *disk_car, const struct fat_boot_sector *fat_header, partition_t *partition)
{
  uint64_t start_fat1;
  uint64_t start_data;
  uint64_t part_size;
  unsigned long int no_of_cluster;
  unsigned long int fat_length;
  const char *buffer=(const char*)fat_header;
  partition->fsname[0]='\0';
  partition->blocksize=fat_sector_size(fat_header)* fat_header->sectors_per_cluster;
  fat_length=le16(fat_header->fat_length)>0?le16(fat_header->fat_length):le32(fat_header->fat32_length);
  part_size=(fat_sectors(fat_header)>0?fat_sectors(fat_header):le32(fat_header->total_sect));
  start_fat1=le16(fat_header->reserved);
  start_data=start_fat1+fat_header->fats*fat_length+(get_dir_entries(fat_header)*32+fat_sector_size(fat_header)-1)/fat_sector_size(fat_header);
  no_of_cluster=(part_size-start_data)/fat_header->sectors_per_cluster;
  if(no_of_cluster<4085)
  {
    partition->upart_type=UP_FAT12;
    snprintf(partition->info, sizeof(partition->info), "FAT12, blocksize=%u", partition->blocksize);
    if(buffer[38]==0x29)	/* BS_BootSig */
    {
      set_part_name_chomp(partition, buffer+FAT1X_PART_NAME, 11);
      if(check_VFAT_volume_name(partition->fsname, 11))
	partition->fsname[0]='\0';
    }
  }
  else if(no_of_cluster<65525)
  {
    partition->upart_type=UP_FAT16;
    snprintf(partition->info, sizeof(partition->info), "FAT16, blocksize=%u", partition->blocksize);
    if(buffer[38]==0x29)	/* BS_BootSig */
    {
      set_part_name_chomp(partition, buffer+FAT1X_PART_NAME, 11);
      if(check_VFAT_volume_name(partition->fsname, 11))
	partition->fsname[0]='\0';
    }
  }
  else
  {
    partition->upart_type=UP_FAT32;
    if(partition->sb_offset==0)
      snprintf(partition->info, sizeof(partition->info), "FAT32, blocksize=%u", partition->blocksize);
    else
      snprintf(partition->info, sizeof(partition->info), "FAT32 found using backup sector, blocksize=%u", partition->blocksize);
    fat32_set_part_name(disk_car,partition,fat_header);
  }
}

/*@
  @ requires \valid_read(fh1);
  @*/
static int log_fat_info(const struct fat_boot_sector*fh1, const upart_type_t upart_type, const unsigned int sector_size)
{
#ifndef DISABLED_FOR_FRAMAC
  log_info("sector_size  %u\n", fat_sector_size(fh1));
  log_info("cluster_size %u\n", fh1->sectors_per_cluster);
  log_info("reserved     %u\n", le16(fh1->reserved));
  log_info("fats         %u\n", fh1->fats);
  log_info("dir_entries  %u\n", get_dir_entries(fh1));
  log_info("sectors      %u\n", fat_sectors(fh1));
  log_info("media        %02X\n", fh1->media);
  log_info("fat_length   %u\n", le16(fh1->fat_length));
  log_info("secs_track   %u\n", le16(fh1->secs_track));
  log_info("heads        %u\n", le16(fh1->heads));
  log_info("hidden       %u\n", (unsigned int)le32(fh1->hidden));
  log_info("total_sect   %u\n", (unsigned int)le32(fh1->total_sect));
  if(upart_type==UP_FAT32)
  {
      log_info("fat32_length %u\n", (unsigned int)le32(fh1->fat32_length));
      log_info("flags        %04X\n", le16(fh1->flags));
      log_info("version      %u.%u\n", fh1->version[0], fh1->version[1]);
      log_info("root_cluster %u\n", (unsigned int)le32(fh1->root_cluster));
      log_info("info_sector  %u\n", le16(fh1->info_sector));
      log_info("backup_boot  %u\n", le16(fh1->backup_boot));
      if(fat32_get_free_count((const unsigned char*)fh1,sector_size)==0xFFFFFFFF)
        log_info("free_count   uninitialised\n");
      else
        log_info("free_count   %lu\n",fat32_get_free_count((const unsigned char*)fh1,sector_size));
      if(fat32_get_next_free((const unsigned char*)fh1,sector_size)==0xFFFFFFFF)
        log_info("next_free    uninitialised\n");
      else
        log_info("next_free    %lu\n",fat32_get_next_free((const unsigned char*)fh1,sector_size));
  }
#endif
  return 0;
}

int log_fat2_info(const struct fat_boot_sector*fh1, const struct fat_boot_sector*fh2, const upart_type_t upart_type, const unsigned int sector_size)
{
#ifndef DISABLED_FOR_FRAMAC
  switch(upart_type)
  {
    case UP_FAT12:
      log_info("\nFAT12\n");
      break;
    case UP_FAT16:
      log_info("\nFAT16\n");
      break;
    case UP_FAT32:
      log_info("\nFAT32\n");
      break;
    default:
      return 1;
  }
  log_info("sector_size  %u %u\n", fat_sector_size(fh1),fat_sector_size(fh2));
  log_info("cluster_size %u %u\n", fh1->sectors_per_cluster,fh2->sectors_per_cluster);
  log_info("reserved     %u %u\n", le16(fh1->reserved),le16(fh2->reserved));
  log_info("fats         %u %u\n", fh1->fats,fh2->fats);
  log_info("dir_entries  %u %u\n", get_dir_entries(fh1),get_dir_entries(fh2));
  log_info("sectors      %u %u\n", fat_sectors(fh1),fat_sectors(fh2));
  log_info("media        %02X %02X\n", fh1->media,fh2->media);
  log_info("fat_length   %u %u\n", le16(fh1->fat_length),le16(fh2->fat_length));
  log_info("secs_track   %u %u\n", le16(fh1->secs_track),le16(fh2->secs_track));
  log_info("heads        %u %u\n", le16(fh1->heads),le16(fh2->heads));
  log_info("hidden       %u %u\n", (unsigned int)le32(fh1->hidden),(unsigned int)le32(fh2->hidden));
  log_info("total_sect   %u %u\n", (unsigned int)le32(fh1->total_sect),(unsigned int)le32(fh2->total_sect));
  if(upart_type==UP_FAT32)
  {
    log_info("fat32_length %u %u\n", (unsigned int)le32(fh1->fat32_length),(unsigned int)le32(fh2->fat32_length));
    log_info("flags        %04X %04X\n", le16(fh1->flags),le16(fh2->flags));
    log_info("version      %u.%u  %u.%u\n", fh1->version[0], fh1->version[1],fh2->version[0], fh2->version[1]);
    log_info("root_cluster %u %u\n", (unsigned int)le32(fh1->root_cluster),(unsigned int)le32(fh2->root_cluster));
    log_info("info_sector  %u %u\n", le16(fh1->info_sector),le16(fh2->info_sector));
    log_info("backup_boot  %u %u\n", le16(fh1->backup_boot),le16(fh2->backup_boot));
    log_info("free_count   ");
    if(fat32_get_free_count((const unsigned char*)fh1,sector_size)==0xFFFFFFFF)
      log_info("uninitialised ");
    else
      log_info("%lu ",fat32_get_free_count((const unsigned char*)fh1,sector_size));
    if(fat32_get_free_count((const unsigned char*)fh2,sector_size)==0xFFFFFFFF)
      log_info("uninitialised");
    else
      log_info("%lu",fat32_get_free_count((const unsigned char*)fh2,sector_size));
    log_info("\nnext_free    ");
    if(fat32_get_next_free((const unsigned char*)fh1,sector_size)==0xFFFFFFFF)
      log_info("uninitialised ");
    else
      log_info("%lu ",fat32_get_next_free((const unsigned char*)fh1,sector_size));
    if(fat32_get_next_free((const unsigned char*)fh2,sector_size)==0xFFFFFFFF)
      log_info("uninitialised\n");
    else
      log_info("%lu\n",fat32_get_next_free((const unsigned char*)fh2,sector_size));
  }
#endif
  return 0;
}

int check_FAT(disk_t *disk_car, partition_t *partition, const int verbose)
{
  unsigned char *buffer;
  buffer=(unsigned char *)MALLOC(3*disk_car->sector_size);
  if((unsigned)disk_car->pread(disk_car, buffer, 3 * disk_car->sector_size, partition->part_offset) != 3 * disk_car->sector_size)
  {
#ifndef DISABLED_FOR_FRAMAC
    screen_buffer_add("check_FAT: can't read FAT boot sector\n");
    log_error("check_FAT: can't read FAT boot sector\n");
#endif
    free(buffer);
    return 1;
  }
  if(test_FAT(disk_car,(const struct fat_boot_sector *)buffer,partition,verbose,0)!=0)
  {
#ifndef DISABLED_FOR_FRAMAC
    if(verbose>0)
    {
      log_error("\n\ntest_FAT()\n");
      log_partition(disk_car,partition);
      log_fat_info((const struct fat_boot_sector*)buffer, partition->upart_type,disk_car->sector_size);
    }
#endif
    free(buffer);
    return 1;
  }
  set_FAT_info(disk_car,(const struct fat_boot_sector *)buffer,partition);
  /*  screen_buffer_add("Ok\n"); */
  free(buffer);
  return 0;
}

/*@
  @ requires \valid(disk);
  @ requires valid_disk(disk);
  @ requires \valid_read(partition);
  @ requires valid_partition(partition);
  @ requires \separated(disk, partition);
  @ decreases 0;
  @*/
static unsigned int get_next_cluster_fat12(disk_t *disk, const partition_t *partition, const int offset, const unsigned int cluster)
{
  unsigned int next_cluster;
  unsigned long int offset_s;
  unsigned long int offset_o;
  unsigned char *buffer=(unsigned char*)MALLOC(2*disk->sector_size);
  offset_s=(cluster+cluster/2)/disk->sector_size;
  offset_o=(cluster+cluster/2)%disk->sector_size;
  if((unsigned)disk->pread(disk, buffer, 2 * disk->sector_size,
	partition->part_offset + (uint64_t)(offset + offset_s) * disk->sector_size) != 2 * disk->sector_size)
  {
#ifndef DISABLED_FOR_FRAMAC
    log_error("get_next_cluster_fat12 read error\n");
#endif
    free(buffer);
    return 0;
  }
  if((cluster&1)!=0)
    next_cluster=le16((*((uint16_t*)&buffer[offset_o])))>>4;
  else
    next_cluster=le16(*((uint16_t*)&buffer[offset_o]))&0x0FFF;
  free(buffer);
  return next_cluster;
}

/*@
  @ requires \valid(disk);
  @ requires valid_disk(disk);
  @ requires \valid_read(partition);
  @ requires valid_partition(partition);
  @ requires \separated(disk, partition);
  @ decreases 0;
  @*/
static unsigned int get_next_cluster_fat16(disk_t *disk, const partition_t *partition, const int offset, const unsigned int cluster)
{
  unsigned int next_cluster;
  unsigned long int offset_s;
  unsigned long int offset_o;
  unsigned char *buffer=(unsigned char*)MALLOC(disk->sector_size);
  const uint16_t *p16=(const uint16_t*)buffer;
  offset_s=cluster/(disk->sector_size/2);
  offset_o=cluster%(disk->sector_size/2);
  if((unsigned)disk->pread(disk, buffer, disk->sector_size,
	partition->part_offset + (uint64_t)(offset + offset_s) * disk->sector_size) != disk->sector_size)
  {
#ifndef DISABLED_FOR_FRAMAC
    log_error("get_next_cluster_fat16 read error\n");
#endif
    free(buffer);
    return 0;
  }
  next_cluster=le16(p16[offset_o]);
  free(buffer);
  return next_cluster;
}

/*@
  @ requires \valid(disk);
  @ requires valid_disk(disk);
  @ requires \valid_read(partition);
  @ requires valid_partition(partition);
  @ requires \separated(disk, partition);
  @ decreases 0;
  @*/
static unsigned int get_next_cluster_fat32(disk_t *disk, const partition_t *partition, const int offset, const unsigned int cluster)
{
  unsigned int next_cluster;
  unsigned long int offset_s;
  unsigned long int offset_o;
  unsigned char *buffer=(unsigned char*)MALLOC(disk->sector_size);
  const uint32_t *p32=(const uint32_t*)buffer;
  offset_s=cluster/(disk->sector_size/4);
  offset_o=cluster%(disk->sector_size/4);
  if((unsigned)disk->pread(disk, buffer, disk->sector_size,
	partition->part_offset + (uint64_t)(offset + offset_s) * disk->sector_size) != disk->sector_size)
  {
#ifndef DISABLED_FOR_FRAMAC
    log_error("get_next_cluster_fat32 read error\n");
#endif
    free(buffer);
    return 0;
  }
  /* FAT32 used 28 bits, the 4 high bits are reserved
   * 0x00000000: free cluster
   * 0x0FFFFFF7: bad cluster
   * 0x0FFFFFF8+: EOC End of cluster
   * */
  next_cluster=le32(p32[offset_o])&0xFFFFFFF;
  free(buffer);
  return next_cluster;
}

unsigned int get_next_cluster(disk_t *disk,const partition_t *partition, const upart_type_t upart_type,const int offset, const unsigned int cluster)
{
  /* Offset can be offset to FAT1 or to FAT2 */
  switch(upart_type)
  {
    case UP_FAT12:
      return get_next_cluster_fat12(disk, partition, offset, cluster);
    case UP_FAT16:
      return get_next_cluster_fat16(disk, partition, offset, cluster);
    case UP_FAT32:
      return get_next_cluster_fat32(disk, partition, offset, cluster);
    default:
#ifndef DISABLED_FOR_FRAMAC
      log_critical("fat.c get_next_cluster unknown fat type\n");
#endif
      return 0;
  }
}

int set_next_cluster(disk_t *disk_car,const partition_t *partition, const upart_type_t upart_type,const int offset, const unsigned int cluster, const unsigned int next_cluster)
{
  unsigned char *buffer;
  unsigned long int offset_s,offset_o;
  const unsigned int buffer_size=(upart_type==UP_FAT12?2*disk_car->sector_size:disk_car->sector_size);
  buffer=(unsigned char*)MALLOC(buffer_size);
  /* Offset can be offset to FAT1 or to FAT2 */
  /*  log_trace("set_next_cluster(upart_type=%u,offset=%u,cluster=%u,next_cluster=%u)\n",upart_type,offset,cluster,next_cluster); */
  switch(upart_type)
  {
    case UP_FAT12:
      offset_s=(cluster+cluster/2)/disk_car->sector_size;
      offset_o=(cluster+cluster/2)%disk_car->sector_size;
      break;
    case UP_FAT16:
      offset_s=cluster/(disk_car->sector_size/2);
      offset_o=cluster%(disk_car->sector_size/2);
      break;
    case UP_FAT32:
      offset_s=cluster/(disk_car->sector_size/4);
      offset_o=cluster%(disk_car->sector_size/4);
      break;
    default:
#ifndef DISABLED_FOR_FRAMAC
      log_critical("fat.c set_next_cluster unknown fat type\n");
#endif
      free(buffer);
      return 1;
  }
  if((unsigned)disk_car->pread(disk_car, buffer, buffer_size,
	partition->part_offset + (uint64_t)(offset + offset_s) * disk_car->sector_size) != buffer_size)
  {
#ifndef DISABLED_FOR_FRAMAC
    log_error("set_next_cluster read error\n");
#endif
    free(buffer);
    return 1;
  }
  switch(upart_type)
  {
    case UP_FAT12:
      if((cluster&1)!=0)
        (*((uint16_t*)&buffer[offset_o]))=le16((next_cluster<<4) | (le16(*((uint16_t*)&buffer[offset_o]))&0xF));
      else
        (*((uint16_t*)&buffer[offset_o]))=le16((next_cluster) |  (le16(*((uint16_t*)&buffer[offset_o]))&0xF000));
      break;
    case UP_FAT16:
      {
        uint16_t *p16=(uint16_t*)buffer;
        p16[offset_o]=le16(next_cluster);
      }
      break;
    case UP_FAT32:
      {
        uint32_t *p32=(uint32_t*)buffer;
        /* FAT32 used 28 bits, the 4 high bits are reserved
         * 0x00000000: free cluster
         * 0x0FFFFFF7: bad cluster
         * 0x0FFFFFF8+: EOC End of cluster
         * */
        p32[offset_o]=le32(next_cluster);
      }
      break;
    default:	/* Avoid compiler warning */
      break;
  }
  if((unsigned)disk_car->pwrite(disk_car, buffer, buffer_size, partition->part_offset + (uint64_t)(offset + offset_s) * disk_car->sector_size) != buffer_size)
  {
#ifndef DISABLED_FOR_FRAMAC
    log_error("Write error: set_next_cluster write error\n");
#endif
    free(buffer);
    return 1;
  }
  free(buffer);
  return 0;
}

unsigned int fat32_get_prev_cluster(disk_t *disk_car,const partition_t *partition, const unsigned int fat_offset, const unsigned int cluster, const unsigned int no_of_cluster)
{
  const uint32_t *p32;
  uint64_t hd_offset=partition->part_offset+(uint64_t)fat_offset*disk_car->sector_size;
  unsigned int prev_cluster;
  unsigned char *buffer=(unsigned char *)MALLOC(disk_car->sector_size);
  p32=(const uint32_t*)buffer;

  for(prev_cluster=2;prev_cluster<=no_of_cluster+1;prev_cluster++)
  {
    const unsigned int offset_o=prev_cluster%(disk_car->sector_size/4);
    if((offset_o==0)||(prev_cluster==2))
    {
      if((unsigned)disk_car->pread(disk_car, buffer, disk_car->sector_size, hd_offset) != disk_car->sector_size)
      {
#ifndef DISABLED_FOR_FRAMAC
        log_error("fat32_get_prev_cluster error\n");
#endif
	return 0;
      }
      hd_offset+=disk_car->sector_size;
    }
    if((le32(p32[offset_o]) & 0xFFFFFFF) ==cluster)
    {
      free(buffer);
      return prev_cluster;
    }
  }
  free(buffer);
  return 0;
}

/*
static unsigned int get_prev_cluster(disk_t *disk_car,const partition_t *partition, const upart_type_t upart_type,const int offset, const unsigned int cluster, const unsigned int no_of_cluster)
{
  unsigned int prev_cluster;
  for(prev_cluster=2;prev_cluster<=no_of_cluster+1;prev_cluster++)
  {
    if(get_next_cluster(disk_car,partition,upart_type,offset, prev_cluster)==cluster)
      return prev_cluster;
  }
  return 0;
}
*/

int test_FAT(disk_t *disk_car, const struct fat_boot_sector *fat_header, const partition_t *partition, const int verbose, const int dump_ind)
{
  uint64_t start_fat1;
  uint64_t start_fat2;
  uint64_t start_rootdir;
  uint64_t start_data;
  uint64_t part_size;
  uint64_t end_data;
  unsigned long int no_of_cluster;
  unsigned long int fat_length;
  unsigned long int fat_length_calc;
  const char *buffer=(const char*)fat_header;
  if(!(le16(fat_header->marker)==0xAA55
        && (fat_header->ignored[0]==0xeb || fat_header->ignored[0]==0xe9)
        && (fat_header->fats==1 || fat_header->fats==2)))
    return 1;   /* Obviously not a FAT */
#ifndef DISABLED_FOR_FRAMAC
  if(verbose>1 || dump_ind!=0)
  {
    log_trace("test_FAT\n");
    log_partition(disk_car, partition);
  }
#endif
  if(dump_ind!=0)
    dump_log(fat_header, DEFAULT_SECTOR_SIZE);
  if(!((fat_header->ignored[0]==0xeb && fat_header->ignored[2]==0x90)||fat_header->ignored[0]==0xe9))
  {
#ifndef DISABLED_FOR_FRAMAC
    screen_buffer_add(msg_CHKFAT_BAD_JUMP);
    log_error(msg_CHKFAT_BAD_JUMP);
#endif
    return 1;
  }
  switch(fat_header->sectors_per_cluster)
  {
    case 1:
    case 2:
    case 4:
    case 8:
    case 16:
    case 32:
    case 64:
    case 128:
      break;
    default:
#ifndef DISABLED_FOR_FRAMAC
      screen_buffer_add(msg_CHKFAT_SECT_CLUSTER);
      log_error(msg_CHKFAT_SECT_CLUSTER);
#endif
      return 1;
  }
  switch(fat_header->fats)
  {
    case 1:
#ifndef DISABLED_FOR_FRAMAC
      screen_buffer_add("check_FAT: Unusual, only one FAT\n");
      log_warning("check_FAT: Unusual, only one FAT\n");
#endif
      break;
    case 2:
      break;
    default:
#ifndef DISABLED_FOR_FRAMAC
      screen_buffer_add("check_FAT: Bad number %u of FAT\n", fat_header->fats);
      log_error("check_FAT: Bad number %u of FAT\n", fat_header->fats);
#endif
      return 1;
  }
  if(fat_sector_size(fat_header)!=disk_car->sector_size)
  {
#ifndef DISABLED_FOR_FRAMAC
    screen_buffer_add("check_FAT: number of bytes per sector mismatches %u (FAT) != %u (HD)\n",
	fat_sector_size(fat_header), disk_car->sector_size);
    log_error("check_FAT: number of bytes per sector mismatches %u (FAT) != %u (HD)\n",
	fat_sector_size(fat_header), disk_car->sector_size);
#endif
    return 1;
  }
  fat_length=le16(fat_header->fat_length)>0?le16(fat_header->fat_length):le32(fat_header->fat32_length);
  part_size=(fat_sectors(fat_header)>0?fat_sectors(fat_header):le32(fat_header->total_sect));
  start_fat1=le16(fat_header->reserved);
  start_fat2=start_fat1+(fat_header->fats>1?fat_length:0);
  start_data=start_fat1+fat_header->fats*fat_length+(get_dir_entries(fat_header)*32+fat_sector_size(fat_header)-1)/fat_sector_size(fat_header);
  no_of_cluster=(part_size-start_data)/fat_header->sectors_per_cluster;
  end_data=start_data+no_of_cluster*fat_header->sectors_per_cluster-1;
#ifndef DISABLED_FOR_FRAMAC
  if(verbose>1)
  {
    log_info("number of cluster = %lu\n",no_of_cluster);
  }
#endif
  if(fat_header->media!=0xF0 && fat_header->media<0xF8)
  {	/* Legal values are 0xF0, 0xF8-0xFF */
#ifndef DISABLED_FOR_FRAMAC
    screen_buffer_add("check_FAT: Bad media descriptor (0x%02x!=0xf8)\n",fat_header->media);
    log_error("check_FAT: Bad media descriptor (0x%02x!=0xf8)\n",fat_header->media);
#endif
    return 1;
  }
  if(no_of_cluster<4085)
  {
#ifndef DISABLED_FOR_FRAMAC
    if(verbose>0)
    {
      log_info("FAT12 at %u/%u/%u\n",
          offset2cylinder(disk_car,partition->part_offset),
          offset2head(disk_car,partition->part_offset),
          offset2sector(disk_car,partition->part_offset));
    }
    if(fat_sectors(fat_header)==0)
    {
      screen_buffer_add(msg_CHKFAT_SIZE);
      log_error(msg_CHKFAT_SIZE);
    }
    if(le16(fat_header->reserved)!=1)
    {
      screen_buffer_add("check_FAT: Unusual number of reserved sectors %u (FAT), should be 1.\n",le16(fat_header->reserved));
      log_warning("check_FAT: Unusual number of reserved sectors %u (FAT), should be 1.\n",le16(fat_header->reserved));
    }
#endif
    if((get_dir_entries(fat_header)==0)||(get_dir_entries(fat_header)%16!=0))
    {
#ifndef DISABLED_FOR_FRAMAC
      screen_buffer_add(msg_CHKFAT_ENTRY);
      log_error(msg_CHKFAT_ENTRY);
#endif
      return 1;
    }
    if((le16(fat_header->fat_length)>256)||(le16(fat_header->fat_length)==0))
    {
#ifndef DISABLED_FOR_FRAMAC
      screen_buffer_add(msg_CHKFAT_SECTPFAT);
      log_error(msg_CHKFAT_SECTPFAT);
#endif
      return 1;
    }
    start_rootdir=start_fat2+fat_length;
    fat_length_calc=((no_of_cluster+2+fat_sector_size(fat_header)*2/3-1)*3/2/fat_sector_size(fat_header));
#ifndef DISABLED_FOR_FRAMAC
    if(memcmp(buffer+FAT_NAME1,"FAT12   ",8)!=0) /* 2 Mo max */
    {
      screen_buffer_add("Should be marked as FAT12\n");
      log_warning("Should be marked as FAT12\n");
    }
    if(fat_header->media!=0xF0)
    {
      screen_buffer_add("check_FAT: Unusual media descriptor (0x%02x!=0xf0)\n", fat_header->media);
      log_warning("check_FAT: Unusual media descriptor (0x%02x!=0xf0)\n", fat_header->media);
    }
#endif
  }
  else if(no_of_cluster<65525)
  {
#ifndef DISABLED_FOR_FRAMAC
    if(verbose>0)
    {
      log_info("FAT16 at %u/%u/%u\n",
          offset2cylinder(disk_car,partition->part_offset),
          offset2head(disk_car,partition->part_offset),
          offset2sector(disk_car,partition->part_offset));
    }
    if(le16(fat_header->reserved)!=1)
    {
      screen_buffer_add("check_FAT: Unusual number of reserved sectors %u (FAT), should be 1.\n",le16(fat_header->reserved));
      log_warning("check_FAT: Unusual number of reserved sectors %u (FAT), should be 1.\n",le16(fat_header->reserved));
    }
#endif
    if(le16(fat_header->fat_length)==0)
    {
#ifndef DISABLED_FOR_FRAMAC
      screen_buffer_add(msg_CHKFAT_SECTPFAT);
      log_error(msg_CHKFAT_SECTPFAT);
#endif
      return 1;
    }
    if((get_dir_entries(fat_header)==0)||(get_dir_entries(fat_header)%16!=0))
    {
#ifndef DISABLED_FOR_FRAMAC
      screen_buffer_add(msg_CHKFAT_ENTRY);
      log_error(msg_CHKFAT_ENTRY);
#endif
      return 1;
    }
    start_rootdir=start_fat2+fat_length;
    fat_length_calc=((no_of_cluster+2+fat_sector_size(fat_header)/2-1)*2/fat_sector_size(fat_header));
#ifndef DISABLED_FOR_FRAMAC
    if(memcmp(buffer+FAT_NAME1,"FAT16   ",8)!=0)
    {
      screen_buffer_add("Should be marked as FAT16\n");
      log_warning("Should be marked as FAT16\n");
    }
    if(fat_header->media!=0xF8)
    { /* the only value I have ever seen is 0xF8 */
      screen_buffer_add("check_FAT: Unusual media descriptor (0x%02x!=0xf8)\n", fat_header->media);
      log_warning("check_FAT: Unusual media descriptor (0x%02x!=0xf8)\n", fat_header->media);
    }
#endif
  }
  else
  {
#ifndef DISABLED_FOR_FRAMAC
    if(verbose>0)
    {
      log_info("FAT32 at %u/%u/%u\n",
          offset2cylinder(disk_car,partition->part_offset),
          offset2head(disk_car,partition->part_offset),
          offset2sector(disk_car,partition->part_offset));
    }
#endif
    if(fat_sectors(fat_header)!=0)
    {
#ifndef DISABLED_FOR_FRAMAC
      screen_buffer_add(msg_CHKFAT_SIZE);
      log_error(msg_CHKFAT_SIZE);
#endif
      return 1;
    }
    if(get_dir_entries(fat_header)!=0)
    {
#ifndef DISABLED_FOR_FRAMAC
      screen_buffer_add(msg_CHKFAT_ENTRY);
      log_error(msg_CHKFAT_ENTRY);
#endif
      return 1;
    }
#ifndef DISABLED_FOR_FRAMAC
    if((fat_header->version[0]!=0) || (fat_header->version[1]!=0))
    {
      screen_buffer_add(msg_CHKFAT_BADFAT32VERSION);
      log_error(msg_CHKFAT_BADFAT32VERSION);
    }
#endif
    if((le32(fat_header->root_cluster)<2) ||(le32(fat_header->root_cluster)>=2+no_of_cluster))
    {
#ifndef DISABLED_FOR_FRAMAC
      screen_buffer_add("Bad root_cluster\n");
      log_error("Bad root_cluster\n");
#endif
      return 1;
    }
    start_rootdir=start_data+(uint64_t)(le32(fat_header->root_cluster)-2)*fat_header->sectors_per_cluster;
    fat_length_calc=((no_of_cluster+2+fat_sector_size(fat_header)/4-1)*4/fat_sector_size(fat_header));
#ifndef DISABLED_FOR_FRAMAC
    if(memcmp(buffer+FAT_NAME2,"FAT32   ",8)!=0)
    {
      screen_buffer_add("Should be marked as FAT32\n");
      log_warning("Should be marked as FAT32\n");
    }
    if(fat_header->media!=0xF8)
    { /* the only value I have ever seen is 0xF8 */
      screen_buffer_add("check_FAT: Unusual media descriptor (0x%02x!=0xf8)\n", fat_header->media);
      log_warning("check_FAT: Unusual media descriptor (0x%02x!=0xf8)\n", fat_header->media);
    }
    if(fat_header->BS_DrvNum!=0 && (fat_header->BS_DrvNum<0x80 || fat_header->BS_DrvNum>0x87))
    {
      screen_buffer_add("Warning: Unusual drive number (0x%02x!=0x80)\n", fat_header->BS_DrvNum);
      log_warning("Warning: Unusual drive number (0x%02x!=0x80)\n", fat_header->BS_DrvNum);
    }
#endif
  }
  if(partition->part_size>0)
  {
    if(part_size > partition->part_size/fat_sector_size(fat_header))
    {
#ifndef DISABLED_FOR_FRAMAC
      screen_buffer_add( "Error: size boot_sector %lu > partition %lu\n",
          (long unsigned)part_size,
          (long unsigned)(partition->part_size/fat_sector_size(fat_header)));
      log_error("test_FAT size boot_sector %lu > partition %lu\n",
          (long unsigned)part_size,
          (long unsigned)(partition->part_size/fat_sector_size(fat_header)));
#endif
      return 1;
    }
    else
    {
#ifndef DISABLED_FOR_FRAMAC
      if(verbose>0 && part_size!=partition->part_size)
        log_info("Info: size boot_sector %lu, partition %lu\n",
            (long unsigned)part_size,
            (long unsigned)(partition->part_size/fat_sector_size(fat_header)));
#endif
    }
  }
#ifndef DISABLED_FOR_FRAMAC
  if(verbose>0)
  {
    log_info("FAT1 : %lu-%lu\n", (long unsigned)start_fat1, (long unsigned)(start_fat1+fat_length-1));
    log_info("FAT2 : %lu-%lu\n", (long unsigned)start_fat2, (long unsigned)(start_fat2+fat_length-1));
    log_info("start_rootdir : %lu", (long unsigned)start_rootdir);
    if(no_of_cluster >= 65525)	/* FAT32 */
      log_info(" root cluster : %u",(unsigned int)le32(fat_header->root_cluster));
    log_info("\nData : %lu-%lu\n", (long unsigned)start_data, (long unsigned)end_data);
    log_info("sectors : %lu\n", (long unsigned)part_size);
    log_info("cluster_size : %u\n", fat_header->sectors_per_cluster);
    log_info("no_of_cluster : %lu (2 - %lu)\n", no_of_cluster,no_of_cluster+1);
    log_info("fat_length %lu calculated %lu\n",fat_length,fat_length_calc);
  }
#endif
  if(fat_length<fat_length_calc)
  {
#ifndef DISABLED_FOR_FRAMAC
    screen_buffer_add(msg_CHKFAT_SECTPFAT);
#endif
    return 1;
  }
  if(fat_header->fats>1)
    comp_FAT(disk_car,partition,fat_length,le16(fat_header->reserved));
#ifndef DISABLED_FOR_FRAMAC
  if(le16(fat_header->heads)!=disk_car->geom.heads_per_cylinder)
  {
    screen_buffer_add("Warning: number of heads/cylinder mismatches %u (FAT) != %u (HD)\n",
	le16(fat_header->heads), disk_car->geom.heads_per_cylinder);
    log_warning("heads/cylinder %u (FAT) != %u (HD)\n",
	le16(fat_header->heads), disk_car->geom.heads_per_cylinder);
  }
  if(le16(fat_header->secs_track)!=disk_car->geom.sectors_per_head)
  {
    screen_buffer_add("Warning: number of sectors per track mismatches %u (FAT) != %u (HD)\n",
	le16(fat_header->secs_track), disk_car->geom.sectors_per_head);
    log_warning("sect/track %u (FAT) != %u (HD)\n",
	le16(fat_header->secs_track), disk_car->geom.sectors_per_head);
  }
#endif
  return 0;
}

int comp_FAT(disk_t *disk, const partition_t *partition, const unsigned long int fat_size, const unsigned long int sect_res)
{
  /*
  return 0 if FATs match
  */
  unsigned int reste;
  uint64_t hd_offset;
  uint64_t hd_offset2;
  unsigned char *buffer;
  unsigned char *buffer2;
  buffer=(unsigned char *)MALLOC(16*disk->sector_size);
  buffer2=(unsigned char *)MALLOC(16*disk->sector_size);
  hd_offset=partition->part_offset+(uint64_t)sect_res*disk->sector_size;
  hd_offset2=hd_offset+(uint64_t)fat_size*disk->sector_size;
  reste=(fat_size>1000?1000:fat_size); /* Quick check ! */
  reste*=disk->sector_size;
  while(reste>0)
  {
    const unsigned int read_size=(reste > 16 * disk->sector_size ? 16 * disk->sector_size :reste);
    reste-=read_size;
    if((unsigned)disk->pread(disk, buffer, read_size, hd_offset) != read_size)
    {
#ifndef DISABLED_FOR_FRAMAC
      log_error("comp_FAT: can't read FAT1\n");
#endif
      free(buffer2);
      free(buffer);
      return 1;
    }
    if((unsigned)disk->pread(disk, buffer2, read_size, hd_offset2) != read_size)
    {
#ifndef DISABLED_FOR_FRAMAC
      log_error("comp_FAT: can't read FAT2\n");
#endif
      free(buffer2);
      free(buffer);
      return 1;
    }
    if(memcmp(buffer, buffer2, read_size)!=0)
    {
#ifndef DISABLED_FOR_FRAMAC
      log_error("FAT differs, FAT sectors=%lu-%lu/%lu\n",
          (unsigned long) ((hd_offset-partition->part_offset)/disk->sector_size-sect_res),
          (unsigned long) ((hd_offset-partition->part_offset+read_size)/disk->sector_size-sect_res),
          fat_size);
#endif
      free(buffer2);
      free(buffer);
      return 1;
    }
    hd_offset+=read_size;
    hd_offset2+=read_size;
  }
  free(buffer2);
  free(buffer);
  return 0;
}

unsigned long int fat32_get_free_count(const unsigned char *boot_fat32, const unsigned int sector_size)
{
  const struct fat_fsinfo *fsinfo=(const struct fat_fsinfo *)&boot_fat32[sector_size];
  /*@ assert \valid_read(fsinfo); */
  return le32(fsinfo->freecnt);
}

unsigned long int fat32_get_next_free(const unsigned char *boot_fat32, const unsigned int sector_size)
{
  const struct fat_fsinfo *fsinfo=(const struct fat_fsinfo *)&boot_fat32[sector_size];
  /*@ assert \valid_read(fsinfo); */
  return le32(fsinfo->nextfree);
}

/*@
  @ requires \valid(disk);
  @ requires valid_disk(disk);
  @ requires \valid_read(partition);
  @ requires valid_partition(partition);
  @ requires \separated(disk, partition);
  @ decreases 0;
  @*/
static int fat_has_EFI_entry(disk_t *disk, const partition_t *partition, const int verbose)
{
#ifndef DISABLED_FOR_FRAMAC
  dir_data_t dir_data;
  struct td_list_head *file_walker = NULL;
  file_info_t dir_list;
  const dir_partition_t res=dir_partition_fat_init(disk, partition, &dir_data, verbose);
  if(res!=DIR_PART_OK)
    return 0;
  TD_INIT_LIST_HEAD(&dir_list.list);
  dir_data.get_dir(disk, partition, &dir_data, 0, &dir_list);
  td_list_for_each(file_walker, &dir_list.list)
  {
    const file_info_t *current_file=td_list_entry_const(file_walker, const file_info_t, list);
    if(strcmp(current_file->name, "EFI")==0)
    {
      delete_list_file(&dir_list);
      dir_data.close(&dir_data);
      return 1;
    }
  }
  delete_list_file(&dir_list);
  dir_data.close(&dir_data);
#endif
  return 0;
}

int recover_FAT(disk_t *disk_car, const struct fat_boot_sector*fat_header, partition_t *partition, const int verbose, const int dump_ind, const int backup)
{
  int efi=0;
  if(test_FAT(disk_car, fat_header, partition, verbose, dump_ind))
    return 1;
  partition->part_size=(uint64_t)(fat_sectors(fat_header)>0?fat_sectors(fat_header):le32(fat_header->total_sect)) *
    fat_sector_size(fat_header);
  /* test_FAT has set partition->upart_type */
  partition->sborg_offset=0;
  partition->sb_size=512;
  partition->sb_offset=0;
  set_FAT_info(disk_car, fat_header, partition);
  switch(partition->upart_type)
  {
    case UP_FAT12:
#ifndef DISABLED_FOR_FRAMAC
      if(verbose||dump_ind)
      {
        log_info("\nFAT12 at %u/%u/%u\n",
            offset2cylinder(disk_car,partition->part_offset),
            offset2head(disk_car,partition->part_offset),
            offset2sector(disk_car,partition->part_offset));
      }
#endif
      partition->part_type_i386=P_12FAT;
      partition->part_type_gpt=GPT_ENT_TYPE_MS_BASIC_DATA;
      break;
    case UP_FAT16:
#ifndef DISABLED_FOR_FRAMAC
      if(verbose||dump_ind)
      {
        log_info("\nFAT16 at %u/%u/%u\n",
            offset2cylinder(disk_car,partition->part_offset),
            offset2head(disk_car,partition->part_offset),
            offset2sector(disk_car,partition->part_offset));
      }
#endif
      if(fat_sectors(fat_header)!=0)
        partition->part_type_i386=P_16FAT;
      else if(offset2cylinder(disk_car,partition->part_offset+partition->part_size-1)<=1024)
        partition->part_type_i386=P_16FATBD;
      else
        partition->part_type_i386=P_16FATBD_LBA;
      partition->part_type_gpt=GPT_ENT_TYPE_MS_BASIC_DATA;
      break;
    case UP_FAT32:
#ifndef DISABLED_FOR_FRAMAC
      if(verbose||dump_ind)
      {
        log_info("\nFAT32 at %u/%u/%u\n",
            offset2cylinder(disk_car,partition->part_offset),
            offset2head(disk_car,partition->part_offset),
            offset2sector(disk_car,partition->part_offset));
      }
#endif
      if(offset2cylinder(disk_car,partition->part_offset+partition->part_size-1)<=1024)
        partition->part_type_i386=P_32FAT;
      else
        partition->part_type_i386=P_32FAT_LBA;
      partition->part_type_mac=PMAC_FAT32;
      partition->part_type_gpt=GPT_ENT_TYPE_MS_BASIC_DATA;
      if(backup)
      {
        partition->sb_offset=6*512;
        partition->part_offset-=partition->sb_offset;  /* backup sector */
      }
      break;
    default:
#ifndef DISABLED_FOR_FRAMAC
      log_critical("recover_FAT unknown FAT type\n");
#endif
      return 1;
  }
  if(memcmp(partition->fsname,"EFI",4)==0)
    efi=1;
  if(efi==0)
    efi=fat_has_EFI_entry(disk_car, partition, verbose);
  if(efi)
  {
    partition->part_type_gpt=GPT_ENT_TYPE_EFI;
    strcpy(partition->partname, "EFI System Partition");
  }
  return 0;
}

/*@
  @ requires \valid_read(disk);
  @ requires valid_disk(disk);
  @ requires \valid_read(fat_header);
  @ requires \valid_read(partition);
  @ requires valid_partition(partition);
  @*/
static int test_OS2MB(const disk_t *disk, const struct fat_boot_sector *fat_header, const partition_t *partition, const int verbose, const int dump_ind)
{
  const char*buffer=(const char*)fat_header;
  if(le16(fat_header->marker)==0xAA55 && memcmp(buffer+FAT_NAME1,"FAT     ",8)==0)
  {
#ifndef DISABLED_FOR_FRAMAC
    if(verbose||dump_ind)
    {
      log_info("OS2MB at %u/%u/%u\n",
	  offset2cylinder(disk, partition->part_offset),
	  offset2head(disk, partition->part_offset),
	  offset2sector(disk, partition->part_offset));
    }
#endif
    if(dump_ind)
      dump_log(buffer, DEFAULT_SECTOR_SIZE);
    return 0;
  }
  return 1;
}

int check_OS2MB(disk_t *disk, partition_t *partition, const int verbose)
{
  unsigned char *buffer=(unsigned char *)MALLOC(disk->sector_size);
  if((unsigned)disk->pread(disk, buffer, disk->sector_size, partition->part_offset) != disk->sector_size)
  {
#ifndef DISABLED_FOR_FRAMAC
    screen_buffer_add("check_OS2MB: Read error\n");
    log_error("check_OS2MB: Read error\n");
#endif
    free(buffer);
    return 1;
  }
  if(test_OS2MB(disk,(const struct fat_boot_sector *)buffer,partition,verbose,0)!=0)
  {
#ifndef DISABLED_FOR_FRAMAC
    if(verbose>0)
    {
      log_info("\n\ntest_OS2MB()\n");
      log_partition(disk, partition);
    }
#endif
    free(buffer);
    return 1;
  }
  partition->upart_type=UP_OS2MB;
  free(buffer);
  return 0;
}

int recover_OS2MB(const disk_t *disk, const struct fat_boot_sector*fat_header, partition_t *partition, const int verbose, const int dump_ind)
{
  if(test_OS2MB(disk, fat_header, partition, verbose, dump_ind))
    return 1;
  /* 1 cylinder */
  partition->upart_type=UP_OS2MB;
  partition->part_size=(uint64_t)disk->geom.heads_per_cylinder * disk->geom.sectors_per_head * disk->sector_size;
  partition->part_type_i386=P_OS2MB;
  partition->fsname[0]='\0';
  partition->info[0]='\0';
  return 0;
}

int is_fat(const partition_t *partition)
{
  return (is_fat12(partition)||is_fat16(partition)||is_fat32(partition));
}

int is_part_fat(const partition_t *partition)
{
  return (is_part_fat12(partition)||is_part_fat16(partition)||is_part_fat32(partition));
}

int is_part_fat12(const partition_t *partition)
{
#if !defined(SINGLE_PARTITION_TYPE) || defined(SINGLE_PARTITION_I386)
  if(partition->arch==&arch_i386)
  {
    switch(partition->part_type_i386)
    {
      case P_12FAT:
      case P_12FATH:
        return 1;
      default:
        break;
    }
  }
#endif
  return 0;
}

static int is_fat12(const partition_t *partition)
{
  return (is_part_fat12(partition) || partition->upart_type==UP_FAT12);
}

int is_part_fat16(const partition_t *partition)
{
#if !defined(SINGLE_PARTITION_TYPE) || defined(SINGLE_PARTITION_I386)
  if(partition->arch==&arch_i386)
  {
    switch(partition->part_type_i386)
    {
      case P_16FAT:
      case P_16FATH:
      case P_16FATBD_LBA:
      case P_16FATBD:
      case P_16FATBDH:
      case P_16FATBD_LBAH:
        return 1;
      default:
        break;
    }
  }
#endif
  return 0;
}

static int is_fat16(const partition_t *partition)
{
  return (is_part_fat16(partition) || partition->upart_type==UP_FAT16);
}

int is_part_fat32(const partition_t *partition)
{
#if !defined(SINGLE_PARTITION_TYPE) || defined(SINGLE_PARTITION_I386)
  if(partition->arch==&arch_i386)
  {
    switch(partition->part_type_i386)
    {
      case P_32FAT:
      case P_32FAT_LBA:
      case P_32FATH:
      case P_32FAT_LBAH:
        return 1;
      default:
        break;
    }
  }
#endif
#if !defined(SINGLE_PARTITION_TYPE) || defined(SINGLE_PARTITION_MAC)
  if(partition->arch==&arch_mac)
  {
    if(partition->part_type_mac==PMAC_FAT32)
      return 1;
  }
#endif
  return 0;
}

static int is_fat32(const partition_t *partition)
{
  return (is_part_fat32(partition) || partition->upart_type==UP_FAT32);
}

int fat32_free_info(disk_t *disk_car,const partition_t *partition, const unsigned int fat_offset, const unsigned int no_of_cluster, unsigned int *next_free, unsigned int*free_count)
{
  unsigned char *buffer;
  const uint32_t *p32;
  unsigned int prev_cluster;
  uint64_t hd_offset=partition->part_offset+(uint64_t)fat_offset*disk_car->sector_size;
  buffer=(unsigned char *)MALLOC(disk_car->sector_size);
  p32=(const uint32_t*)buffer;
  *next_free=0;
  *free_count=0;
  for(prev_cluster=2;prev_cluster<=no_of_cluster+1;prev_cluster++)
  {
    unsigned long int cluster;
    unsigned int offset_o;
    offset_o=prev_cluster%(disk_car->sector_size/4);
    if((offset_o==0)||(prev_cluster==2))
    {
      if((unsigned)disk_car->pread(disk_car, buffer, disk_car->sector_size, hd_offset) != disk_car->sector_size)
      {
#ifndef DISABLED_FOR_FRAMAC
        log_error("fat32_free_info read error\n");
#endif
        *next_free=0xFFFFFFFF;
        *free_count=0xFFFFFFFF;
        return 1;
      }
      hd_offset+=disk_car->sector_size;
    }
    cluster=le32(p32[offset_o]) & 0xFFFFFFF;
    if(cluster==0)
    {
      (*free_count)++;
      if(*next_free==0)
        *next_free=prev_cluster;
    }
  }
#ifndef DISABLED_FOR_FRAMAC
  log_info("next_free %u, free_count %u\n",*next_free,*free_count);
#endif
  free(buffer);
  return 0;
}

int check_VFAT_volume_name(const char *name, const unsigned int max_size)
{
  unsigned int i;
  /*@
    @ loop assigns i;
    @ loop variant max_size - i;
    @*/
  for(i=0; i<max_size && name[i]!='\0'; i++)
  {
    if(name[i] < 0x20)
      return 1;
    switch(name[i])
    {
      case '<':
      case '>':
      case ':':
      case '"':
      case '/':
      case '\\':
      case '|':
      case '?':
      case '*':
	return 1;
    }
  }
  return 0; /* Ok */
}
