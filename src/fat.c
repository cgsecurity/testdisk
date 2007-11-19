/*

    File: fat.c

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
#include "testdisk.h"
#include "intrf.h"
#ifdef HAVE_NCURSES
#include "intrfn.h"
#else
#include <stdio.h>
#endif
#include "log.h"
/* #include "guid_cmp.h" */
extern const arch_fnct_t arch_i386;
extern const arch_fnct_t arch_mac;

static int set_FAT_info(disk_t *disk_car, const struct fat_boot_sector *fat_header, partition_t *partition,const int verbose);
static void fat_set_part_name(partition_t *partition,const unsigned char *src,const int max_size);
static int log_fat_info(const struct fat_boot_sector*fh1, const upart_type_t upart_type, const unsigned int sector_size);

static void fat_set_part_name(partition_t *partition,const unsigned char *src,const int max_size)
{
  int i;
  for(i=0;(i<max_size) && (src[i]!=(char)0);i++)
    partition->fsname[i]=src[i];
  partition->fsname[i--]='\0';
  for(;(i>=0) && (src[i]==' ');i--);
  partition->fsname[i+1]='\0';
}

static int log_fat_info(const struct fat_boot_sector*fh1, const upart_type_t upart_type, const unsigned int sector_size)
{
  log_info("sector_size  %u\n", fat_sector_size(fh1));
  log_info("cluster_size %u\n", fh1->cluster_size);
  log_info("reserved     %u\n", le16(fh1->reserved));
  log_info("fats         %u\n", fh1->fats);
  log_info("dir_entries  %u\n", get_dir_entries(fh1));
  log_info("sectors      %u\n", sectors(fh1));
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
  return 0;
}

#ifdef HAVE_NCURSES
static int dump_fat_info_ncurses(const struct fat_boot_sector*fh1, const upart_type_t upart_type, const unsigned int sector_size)
{
  switch(upart_type)
  {
    case UP_FAT12:
      wprintw(stdscr,"FAT : 12\n");
      break;
    case UP_FAT16:
      wprintw(stdscr,"FAT : 16\n");
      break;
    case UP_FAT32:
      wprintw(stdscr,"FAT : 32\n");
      break;
    default:
      wprintw(stdscr,"Not a FAT\n");
      return 0;
  }
  wprintw(stdscr,"cluster_size %u\n", fh1->cluster_size);
  wprintw(stdscr,"reserved     %u\n", le16(fh1->reserved));
  if(sectors(fh1)!=0)
    wprintw(stdscr,"sectors      %u\n", sectors(fh1));
  if(le32(fh1->total_sect)!=0)
    wprintw(stdscr,"total_sect   %u\n", (unsigned int)le32(fh1->total_sect));
  if(upart_type==UP_FAT32)
  {
    wprintw(stdscr,"fat32_length %u\n", (unsigned int)le32(fh1->fat32_length));
    wprintw(stdscr,"root_cluster %u\n", (unsigned int)le32(fh1->root_cluster));
    wprintw(stdscr,"flags        %04X\n", le16(fh1->flags));
    wprintw(stdscr,"version      %u.%u\n", fh1->version[0], fh1->version[1]);
    wprintw(stdscr,"root_cluster %u\n", (unsigned int)le32(fh1->root_cluster));
    wprintw(stdscr,"info_sector  %u\n", le16(fh1->info_sector));
    wprintw(stdscr,"backup_boot  %u\n", le16(fh1->backup_boot));
    if(fat32_get_free_count((const unsigned char*)fh1,sector_size)==0xFFFFFFFF)
      wprintw(stdscr,"free_count   uninitialised\n");
    else
      wprintw(stdscr,"free_count   %lu\n",fat32_get_free_count((const unsigned char*)fh1,sector_size));
    if(fat32_get_next_free((const unsigned char*)fh1,sector_size)==0xFFFFFFFF)
      wprintw(stdscr,"next_free    uninitialised\n");
    else
      wprintw(stdscr,"next_free    %lu\n",fat32_get_next_free((const unsigned char*)fh1,sector_size));
  } else {
    wprintw(stdscr,"fat_length   %u\n", le16(fh1->fat_length));
    wprintw(stdscr,"dir_entries  %u\n", get_dir_entries(fh1));
  }
  return 0;
}
#endif

int dump_fat_info(const struct fat_boot_sector*fh1, const upart_type_t upart_type, const unsigned int sector_size)
{
#ifdef HAVE_NCURSES
  return dump_fat_info_ncurses(fh1, upart_type, sector_size);
#else
  return 0;
#endif
}

#ifdef HAVE_NCURSES
static int dump_2fat_info_ncurses(const struct fat_boot_sector*fh1, const struct fat_boot_sector*fh2, const upart_type_t upart_type, const unsigned int sector_size)
{
  switch(upart_type)
  {
    case UP_FAT12:
      wprintw(stdscr,"FAT : 12\n");
      break;
    case UP_FAT16:
      wprintw(stdscr,"FAT : 16\n");
      break;
    case UP_FAT32:
      wprintw(stdscr,"FAT : 32\n");
      break;
    default:
      wprintw(stdscr,"Not a FAT\n");
      return 1;
  }
  wprintw(stdscr,"cluster_size %u %u\n", fh1->cluster_size, fh2->cluster_size);
  wprintw(stdscr,"reserved     %u %u\n", le16(fh1->reserved),le16(fh2->reserved));
  if(sectors(fh1)!=0 || sectors(fh2)!=0)
    wprintw(stdscr,"sectors      %u %u\n", sectors(fh1), sectors(fh2));
  if(le32(fh1->total_sect)!=0 || le32(fh2->total_sect)!=0)
    wprintw(stdscr,"total_sect   %u %u\n", (unsigned int)le32(fh1->total_sect), (unsigned int)le32(fh2->total_sect));
  if(upart_type==UP_FAT32)
  {
    wprintw(stdscr,"fat32_length %u %u\n", (unsigned int)le32(fh1->fat32_length), (unsigned int)le32(fh2->fat32_length));
    wprintw(stdscr,"root_cluster %u %u\n", (unsigned int)le32(fh1->root_cluster), (unsigned int)le32(fh2->root_cluster));
    wprintw(stdscr,"free_count   ");
    if(fat32_get_free_count((const unsigned char*)fh1,sector_size)==0xFFFFFFFF)
      wprintw(stdscr,"uninitialised ");
    else
      wprintw(stdscr,"%lu ",fat32_get_free_count((const unsigned char*)fh1,sector_size));
    if(fat32_get_free_count((const unsigned char*)fh2,sector_size)==0xFFFFFFFF)
      wprintw(stdscr,"uninitialised\n");
    else
      wprintw(stdscr,"%lu\n",fat32_get_free_count((const unsigned char*)fh2,sector_size));
    wprintw(stdscr,"next_free    ");
    if(fat32_get_next_free((const unsigned char*)fh1,sector_size)==0xFFFFFFFF)
      wprintw(stdscr,"uninitialised ");
    else
      wprintw(stdscr,"%lu ",fat32_get_next_free((const unsigned char*)fh1,sector_size));
    if(fat32_get_next_free((const unsigned char*)fh2,sector_size)==0xFFFFFFFF)
      wprintw(stdscr,"uninitialised\n");
    else
      wprintw(stdscr,"%lu\n",fat32_get_next_free((const unsigned char*)fh2,sector_size));
  } else {
    wprintw(stdscr,"fat_length   %u %u\n", le16(fh1->fat_length), le16(fh2->fat_length));
    wprintw(stdscr,"dir_entries  %u %u\n", get_dir_entries(fh1), get_dir_entries(fh2));
  }
  return 0;
}
#endif

int dump_2fat_info(const struct fat_boot_sector*fh1, const struct fat_boot_sector*fh2, const upart_type_t upart_type, const unsigned int sector_size)
{
#ifdef HAVE_NCURSES
  return dump_2fat_info_ncurses(fh1, fh2, upart_type, sector_size);
#else
  return 0;
#endif
}

int log_fat2_info(const struct fat_boot_sector*fh1, const struct fat_boot_sector*fh2, const upart_type_t upart_type, const unsigned int sector_size)
{
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
  log_info("cluster_size %u %u\n", fh1->cluster_size,fh2->cluster_size);
  log_info("reserved     %u %u\n", le16(fh1->reserved),le16(fh2->reserved));
  log_info("fats         %u %u\n", fh1->fats,fh2->fats);
  log_info("dir_entries  %u %u\n", get_dir_entries(fh1),get_dir_entries(fh2));
  log_info("sectors      %u %u\n", sectors(fh1),sectors(fh2));
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
  return 0;
}

int check_FAT(disk_t *disk_car,partition_t *partition,const int verbose)
{
  unsigned char *buffer;
  buffer=MALLOC(3*disk_car->sector_size);
  if(disk_car->read(disk_car,3*disk_car->sector_size, buffer, partition->part_offset)!=0)
  {
    aff_buffer(BUFFER_ADD,"check_FAT: can't read FAT boot sector\n");
    log_error("check_FAT: can't read FAT boot sector\n");
    free(buffer);
    return 1;
  }
  if(test_FAT(disk_car,(const struct fat_boot_sector *)buffer,partition,verbose,0)!=0)
  {
    if(verbose>0)
    {
      log_error("\n\ntest_FAT()\n");
      log_partition(disk_car,partition);
      log_fat_info((const struct fat_boot_sector*)buffer, partition->upart_type,disk_car->sector_size);
    }
    free(buffer);
    return 1;
  }
  set_FAT_info(disk_car,(const struct fat_boot_sector *)buffer,partition,verbose);
  /*  aff_buffer(BUFFER_ADD,"Ok\n"); */
  free(buffer);
  return 0;
}

static int set_FAT_info(disk_t *disk_car, const struct fat_boot_sector *fat_header, partition_t *partition,const int verbose)
{
  const char*buffer=(const char*)fat_header;
  partition->fsname[0]='\0';
  switch(partition->upart_type)
  {
    case UP_FAT12:
      snprintf(partition->info,sizeof(partition->info),"FAT12");
      if(buffer[38]==0x29)	/* BS_BootSig */
      {
        fat_set_part_name(partition,((const unsigned char*)fat_header)+FAT1X_PART_NAME,11);
        if(check_volume_name(partition->fsname,11))
          partition->fsname[0]='\0';
      }
      break;
    case UP_FAT16:
      snprintf(partition->info,sizeof(partition->info),"FAT16");
      if(buffer[38]==0x29)	/* BS_BootSig */
      {
        fat_set_part_name(partition,((const unsigned char*)fat_header)+FAT1X_PART_NAME,11);
        if(check_volume_name(partition->fsname,11))
          partition->fsname[0]='\0';
      }
      break;
    case UP_FAT32:
      snprintf(partition->info,sizeof(partition->info),"FAT32");
      fat32_set_part_name(disk_car,partition,fat_header);
      break;
    default:
      log_critical("set_FAT_info unknown upart_type\n");
      return 1;
  }
  return 0;
}

unsigned int get_next_cluster(disk_t *disk_car,const partition_t *partition, const upart_type_t upart_type,const int offset, const unsigned int cluster)
{
  /* Offset can be offset to FAT1 or to FAT2 */
  /* log_trace("get_next_cluster(upart_type=%u,offset=%u,cluster=%u\n",upart_type,offset,cluster); */
  unsigned char *buffer;
  unsigned int next_cluster;
  unsigned long int offset_s,offset_o;
  const unsigned int buffer_size=(upart_type==UP_FAT12?2*disk_car->sector_size:disk_car->sector_size);
  buffer=(unsigned char*)MALLOC(buffer_size);
  switch(upart_type)
  {
    case UP_FAT12:
      {
        offset_s=(cluster+cluster/2)/disk_car->sector_size;
        offset_o=(cluster+cluster/2)%disk_car->sector_size;
        if(disk_car->read(disk_car,2*disk_car->sector_size, buffer, partition->part_offset+(uint64_t)(offset+offset_s)*disk_car->sector_size)!=0)
        {
          log_error("get_next_cluster read error\n"); return 0;
        }
        if((cluster&1)!=0)
          next_cluster=le16((*((uint16_t*)&buffer[offset_o])))>>4;
        else
          next_cluster=le16(*((uint16_t*)&buffer[offset_o]))&0x0FFF;
        free(buffer);
        return next_cluster;
      }
    case UP_FAT16:
      {
        const uint16_t *p16=(const uint16_t*)buffer;
        offset_s=cluster/(disk_car->sector_size/2);
        offset_o=cluster%(disk_car->sector_size/2);
        if(disk_car->read(disk_car,disk_car->sector_size, buffer, partition->part_offset+(uint64_t)(offset+offset_s)*disk_car->sector_size)!=0)
        {
          log_error("get_next_cluster read error\n"); return 0;
        }
        next_cluster=le16(p16[offset_o]);
        free(buffer);
        return next_cluster;
      }
    case UP_FAT32:
      {
        const uint32_t *p32=(const uint32_t*)buffer;
        offset_s=cluster/(disk_car->sector_size/4);
        offset_o=cluster%(disk_car->sector_size/4);
        if(disk_car->read(disk_car,disk_car->sector_size, buffer, partition->part_offset+(uint64_t)(offset+offset_s)*disk_car->sector_size)!=0)
        {
          log_error("get_next_cluster read error\n"); return 0;
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
    default:
      log_critical("fat.c get_next_cluster unknown fat type\n");
      free(buffer);
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
      log_critical("fat.c set_next_cluster unknown fat type\n");
      free(buffer);
      return 1;
  }
  if(disk_car->read(disk_car,buffer_size, buffer, partition->part_offset+(uint64_t)(offset+offset_s)*disk_car->sector_size)!=0)
  {
    log_error("set_next_cluster read error\n");
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
  if(disk_car->write(disk_car,buffer_size, &buffer, partition->part_offset+(uint64_t)(offset+offset_s)*disk_car->sector_size)!=0)
  {
    display_message("Write error: set_next_cluster write error\n");
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
  unsigned char *buffer=MALLOC(disk_car->sector_size);
  p32=(const uint32_t*)buffer;

  for(prev_cluster=2;prev_cluster<=no_of_cluster+1;prev_cluster++)
  {
    unsigned int offset_s,offset_o;
    offset_s=prev_cluster/(disk_car->sector_size/4);
    offset_o=prev_cluster%(disk_car->sector_size/4);
    if((offset_o==0)||(prev_cluster==2))
    {
      if(disk_car->read(disk_car,disk_car->sector_size, &buffer, hd_offset)!=0)
      {
        log_error("fat32_get_prev_cluster error\n"); return 0;
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

int test_FAT(disk_t *disk_car,const struct fat_boot_sector *fat_header, partition_t *partition,const int verbose, const int dump_ind)
{
  upart_type_t upart_type=UP_UNK;
  uint64_t start_fat1,start_fat2,start_rootdir,start_data,part_size,end_data;
  unsigned long int no_of_cluster,fat_length,fat_length_calc;
  const char *buffer=(const char*)fat_header;
  if(!(le16(fat_header->marker)==0xAA55
        && (fat_header->ignored[0]==0xeb || fat_header->ignored[0]==0xe9)
        && (fat_header->fats==1 || fat_header->fats==2)))
    return 1;   /* Obviously not a FAT */
  if(verbose>1)
  {
    log_trace("test_FAT\n");
    log_partition(disk_car,partition);
  }
#ifdef HAVE_NCURSES
  if(dump_ind!=0)
    dump_ncurses(fat_header,DEFAULT_SECTOR_SIZE);
#endif
  if(!((fat_header->ignored[0]==0xeb && fat_header->ignored[2]==0x90)||fat_header->ignored[0]==0xe9))
  {
    aff_buffer(BUFFER_ADD,msg_CHKFAT_BAD_JUMP);
    log_error(msg_CHKFAT_BAD_JUMP);
    return 1;
  }
  if(fat_sector_size(fat_header)!=disk_car->sector_size)
  {
    aff_buffer(BUFFER_ADD,"check_FAT: Incorrect number of bytes per sector %u (FAT) != %u (HD)\n",fat_sector_size(fat_header),disk_car->sector_size);
    log_error("check_FAT: Incorrect number of bytes per sector %u (FAT) != %u (HD)\n",fat_sector_size(fat_header),disk_car->sector_size);
    return 1;
  }
  switch(fat_header->cluster_size)
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
      aff_buffer(BUFFER_ADD,msg_CHKFAT_SECT_CLUSTER);
      log_error(msg_CHKFAT_SECT_CLUSTER);
      return 1;
  }
  switch(fat_header->fats)
  {
    case 1:
      aff_buffer(BUFFER_ADD,"check_FAT: Unusual, only one FAT\n");
      log_warning("check_FAT: Unusual, only one FAT\n");
      break;
    case 2:
      break;
    default:
      aff_buffer(BUFFER_ADD,"check_FAT: Bad number %u of FAT\n", fat_header->fats);
      log_error("check_FAT: Bad number %u of FAT\n", fat_header->fats);
      return 1;
  }
  if(fat_header->media!=0xF0 && fat_header->media<0xF8)
  {	/* Legal values are 0xF0, 0xF8-0xFF */
    aff_buffer(BUFFER_ADD,"check_FAT: Bad media descriptor (0x%2x!=0xf8)\n",fat_header->media);
    log_error("check_FAT: Bad media descriptor (0x%2x!=0xf8)\n",fat_header->media);
    return 1;
  }
  if(fat_header->media!=0xF8)
  { /* the only value I have ever seen is 0xF8 */
    aff_buffer(BUFFER_ADD,"check_FAT: Unusual media descriptor (0x%2x!=0xf8)\n",fat_header->media);
    log_warning("check_FAT: Unusual media descriptor (0x%2x!=0xf8)\n",fat_header->media);
  }
  fat_length=le16(fat_header->fat_length)>0?le16(fat_header->fat_length):le32(fat_header->fat32_length);
  part_size=(sectors(fat_header)>0?sectors(fat_header):le32(fat_header->total_sect));
  start_fat1=le16(fat_header->reserved);
  start_fat2=start_fat1+(fat_header->fats>1?fat_length:0);
  start_data=start_fat1+fat_header->fats*fat_length+(get_dir_entries(fat_header)*32+disk_car->sector_size-1)/disk_car->sector_size;
  no_of_cluster=(part_size-start_data)/fat_header->cluster_size;
  end_data=start_data+no_of_cluster*fat_header->cluster_size-1;
  if(verbose>1)
  {
    log_info("number of cluster = %lu\n",no_of_cluster);
  }
  if(no_of_cluster<4085)
  {
    upart_type=UP_FAT12;
    if(verbose>0)
    {
      log_info("FAT12 at %u/%u/%u\n",
          offset2cylinder(disk_car,partition->part_offset),
          offset2head(disk_car,partition->part_offset),
          offset2sector(disk_car,partition->part_offset));
    }
    if(sectors(fat_header)==0)
    {
      aff_buffer(BUFFER_ADD,msg_CHKFAT_SIZE);
      log_error(msg_CHKFAT_SIZE);
    }
    if(le16(fat_header->reserved)!=1)
    {
      aff_buffer(BUFFER_ADD,"check_FAT: Unusual number of reserved sectors %u (FAT), should be 1.\n",le16(fat_header->reserved));
      log_warning("check_FAT: Unusual number of reserved sectors %u (FAT), should be 1.\n",le16(fat_header->reserved));
    }
    if((get_dir_entries(fat_header)==0)||(get_dir_entries(fat_header)%16!=0))
    {
      aff_buffer(BUFFER_ADD,msg_CHKFAT_ENTRY);
      log_error(msg_CHKFAT_ENTRY);
      return 1;
    }
    if((le16(fat_header->fat_length)>256)||(le16(fat_header->fat_length)==0))
    {
      aff_buffer(BUFFER_ADD,msg_CHKFAT_SECTPFAT);
      log_error(msg_CHKFAT_SECTPFAT);
      return 1;
    }
    start_rootdir=start_fat2+fat_length;
    fat_length_calc=((no_of_cluster+2+disk_car->sector_size*2/3-1)*3/2/disk_car->sector_size);
    partition->upart_type=UP_FAT12;
    if(memcmp(buffer+FAT_NAME1,"FAT12   ",8)!=0) /* 2 Mo max */
    {
      aff_buffer(BUFFER_ADD,"Should be marked as FAT12\n");
      log_warning("Should be marked as FAT12\n");
    }
  }
  else if(no_of_cluster<65525)
  {
    upart_type=UP_FAT16;
    if(verbose>0)
    {
      log_info("FAT16 at %u/%u/%u\n",
          offset2cylinder(disk_car,partition->part_offset),
          offset2head(disk_car,partition->part_offset),
          offset2sector(disk_car,partition->part_offset));
    }
    if(le16(fat_header->reserved)!=1)
    {
      aff_buffer(BUFFER_ADD,"check_FAT: Unusual number of reserved sectors %u (FAT), should be 1.\n",le16(fat_header->reserved));
      log_warning("check_FAT: Unusual number of reserved sectors %u (FAT), should be 1.\n",le16(fat_header->reserved));
    }
    if(le16(fat_header->fat_length)==0)
    {
      aff_buffer(BUFFER_ADD,msg_CHKFAT_SECTPFAT);
      log_error(msg_CHKFAT_SECTPFAT);
      return 1;
    }
    if((get_dir_entries(fat_header)==0)||(get_dir_entries(fat_header)%16!=0))
    {
      aff_buffer(BUFFER_ADD,msg_CHKFAT_ENTRY);
      log_error(msg_CHKFAT_ENTRY);
      return 1;
    }
    start_rootdir=start_fat2+fat_length;
    fat_length_calc=((no_of_cluster+2+disk_car->sector_size/2-1)*2/disk_car->sector_size);
    partition->upart_type=UP_FAT16;
    if(memcmp(buffer+FAT_NAME1,"FAT16   ",8)!=0)
    {
      aff_buffer(BUFFER_ADD,"Should be marked as FAT16\n");
      log_warning("Should be marked as FAT16\n");
    }
  }
  else
  {
    upart_type=UP_FAT32;
    if(verbose>0)
    {
      log_info("FAT32 at %u/%u/%u\n",
          offset2cylinder(disk_car,partition->part_offset),
          offset2head(disk_car,partition->part_offset),
          offset2sector(disk_car,partition->part_offset));
    }
    if(sectors(fat_header)!=0)
    {
      aff_buffer(BUFFER_ADD,msg_CHKFAT_SIZE);
      log_error(msg_CHKFAT_SIZE);
      return 1;
    }
    if(get_dir_entries(fat_header)!=0)
    {
      aff_buffer(BUFFER_ADD,msg_CHKFAT_ENTRY);
      log_error(msg_CHKFAT_ENTRY);
      return 1;
    }
    if((fat_header->version[0]!=0) || (fat_header->version[1]!=0))
    {
      aff_buffer(BUFFER_ADD,msg_CHKFAT_BADFAT32VERSION);
      log_error(msg_CHKFAT_BADFAT32VERSION);
    }
    if((le32(fat_header->root_cluster)<2) ||(le32(fat_header->root_cluster)>=2+no_of_cluster))
    {
      aff_buffer(BUFFER_ADD,"Bad root_cluster\n");
      log_error("Bad root_cluster\n");
      return 1;
    }
    start_rootdir=start_data+(uint64_t)(le32(fat_header->root_cluster)-2)*fat_header->cluster_size;
    fat_length_calc=((no_of_cluster+2+disk_car->sector_size/4-1)*4/disk_car->sector_size);
    partition->upart_type=UP_FAT32;
    if(memcmp(buffer+FAT_NAME2,"FAT32   ",8)!=0)
    {
      aff_buffer(BUFFER_ADD,"Should be marked as FAT32\n");
      log_warning("Should be marked as FAT32\n");
    }
  }
  if(partition->part_size>0)
  {
    if(part_size > partition->part_size/disk_car->sector_size)
    {
      aff_buffer(BUFFER_ADD, "Error: size boot_sector %lu > partition %lu\n",
          (long unsigned)part_size,
          (long unsigned)(partition->part_size/disk_car->sector_size));
      log_error("test_FAT size boot_sector %lu > partition %lu\n",
          (long unsigned)part_size,
          (long unsigned)(partition->part_size/disk_car->sector_size));
      return 1;
    }
    else
    {
      if(verbose>0 && part_size!=partition->part_size)
        log_info("Info: size boot_sector %lu, partition %lu\n",
            (long unsigned)part_size,
            (long unsigned)(partition->part_size/disk_car->sector_size));
    }
  }
  if(verbose>0)
  {
    log_info("FAT1 : %lu-%lu\n", (long unsigned)start_fat1, (long unsigned)(start_fat1+fat_length-1));
    log_info("FAT2 : %lu-%lu\n", (long unsigned)start_fat2, (long unsigned)(start_fat2+fat_length-1));
    log_info("start_rootdir : %lu", (long unsigned)start_rootdir);
    if(partition->upart_type==UP_FAT32)
      log_info(" root cluster : %u",(unsigned int)le32(fat_header->root_cluster));
    log_info("\nData : %lu-%lu\n", (long unsigned)start_data, (long unsigned)end_data);
    log_info("sectors : %lu\n", (long unsigned)part_size);
    log_info("cluster_size : %u\n",fat_header->cluster_size);
    log_info("no_of_cluster : %lu (2 - %lu)\n", no_of_cluster,no_of_cluster+1);
    log_info("fat_length %lu calculated %lu\n",fat_length,fat_length_calc);
  }
  if(fat_length<fat_length_calc)
  {
    aff_buffer(BUFFER_ADD,msg_CHKFAT_SECTPFAT);
    return 1;
  }
  if(fat_header->fats>1)
    comp_FAT(disk_car,partition,fat_length,le16(fat_header->reserved));
  if(le16(fat_header->heads)!=disk_car->CHS.head+1)
  {
    aff_buffer(BUFFER_ADD,"Warning: Incorrect number of heads/cylinder %u (FAT) != %u (HD)\n",le16(fat_header->heads),disk_car->CHS.head+1);
    log_warning("heads/cylinder %u (FAT) != %u (HD)\n",le16(fat_header->heads),disk_car->CHS.head+1);
  }
  if(le16(fat_header->secs_track)!=disk_car->CHS.sector)
  {
    aff_buffer(BUFFER_ADD,"Warning: Incorrect number of sectors per track %u (FAT) != %u (HD)\n",le16(fat_header->secs_track),disk_car->CHS.sector);
    log_warning("sect/track %u (FAT) != %u (HD)\n",le16(fat_header->secs_track),disk_car->CHS.sector);
  }
  return 0;
}

int comp_FAT(disk_t *disk_car,const partition_t *partition,const unsigned long int fat_size,const unsigned long int sect_res)
{
  /*
  return 0 if FATs match
  */
  unsigned int reste;
  uint64_t hd_offset, hd_offset2;
  unsigned char *buffer, *buffer2;
  buffer=(unsigned char *)MALLOC(NBR_SECT*disk_car->sector_size);
  buffer2=(unsigned char *)MALLOC(NBR_SECT*disk_car->sector_size);
  hd_offset=partition->part_offset+(uint64_t)sect_res*disk_car->sector_size;
  hd_offset2=hd_offset+(uint64_t)fat_size*disk_car->sector_size;
  reste=(fat_size>1000?1000:fat_size); /* Quick check ! */
  while(reste>0)
  {
    const unsigned int read_size=reste>NBR_SECT?NBR_SECT:reste;
    reste-=read_size;
    if(disk_car->read(disk_car,read_size*disk_car->sector_size, buffer, hd_offset))
    {
      log_error("comp_FAT: can't read FAT1\n");
      return 1;
    }
    if(disk_car->read(disk_car,read_size*disk_car->sector_size, buffer2, hd_offset2))
    {
      log_error("comp_FAT: can't read FAT2\n");
      return 1;
    }
    if(memcmp(buffer,buffer2,disk_car->sector_size*read_size)!=0)
    {
      log_error("FAT differs, FAT sectors=%lu-%lu/%lu\n",
          (unsigned long) ((hd_offset-partition->part_offset)/disk_car->sector_size-sect_res),
          (unsigned long) ((hd_offset-partition->part_offset)/disk_car->sector_size-sect_res+read_size),
          fat_size); 
      free(buffer2);
      free(buffer);
      return 1;
    }
    hd_offset+=read_size*disk_car->sector_size;
    hd_offset2+=read_size*disk_car->sector_size;
  }
  free(buffer2);
  free(buffer);
  return 0;
}

unsigned int fat_sector_size(const struct fat_boot_sector *fat_header)
{ return (fat_header->sector_size[1]<<8)+fat_header->sector_size[0]; }

unsigned int get_dir_entries(const struct fat_boot_sector *fat_header)
{ return (fat_header->dir_entries[1]<<8)+fat_header->dir_entries[0]; }

unsigned int sectors(const struct fat_boot_sector *fat_header)
{ return (fat_header->sectors[1]<<8)+fat_header->sectors[0]; }

unsigned long int fat32_get_free_count(const unsigned char *boot_fat32, const unsigned int sector_size)
{
  return (boot_fat32[sector_size+0x1E8+3]<<24)+(boot_fat32[sector_size+0x1E8+2]<<16)+(boot_fat32[sector_size+0x1E8+1]<<8)+boot_fat32[sector_size+0x1E8];
}

unsigned long int fat32_get_next_free(const unsigned char *boot_fat32, const unsigned int sector_size)
{
  return (boot_fat32[sector_size+0x1EC+3]<<24)+(boot_fat32[sector_size+0x1EC+2]<<16)+(boot_fat32[sector_size+0x1EC+1]<<8)+boot_fat32[sector_size+0x1EC];
}

int recover_FAT(disk_t *disk_car, const struct fat_boot_sector*fat_header, partition_t *partition, const int verbose, const int dump_ind, const int backup)
{
  if(test_FAT(disk_car, fat_header, partition, verbose, dump_ind))
    return 1;
  partition->part_size=(uint64_t)(sectors(fat_header)>0?sectors(fat_header):le32(fat_header->total_sect)) *
    fat_sector_size(fat_header);
  /* test_FAT has set partition->upart_type */
  partition->sborg_offset=0;
  partition->sb_size=512;
  partition->sb_offset=0;
  switch(partition->upart_type)
  {
    case UP_FAT12:
      if(verbose||dump_ind)
      {
        log_info("\nFAT12 at %u/%u/%u\n",
            offset2cylinder(disk_car,partition->part_offset),
            offset2head(disk_car,partition->part_offset),
            offset2sector(disk_car,partition->part_offset));
      }
      partition->part_type_i386=P_12FAT;
      partition->part_type_gpt=GPT_ENT_TYPE_MS_BASIC_DATA;
      break;
    case UP_FAT16:
      if(verbose||dump_ind)
      {
        log_info("\nFAT16 at %u/%u/%u\n",
            offset2cylinder(disk_car,partition->part_offset),
            offset2head(disk_car,partition->part_offset),
            offset2sector(disk_car,partition->part_offset));
      }
      if(sectors(fat_header)!=0)
        partition->part_type_i386=P_16FAT;
      else if(offset2cylinder(disk_car,partition->part_offset+partition->part_size-1)<=1024)
        partition->part_type_i386=P_16FATBD;
      else
        partition->part_type_i386=P_16FATBD_LBA;
      partition->part_type_gpt=GPT_ENT_TYPE_MS_BASIC_DATA;
      break;
    case UP_FAT32:
      if(verbose||dump_ind)
      {
        log_info("\nFAT32 at %u/%u/%u\n",
            offset2cylinder(disk_car,partition->part_offset),
            offset2head(disk_car,partition->part_offset),
            offset2sector(disk_car,partition->part_offset));
      }
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
      log_critical("recover_FAT unknown FAT type\n");
      return 1;
  }
  set_FAT_info(disk_car,fat_header,partition,verbose);
  return 0;
}

int fat32_set_part_name(disk_t *disk_car, partition_t *partition, const struct fat_boot_sector*fat_header)
{
  partition->fsname[0]='\0';
  if((fat_header->cluster_size>0)&&(fat_header->cluster_size<=128))
  {
    unsigned char *buffer=(unsigned char*)MALLOC(fat_header->cluster_size*disk_car->sector_size);
    if(disk_car->read(disk_car,
          fat_header->cluster_size*disk_car->sector_size,
          buffer,
          partition->part_offset +
          (le16(fat_header->reserved)+fat_header->fats*le32(fat_header->fat32_length)+(uint64_t)(le32(fat_header->root_cluster)-2)*fat_header->cluster_size) * disk_car->sector_size))
    {
      log_error("fat32_set_part_name() cannot read FAT32 root cluster.\n");
    }
    else
    {
      int i;
      int stop=0;
      for(i=0;(i<16*fat_header->cluster_size)&&(stop==0);i++)
      { /* Test attribut volume name and check if the volume name is erased or not */
        if(((buffer[i*0x20+0xB] & ATTR_EXT) !=ATTR_EXT) && ((buffer[i*0x20+0xB] & ATTR_VOLUME) !=0) && (buffer[i*0x20]!=0xE5))
        {
          /*      dump_ncurses(&buffer[i*0x20],0x20); */
          fat_set_part_name(partition,&buffer[i*0x20],11);
          if(check_volume_name(partition->fsname,11))
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
    log_info("set_FAT_info: name from BS used\n");
    fat_set_part_name(partition,((const unsigned char*)fat_header)+FAT32_PART_NAME,11);
    if(check_volume_name(partition->fsname,11))
      partition->fsname[0]='\0';
  }
  return 0;
}

int check_HPFS(disk_t *disk_car,partition_t *partition,const int verbose)
{
  unsigned char buffer[512];
  if(disk_car->read(disk_car,disk_car->sector_size, &buffer, partition->part_offset)!=0)
  {
    aff_buffer(BUFFER_ADD,"check_HPFS: Read error\n");
    log_error("check_HPFS: Read error\n");
    return 1;
  }
  if(test_HPFS(disk_car,(const struct fat_boot_sector *)buffer,partition,verbose,0)!=0)
  {
    if(verbose>0)
    {
      log_info("\n\ntest_HPFS()\n");
      log_partition(disk_car,partition);
    }
    return 1;
  }
  return 0;
}

int test_HPFS(disk_t *disk_car,const struct fat_boot_sector *fat_header, partition_t *partition,const int verbose, const int dump_ind)
{
  const char*buffer=(const char*)fat_header;
  if(le16(fat_header->marker)==0xAA55)
  {
    if(memcmp(buffer+OS2_NAME,"IBM",3)==0)
    {   /* D'apres une analyse de OS2 sur systeme FAT...
           FAT_NAME1=FAT
         */
      if(verbose||dump_ind)
      {
        log_info("\nHPFS maybe at %u/%u/%u\n",
            offset2cylinder(disk_car,partition->part_offset),
            offset2head(disk_car,partition->part_offset),
            offset2sector(disk_car,partition->part_offset));
      }
#ifdef HAVE_NCURSES
      if(dump_ind)
        dump_ncurses(buffer,DEFAULT_SECTOR_SIZE);
#endif
      partition->part_size=(uint64_t)(sectors(fat_header)>0?sectors(fat_header):le32(fat_header->total_sect)) *
        fat_sector_size(fat_header);
      partition->upart_type=UP_HPFS;
      return 0;
    }
  }     /* fin marqueur de fin :)) */
  return 1;
}

int recover_HPFS(disk_t *disk_car,const struct fat_boot_sector*fat_header, partition_t *partition, const int verbose, const int dump_ind)
{
  if(test_HPFS(disk_car,fat_header,partition,verbose,0)!=0)
    return 1;
  partition->part_type_i386=P_HPFS;
  partition->part_type_gpt=GPT_ENT_TYPE_MAC_HFS;
  partition->fsname[0]='\0';
  partition->info[0]='\0';
  return 0;
}

int check_OS2MB(disk_t *disk_car,partition_t *partition,const int verbose)
{
  unsigned char buffer[0x200];
  if(disk_car->read(disk_car,disk_car->sector_size, &buffer, partition->part_offset)!=0)
  {
    aff_buffer(BUFFER_ADD,"check_OS2MB: Read error\n");
    log_error("check_OS2MB: Read error\n");
    return 1;
  }
  if(test_OS2MB(disk_car,(const struct fat_boot_sector *)buffer,partition,verbose,0)!=0)
  {
    if(verbose>0)
    {
      log_info("\n\ntest_OS2MB()\n");
      log_partition(disk_car,partition);
    }
    return 1;
  }
  return 0;
}

int recover_OS2MB(disk_t *disk_car, const struct fat_boot_sector*fat_header, partition_t *partition, const int verbose, const int dump_ind)
{
  if(test_OS2MB(disk_car, fat_header, partition, verbose, dump_ind))
    return 1;
  partition->part_size=(uint64_t)(disk_car->CHS.head+1) * disk_car->CHS.sector*disk_car->sector_size; /* 1 cylinder */
  partition->part_type_i386=P_OS2MB;
  partition->fsname[0]='\0';
  partition->info[0]='\0';
  return 0;
}

int test_OS2MB(disk_t *disk_car,const struct fat_boot_sector *fat_header, partition_t *partition,const int verbose, const int dump_ind)
{
  const char*buffer=(const char*)fat_header;
  if(le16(fat_header->marker)==0xAA55 && memcmp(buffer+FAT_NAME1,"FAT     ",8)==0)
  {
    if(verbose||dump_ind)
    {
      log_info("\nMarker (0xAA55) at %u/%u/%u\n", offset2cylinder(disk_car,partition->part_offset),offset2head(disk_car,partition->part_offset),offset2sector(disk_car,partition->part_offset));
    }
#ifdef HAVE_NCURSES
    if(dump_ind)
      dump_ncurses(buffer,DEFAULT_SECTOR_SIZE);
#endif
    partition->upart_type=UP_OS2MB;
    return 0;
  }
  return 1;
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
  /*
  else if(partition->arch==&arch_gpt)
  {
     if(guid_cmp(partition->part_type_gpt,GPT_ENT_TYPE_MS_BASIC_DATA)==0)
     return 1;
  }
  */
  return 0;
}

int is_fat12(const partition_t *partition)
{
  return (is_part_fat12(partition) || partition->upart_type==UP_FAT12);
}

int is_part_fat16(const partition_t *partition)
{
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
  /*
  else if(partition->arch==&arch_gpt)
  {
    if(guid_cmp(partition->part_type_gpt,GPT_ENT_TYPE_MS_BASIC_DATA)==0)
      return 1;
  }
   */
  return 0;
}

int is_fat16(const partition_t *partition)
{
  return (is_part_fat16(partition) || partition->upart_type==UP_FAT16);
}

int is_part_fat32(const partition_t *partition)
{
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
  else if(partition->arch==&arch_mac)
  {
    if(partition->part_type_mac==PMAC_FAT32)
      return 1;
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

int is_fat32(const partition_t *partition)
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
    unsigned int offset_s,offset_o;
    offset_s=prev_cluster/(disk_car->sector_size/4);
    offset_o=prev_cluster%(disk_car->sector_size/4);
    if((offset_o==0)||(prev_cluster==2))
    {
      if(disk_car->read(disk_car,disk_car->sector_size, buffer, hd_offset)!=0)
      {
        log_error("fat32_free_info read error\n");
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
  log_info("next_free %u, free_count %u\n",*next_free,*free_count);
  free(buffer);
  return 0;
}

