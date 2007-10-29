/*

    File: dir_fat.c

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
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#include "types.h"
#include "common.h"
#include "fat.h"
#include "lang.h"
#include "fnctdsk.h"
#include "testdisk.h"
#include "intrf.h"
#include "dir.h"
#include "fat_dir.h"
#include "log.h"

#define MSDOS_MKMODE(a,m) ((m & (a & ATTR_RO ? LINUX_S_IRUGO|LINUX_S_IXUGO : LINUX_S_IRWXUGO)) | (a & ATTR_DIR ? LINUX_S_IFDIR : LINUX_S_IFREG))
struct fat_dir_struct
{
  struct fat_boot_sector*boot_sector;
};


static int date_dos2unix(const unsigned short f_time,const unsigned short f_date);
static file_data_t *fat1x_rootdir(disk_t *disk_car, const partition_t *partition, const int verbose, const struct fat_boot_sector*fat_header);
static file_data_t *fat12_dir(disk_t *disk_car, const partition_t *partition, dir_data_t *dir_data, const unsigned long int first_cluster);
static file_data_t *fat16_dir(disk_t *disk_car, const partition_t *partition, dir_data_t *dir_data, const unsigned long int first_cluster);
static file_data_t *fat32_dir(disk_t *disk_car, const partition_t *partition, dir_data_t *dir_data, const unsigned long int first_cluster);
static inline void fat16_towchar(wchar_t *dst, const uint8_t *src, size_t len);
static void dir_partition_fat_close(dir_data_t *dir_data);

static int32_t secwest;

static inline void fat16_towchar(wchar_t *dst, const uint8_t *src, size_t len)
{
	while (len--) {
		*dst++ = src[0] | (src[1] << 8);
		src += 2;
	}
}

file_data_t *dir_fat_aux(const unsigned char*buffer, const unsigned int size, const unsigned int cluster_size)
{
  const struct msdos_dir_entry *de=(const struct msdos_dir_entry*)buffer;
  wchar_t unicode[1000];
  unsigned char long_slots;
  file_data_t *dir_list=NULL;
  file_data_t *current_file=NULL;
GetNew:
  long_slots = 0;
  unicode[0]=0;
  if (de->name[0] == (int8_t) DELETED_FLAG)
    goto RecEnd;
  if (de->attr == ATTR_EXT) {
    unsigned int i;
    const struct msdos_dir_slot *ds;
    unsigned char id;
    unsigned char slot;
    unsigned char slots;
    unsigned char sum;
    unsigned char alias_checksum;
ParseLong:
    slots = 0;
    ds = (const struct msdos_dir_slot *) de;
    id = ds->id;
    if ((id & 0x40)==0)
      goto RecEnd;
    slots = id & ~0x40;
    if (slots > 20 || slots==0)	/* ceil(256 * 2 / 26) */
      goto RecEnd;
    long_slots = slots;
    alias_checksum = ds->alias_checksum;

    slot = slots;
    while (1) {
      int offset;

      slot--;
      offset = slot * 13;
      fat16_towchar(unicode + offset, ds->name0_4, 5);
      fat16_towchar(unicode + offset + 5, ds->name5_10, 6);
      fat16_towchar(unicode + offset + 11, ds->name11_12, 2);

      if ((ds->id & 0x40)!=0) {
	unicode[offset + 13] = 0;
      }
      de++;
      if((const void*)de>=(const void*)(buffer+size))
	goto EODir;
      if (slot == 0)
	break;
      ds = (const struct msdos_dir_slot *) de;
      if (ds->attr !=  ATTR_EXT)
	goto RecEnd;	/* XXX */
      if ((ds->id & ~0x40) != slot)
	goto ParseLong;
      if (ds->alias_checksum != alias_checksum)
	goto ParseLong;
    }
    if (de->name[0] == (int8_t) DELETED_FLAG)
      goto RecEnd;
    if (de->attr ==  ATTR_EXT)
      goto ParseLong;
    if (IS_FREE(de->name) || ((de->attr & ATTR_VOLUME)!=0))
      goto RecEnd;
    for (sum = 0, i = 0; i < 8; i++)
      sum = (((sum&1)<<7)|((sum&0xfe)>>1)) + de->name[i];
    for (i = 0; i < 3; i++)
      sum = (((sum&1)<<7)|((sum&0xfe)>>1)) + de->ext[i];
    if (sum != alias_checksum)
      long_slots = 0;
  }
RecEnd:
  if((unicode[0]==0) &&(de->attr != ATTR_EXT))
  { /* short name 8.3 */
    int i;
    int j=0;
    for(i=0;(i<8)&&(de->name[i]!=' ');i++)
      unicode[j++]=de->name[i];
    if(de->ext[0]!=' ')
    {
      unicode[j++]='.';
      for(i=0;(i<3)&&(de->ext[i]!=' ');i++)
	unicode[j++]=de->ext[i];
    }
    unicode[j]=0;
  }
  if (((de->attr != ATTR_EXT)||(long_slots!=0)) && ((int8_t) unicode[0] != (int8_t) DELETED_FLAG) && !(de->attr & ATTR_VOLUME))
  {
    if(unicode[0]!=0)
    {
      unsigned int i;
      file_data_t *new_file=MALLOC(sizeof(*new_file));
      for(i=0;(unicode[i]!=0)&&(i<sizeof(new_file->name)-1);i++)
	new_file->name[i]=(char) unicode[i];
      new_file->name[i]=0;
      new_file->filestat.st_dev=0;
      new_file->filestat.st_ino=(le16(de->starthi)<<16)|le16(de->start);
      new_file->filestat.st_mode = MSDOS_MKMODE(de->attr,(LINUX_S_IRWXUGO & ~(LINUX_S_IWGRP|LINUX_S_IWOTH)));
      new_file->filestat.st_nlink=0;
      new_file->filestat.st_uid=0;
      new_file->filestat.st_gid=0;
      new_file->filestat.st_rdev=0;
      new_file->filestat.st_size=le32(de->size);
#ifdef HAVE_STRUCT_STAT_ST_BLKSIZE
      new_file->filestat.st_blksize=cluster_size;
#ifdef HAVE_STRUCT_STAT_ST_BLOCKS
      if(new_file->filestat.st_blksize!=0)
      {
	new_file->filestat.st_blocks=(new_file->filestat.st_size+new_file->filestat.st_blksize-1)/new_file->filestat.st_blksize;
      }
#endif
#endif
      new_file->filestat.st_atime=new_file->filestat.st_ctime=new_file->filestat.st_mtime=date_dos2unix(le16(de->time),le16(de->date));
      new_file->prev=current_file;
      new_file->next=NULL;
      /* log_debug("fat: new file %s de=%p size=%u\n",new_file->name,de,le32(de->size)); */
      if(current_file!=NULL)
        current_file->next=new_file;
      else
        dir_list=new_file;
      current_file=new_file;
    }
    else
    {
      return dir_list;
    }
  }
  de++;
  if((const void *)de<(const void *)(buffer+size-1))
    goto GetNew;
EODir:
  return dir_list;
}

static int day_n[] = { 0,31,59,90,120,151,181,212,243,273,304,334,0,0,0,0 };
		  /* JanFebMarApr May Jun Jul Aug Sep Oct Nov Dec */

/* Convert a MS-DOS time/date pair to a UNIX date (seconds since 1 1 70). */

static int date_dos2unix(const unsigned short f_time, const unsigned short f_date)
{
	int month,year,secs;

	/* first subtract and mask after that... Otherwise, if
	   f_date == 0, bad things happen */
	month = ((f_date >> 5) - 1) & 15;
	year = f_date >> 9;
	secs = (f_time & 31)*2+60*((f_time >> 5) & 63)+(f_time >> 11)*3600+86400*
	    ((f_date & 31)-1+day_n[month]+(year/4)+year*365-((year & 3) == 0 &&
	    month < 2 ? 1 : 0)+3653);
			/* days since 1.1.70 plus 80's leap day */
	return secs+secwest;
}

static file_data_t *fat12_dir(disk_t *disk_car, const partition_t *partition, dir_data_t *dir_data, const unsigned long int first_cluster)
{
  const struct fat_dir_struct *ls=(const struct fat_dir_struct*)dir_data->private_dir_data;
  const struct fat_boot_sector*fat_header=ls->boot_sector;
  if(fat_header->cluster_size<1)
  {
    log_error("FAT12: Can't list files, bad cluster size\n");
    return NULL;
  }
  if(fat_sector_size(fat_header)==0)
  {
    log_error("FAT12: Can't list files, bad sector size\n");
    return NULL;
  }
  if(first_cluster==0)
    return fat1x_rootdir(disk_car,partition,dir_data->verbose,fat_header);
  {
    file_data_t *dir_list;
    unsigned int cluster_size=fat_header->cluster_size;
    unsigned char *buffer_dir=MALLOC(fat_sector_size(fat_header)*cluster_size*10);
    unsigned int cluster;
    unsigned int nbr_cluster;
    int stop=0;
    memset(buffer_dir,0,fat_sector_size(fat_header)*cluster_size*10);
    for(cluster=first_cluster, nbr_cluster=0;
	((cluster&0x0ff8)!=(unsigned)FAT12_EOC) && (cluster>=2) && (nbr_cluster<10) && (stop==0);
	cluster=get_next_cluster(disk_car,partition, UP_FAT12,le16(fat_header->reserved), cluster), nbr_cluster++)
    {
      uint64_t start=partition->part_offset+(uint64_t)(le16(fat_header->reserved)+fat_header->fats*le16(fat_header->fat_length)+(get_dir_entries(fat_header)*32+fat_sector_size(fat_header)-1)/fat_sector_size(fat_header)+(cluster-2)*cluster_size)*fat_sector_size(fat_header);
      if(dir_data->verbose>0)
      {
        log_info("FAT12: cluster=%u(0x%x), pos=%lu\n",cluster,cluster,(long unsigned)(start/fat_sector_size(fat_header)));
      }
      if(disk_car->read(disk_car, cluster_size*fat_sector_size(fat_header), buffer_dir+(uint64_t)fat_sector_size(fat_header)*cluster_size*nbr_cluster, start))
      {
	log_error("FAT12: Can't read directory cluster\n");
	stop=1;
      }
    }
    dir_list=dir_fat_aux(buffer_dir,fat_sector_size(fat_header)*cluster_size*nbr_cluster,cluster_size);
    free(buffer_dir);
    return dir_list;
  }
}

static file_data_t *fat16_dir(disk_t *disk_car, const partition_t *partition, dir_data_t *dir_data, const unsigned long int first_cluster)
{
  const struct fat_dir_struct *ls=(const struct fat_dir_struct*)dir_data->private_dir_data;
  const struct fat_boot_sector*fat_header=ls->boot_sector;
  if(fat_header->cluster_size<1)
  {
    log_error("FAT16: Can't list files, bad cluster size.\n");
    return NULL;
  }
  if(fat_sector_size(fat_header)==0)
  {
    log_error("FAT16: Can't list files, bad sector size\n");
    return NULL;
  }
  if(first_cluster==0)
    return fat1x_rootdir(disk_car,partition,dir_data->verbose,fat_header);
  {
    file_data_t *dir_list=NULL;
    unsigned int cluster_size=fat_header->cluster_size;
    unsigned char *buffer_dir=MALLOC(disk_car->sector_size*cluster_size*10);
    unsigned int cluster;
    unsigned int nbr_cluster;
    int stop=0;
    memset(buffer_dir,0,disk_car->sector_size*cluster_size*10);
    /* Need to correct the test */
    for(cluster=first_cluster, nbr_cluster=0;
        ((cluster&0xfff8)!=(unsigned)FAT16_EOC) && (cluster>=2) && (nbr_cluster<10)&&(stop==0);
        cluster=get_next_cluster(disk_car,partition, UP_FAT16,le16(fat_header->reserved), cluster), nbr_cluster++)
    {
      uint64_t start=partition->part_offset+(uint64_t)(le16(fat_header->reserved)+fat_header->fats*le16(fat_header->fat_length)+(get_dir_entries(fat_header)*32+disk_car->sector_size-1)/disk_car->sector_size+(cluster-2)*cluster_size)*disk_car->sector_size;
      if(dir_data->verbose>0)
      {
        log_info("FAT16 cluster=%u(0x%x), pos=%lu\n",cluster,cluster,(long unsigned)(start/disk_car->sector_size));
      }
      if(disk_car->read(disk_car, cluster_size*disk_car->sector_size, buffer_dir+(uint64_t)disk_car->sector_size*cluster_size*nbr_cluster, start))
      {
        log_error("FAT16: Can't read directory cluster\n");
        stop=1;
      }
    }
    dir_list=dir_fat_aux(buffer_dir,disk_car->sector_size*cluster_size*nbr_cluster,cluster_size);
    free(buffer_dir);
    return dir_list;
  }
}

static file_data_t *fat32_dir(disk_t *disk_car, const partition_t *partition, dir_data_t *dir_data, const unsigned long int first_cluster)
{
  const struct fat_dir_struct *ls=(const struct fat_dir_struct*)dir_data->private_dir_data;
  const struct fat_boot_sector*fat_header=ls->boot_sector;
  if(fat_header->cluster_size==0)
  {
    log_error("FAT32: Can't list files, bad cluster size.\n");
    return NULL;
  }
  if(le32(fat_header->root_cluster)==0)
  {
    log_error("FAT32: Can't list files, bad root cluster.\n");
    return NULL;
  }
  if(fat_sector_size(fat_header)==0)
  {
    log_error("FAT32: Can't list files, bad sector size.\n");
    return NULL;
  }
  {
    file_data_t *dir_list;
    unsigned int cluster_size=fat_header->cluster_size;
    unsigned char *buffer_dir=MALLOC(fat_sector_size(fat_header)*cluster_size*10);
    unsigned int cluster;
    unsigned int nbr_cluster;
    int stop=0;
    memset(buffer_dir,0,fat_sector_size(fat_header)*cluster_size*10);
    /* Need to correct the test */
    for(cluster=(first_cluster==0?le32(fat_header->root_cluster):first_cluster), nbr_cluster=0;
        ((cluster&0xffffff8)!=(unsigned)FAT32_EOC) && (cluster>=2) && (nbr_cluster<10) && (stop==0);
        cluster=get_next_cluster(disk_car,partition, UP_FAT32,le16(fat_header->reserved), cluster), nbr_cluster++)
    {
      uint64_t start=partition->part_offset+(uint64_t)(le16(fat_header->reserved)+fat_header->fats*le32(fat_header->fat32_length)+(cluster-2)*cluster_size)*fat_sector_size(fat_header);
      if(dir_data->verbose>0)
      {
        log_verbose("FAT32 cluster=%u(0x%x), pos=%lu\n",cluster,cluster,(long unsigned)(start/fat_sector_size(fat_header)));
      }
      if(disk_car->read(disk_car, cluster_size*fat_sector_size(fat_header), buffer_dir+(uint64_t)fat_sector_size(fat_header)*cluster_size*nbr_cluster, start))
      {
        log_error("FAT32: Can't read directory cluster\n");
        stop=1;
      }
      //      log_debug("read cluster %u\n",cluster);
    }
    //    log_debug("nbr_cluster=%u\n",nbr_cluster);
    dir_list=dir_fat_aux(buffer_dir,fat_sector_size(fat_header)*cluster_size*nbr_cluster,cluster_size);
    free(buffer_dir);
    return dir_list;
  }
}


static file_data_t *fat1x_rootdir(disk_t *disk_car, const partition_t *partition, const int verbose, const struct fat_boot_sector*fat_header)
{
  unsigned int root_size=(get_dir_entries(fat_header)*32+disk_car->sector_size-1)/disk_car->sector_size*disk_car->sector_size;
  if(verbose>1)
  {
    log_trace("fat1x_rootdir root_size=%u sectors\n",root_size/disk_car->sector_size);
  }
  {
    file_data_t *res=NULL;
    uint64_t start;
    unsigned char *buffer_dir;
    buffer_dir=(unsigned char*)MALLOC(root_size);
    start=partition->part_offset+(uint64_t)((le16(fat_header->reserved)+fat_header->fats*le16(fat_header->fat_length))*disk_car->sector_size);
    if(disk_car->read(disk_car, root_size, buffer_dir, start))
    {
      log_error("FAT 1x: Can't read root directory\n");
      free(buffer_dir);
      return NULL;
    }
    res=dir_fat_aux(buffer_dir,root_size,fat_header->cluster_size);
    free(buffer_dir);
    return res;
  }
}


static void set_secwest(void)
{
  struct  tm *tmptr;
  time_t t;

  t = time(NULL);
  tmptr = localtime(&t);
#ifdef HAVE_STRUCT_TM_TM_GMTOFF
  secwest = -1 * tmptr->tm_gmtoff;
#elif defined (DJGPP)
  secwest = 0;
#else
#if defined (__CYGWIN__)
  secwest = _timezone;
#else
  secwest = timezone;
#endif
  /* account for daylight savings */
  if (tmptr->tm_isdst)
    secwest -= 3600;
#endif
}

int dir_partition_fat_init(disk_t *disk_car, const partition_t *partition, dir_data_t *dir_data, const int verbose)
{
  static unsigned char *buffer;
  static struct fat_dir_struct *ls;
  buffer=(unsigned char*)MALLOC(0x200);
  if(disk_car->read(disk_car,0x200, buffer, partition->part_offset+(uint64_t)partition->boot_sector*disk_car->sector_size))
  {
    free(buffer);
    return -1;
  }
  set_secwest();
  ls=(struct fat_dir_struct *)MALLOC(sizeof(*ls));
  ls->boot_sector=(struct fat_boot_sector*)buffer;
  strncpy(dir_data->current_directory,"/",sizeof(dir_data->current_directory));
  dir_data->current_inode=0;
  dir_data->verbose=verbose;
  dir_data->copy_file=NULL;
  dir_data->close=dir_partition_fat_close;
  dir_data->local_dir=NULL;
  dir_data->private_dir_data=ls;
  switch(partition->upart_type)
  {
    case UP_FAT12:
      dir_data->get_dir=fat12_dir;
      break;
    case UP_FAT16:
      dir_data->get_dir=fat16_dir;
      break;
    case UP_FAT32:
      dir_data->get_dir=fat32_dir;
      break;
    default:
      log_critical("Not a valid FAT type (upart_type=%u)\n",partition->upart_type);
      free(ls->boot_sector);
      free(ls);
      dir_data->private_dir_data=NULL;
      return -1;
  }
  return 0;
}

static void dir_partition_fat_close(dir_data_t *dir_data)
{
  struct fat_dir_struct *ls=(struct fat_dir_struct*)dir_data->private_dir_data;
  free(ls->boot_sector);
  free(ls);
}
