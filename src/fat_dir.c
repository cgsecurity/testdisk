/*

    File: fat_dir.c

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
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#include <errno.h>
#include "types.h"
#include "common.h"
#include "fat.h"
#include "lang.h"
#include "intrf.h"
#include "dir.h"
#include "fat_dir.h"
#include "log.h"
#include "setdate.h"

#define MSDOS_MKMODE(a,m) ((m & (a & ATTR_RO ? LINUX_S_IRUGO|LINUX_S_IXUGO : LINUX_S_IRWXUGO)) | (a & ATTR_DIR ? LINUX_S_IFDIR : LINUX_S_IFREG))
struct fat_dir_struct
{
  struct fat_boot_sector*boot_sector;
};


static int date_dos2unix(const unsigned short f_time,const unsigned short f_date);
static file_data_t *fat1x_rootdir(disk_t *disk_car, const partition_t *partition, const dir_data_t *dir_data, const struct fat_boot_sector*fat_header);
static file_data_t *fat_dir(disk_t *disk_car, const partition_t *partition, dir_data_t *dir_data, const unsigned long int first_cluster);
static inline void fat16_towchar(wchar_t *dst, const uint8_t *src, size_t len);
static int fat_copy(disk_t *disk_car, const partition_t *partition, dir_data_t *dir_data, const file_data_t *file);
static void dir_partition_fat_close(dir_data_t *dir_data);

static int32_t secwest;

static inline void fat16_towchar(wchar_t *dst, const uint8_t *src, size_t len)
{
	while (len--) {
		*dst++ = src[0] | (src[1] << 8);
		src += 2;
	}
}

file_data_t *dir_fat_aux(const unsigned char*buffer, const unsigned int size, const unsigned int cluster_size, const unsigned int param)
{
  const struct msdos_dir_entry *de=(const struct msdos_dir_entry*)buffer;
  wchar_t unicode[1000];
  unsigned char long_slots;
  file_data_t *dir_list=NULL;
  file_data_t *current_file=NULL;
  unsigned int status;
  unsigned int inode;
  int utf8=1;
#ifdef HAVE_WCTOMB
  wctomb(NULL, 0);
#endif
GetNew:
  status=0;
  long_slots = 0;
  unicode[0]=0;
  if (de->attr == ATTR_EXT &&
      de->name[0] == (int8_t) DELETED_FLAG &&
      (param & FLAG_LIST_DELETED)==FLAG_LIST_DELETED)
  {
    unsigned int i;
    const struct msdos_dir_slot *ds;
    const struct msdos_dir_entry *de_initial;
    unsigned char slot;
    unsigned char sum;
    unsigned char alias_checksum;
ParseLongDeleted:
    de_initial=de;
    long_slots = 0;
    ds = (const struct msdos_dir_slot *) de;
    alias_checksum = ds->alias_checksum;
    /* The number of slot has been overwritten, try to find it */
    while (1)
    {
      if((const void*)de>=(const void*)(buffer+size))
	goto EODir;
      ds = (const struct msdos_dir_slot *) de;
      if(de->name[0] != (int8_t) DELETED_FLAG)
	goto GetNew;
      if (ds->attr !=  ATTR_EXT)
	goto ParseLongDeletedNext;
      if (ds->alias_checksum != alias_checksum)
	goto ParseLongDeleted;
      de++;
      long_slots++;
    }
ParseLongDeletedNext:
    if ((de->attr & ATTR_VOLUME)!=0)
    {
      long_slots=0;
      goto RecEnd;
    }
    {
      ds = (const struct msdos_dir_slot *) de_initial;
      unicode[long_slots * 13] = 0;
      for(slot=long_slots;slot!=0;)
      {
	int offset;
	slot--;
	offset = slot * 13;
	fat16_towchar(unicode + offset, ds->name0_4, 5);
	fat16_towchar(unicode + offset + 5, ds->name5_10, 6);
	fat16_towchar(unicode + offset + 11, ds->name11_12, 2);
	ds++;
      }
    }
    /* The first char of the short filename has been overwritten,
       use the uppercase version of the first char from the unicode filename
     */
    for (sum = toupper(unicode[0]), i = 1; i < 8; i++)
      sum = (((sum&1)<<7)|((sum&0xfe)>>1)) + de->name[i];
    for (i = 0; i < 3; i++)
      sum = (((sum&1)<<7)|((sum&0xfe)>>1)) + de->ext[i];
    /* If checksum don't match, use the short filename */
    if (sum != alias_checksum)
      long_slots = 0;
    else
      status=FILE_STATUS_DELETED;
  }
  else if (de->attr == ATTR_EXT)
  {
    unsigned int i;
    const struct msdos_dir_slot *ds;
    unsigned char id;
    unsigned char sum;
    unsigned char alias_checksum;
ParseLong:
    ds = (const struct msdos_dir_slot *) de;
    id = ds->id;
    if ((id & 0x40)==0)
      goto RecEnd;
    {
      unsigned char slots;
      unsigned char slot;
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
	{
	  long_slots=0;
	  goto RecEnd;	/* XXX */
	}
	if ((ds->id & ~0x40) != slot)
	  goto ParseLong;
	if (ds->alias_checksum != alias_checksum)
	  goto ParseLong;
      }
    }
    if (de->attr ==  ATTR_EXT)
      goto ParseLong;
    if (IS_FREE(de->name) || ((de->attr & ATTR_VOLUME)!=0))
    {
      long_slots=0;
      goto RecEnd;
    }
    for (sum = 0, i = 0; i < 8; i++)
      sum = (((sum&1)<<7)|((sum&0xfe)>>1)) + de->name[i];
    for (i = 0; i < 3; i++)
      sum = (((sum&1)<<7)|((sum&0xfe)>>1)) + de->ext[i];
    if (sum != alias_checksum)
      long_slots = 0;
  }
RecEnd:
    inode=(le16(de->starthi)<<16)|le16(de->start);
    if((param&FLAG_LIST_MASK12)!=0)
      inode&=0xfff;
    else if((param&FLAG_LIST_MASK16)!=0)
      inode&=0xffff;
    else
      inode&=0xfffffff;
  if(long_slots==0 && de->attr != ATTR_EXT)
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
    if(((int8_t) unicode[0] == (int8_t) DELETED_FLAG) &&
      ((param & FLAG_LIST_DELETED)==FLAG_LIST_DELETED) &&
      inode!=0 && de->name[1]!='\0' &&
      de->name[2]!='\0' && de->name[3]!='\0' &&
      de->name[4]!='\0' && de->name[5]!='\0' &&
      de->name[6]!='\0' && de->name[7]!='\0')
     {
      status=FILE_STATUS_DELETED;
      if((de->attr&ATTR_DIR)==ATTR_DIR &&
	((dir_list==NULL && unicode[1]=='\0') ||
	 (dir_list!=NULL && dir_list->next==NULL && unicode[1]=='.' && unicode[2]=='\0')))
	unicode[0]='.';	/* "." and ".." are the first two entries */
      else
	unicode[0]='_';
    }
  }
  if (((de->attr != ATTR_EXT)||(long_slots!=0)) &&
      !(de->attr & ATTR_VOLUME))
  {
    if(unicode[0]==0)
      return dir_list;
    if((int8_t) unicode[0] != (int8_t) DELETED_FLAG)
    {
      unsigned int i,o;
      file_data_t *new_file=(file_data_t *)MALLOC(sizeof(*new_file));
      for(i=0,o=0; unicode[i]!=0 && o<sizeof(new_file->name)-1; i++)
      {
	if(utf8 && unicode[i]>0x7f)
	{
#ifdef HAVE_WCTOMB
	  const int sizec=wctomb(&new_file->name[o], unicode[i]);
#else
	  const int sizec=unicode[i];
#endif
	  if(sizec <= 0)
	  {
	    new_file->name[o]=(char) unicode[i];
	    utf8=0;
	  }
	  else
	    o += sizec;
	}
	else
	  new_file->name[o++]=(char) unicode[i];
      }
      new_file->name[o]=0;
      new_file->stat.st_dev=0;
      new_file->stat.st_ino=inode;
      new_file->stat.st_mode = MSDOS_MKMODE(de->attr,(LINUX_S_IRWXUGO & ~(LINUX_S_IWGRP|LINUX_S_IWOTH)));
      new_file->stat.st_nlink=0;
      new_file->stat.st_uid=0;
      new_file->stat.st_gid=0;
      new_file->stat.st_rdev=0;
      new_file->stat.st_size=le32(de->size);
#ifdef HAVE_STRUCT_STAT_ST_BLKSIZE
      new_file->stat.st_blksize=cluster_size;
#ifdef HAVE_STRUCT_STAT_ST_BLOCKS
      if(new_file->stat.st_blksize!=0)
      {
	new_file->stat.st_blocks=(le32(de->size) + new_file->stat.st_blksize - 1) / new_file->stat.st_blksize;
      }
#endif
#endif
      new_file->stat.st_atime=new_file->stat.st_ctime=new_file->stat.st_mtime=date_dos2unix(le16(de->time),le16(de->date));
      new_file->status=status;
      new_file->prev=current_file;
      new_file->next=NULL;
      /* log_debug("fat: new file %s de=%p size=%u\n",new_file->name,de,le32(de->size)); */
      if(current_file!=NULL)
        current_file->next=new_file;
      else
        dir_list=new_file;
      current_file=new_file;
    }
  }
  de++;
  if((const void *)de<(const void *)(buffer+size-1) &&
      de->name[0] != (int8_t) 0)
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

enum {FAT_FOLLOW_CLUSTER, FAT_NEXT_FREE_CLUSTER, FAT_NEXT_CLUSTER};

static int is_EOC(const unsigned int cluster, const upart_type_t upart_type)
{
  if(upart_type==UP_FAT12)
    return ((cluster&0x0ff8)==(unsigned)FAT12_EOC);
  else if(upart_type==UP_FAT16)
    return ((cluster&0x0fff8)==(unsigned)FAT16_EOC);
  else
    return((cluster&0xffffff8)==(unsigned)FAT32_EOC);
}

#define NBR_CLUSTER_MAX 30
static file_data_t *fat_dir(disk_t *disk_car, const partition_t *partition, dir_data_t *dir_data, const unsigned long int first_cluster)
{
  const struct fat_dir_struct *ls=(const struct fat_dir_struct*)dir_data->private_dir_data;
  const struct fat_boot_sector*fat_header=ls->boot_sector;
  unsigned int cluster=first_cluster;
  if(fat_header->sectors_per_cluster<1)
  {
    log_error("FAT: Can't list files, bad cluster size.\n");
    return NULL;
  }
  if(fat_sector_size(fat_header)==0)
  {
    log_error("FAT: Can't list files, bad sector size.\n");
    return NULL;
  }
  if(cluster==0)
  {
    if(partition->upart_type!=UP_FAT32)
      return fat1x_rootdir(disk_car, partition, dir_data, fat_header);
    if(le32(fat_header->root_cluster)<2)
    {
      log_error("FAT32: Can't list files, bad root cluster.\n");
      return NULL;
    }
    cluster=le32(fat_header->root_cluster);
  }
  {
    file_data_t *dir_list=NULL;
    const unsigned int cluster_size=fat_header->sectors_per_cluster * fat_sector_size(fat_header);
    unsigned char *buffer_dir=(unsigned char *)MALLOC(cluster_size*NBR_CLUSTER_MAX);
    unsigned int nbr_cluster;
    int stop=0;
    uint64_t start_fat1,start_data,part_size;
    unsigned long int no_of_cluster,fat_length;
    unsigned int fat_meth=FAT_FOLLOW_CLUSTER;
    memset(buffer_dir,0,cluster_size*NBR_CLUSTER_MAX);
    fat_length=le16(fat_header->fat_length)>0?le16(fat_header->fat_length):le32(fat_header->fat32_length);
    part_size=(sectors(fat_header)>0?sectors(fat_header):le32(fat_header->total_sect));
    start_fat1=le16(fat_header->reserved);
    start_data=start_fat1+fat_header->fats*fat_length+(get_dir_entries(fat_header)*32+disk_car->sector_size-1)/disk_car->sector_size;
    no_of_cluster=(part_size-start_data)/fat_header->sectors_per_cluster;
    nbr_cluster=0;
    while(!is_EOC(cluster, partition->upart_type) && cluster>=2 && nbr_cluster<NBR_CLUSTER_MAX && stop==0)
    {
      uint64_t start=partition->part_offset+(uint64_t)(start_data+(cluster-2)*fat_header->sectors_per_cluster)*fat_sector_size(fat_header);
//      if(dir_data->verbose>0)
      {
        log_info("FAT: cluster=%u(0x%x), pos=%lu\n",cluster,cluster,(long unsigned)(start/fat_sector_size(fat_header)));
      }
      if((unsigned)disk_car->pread(disk_car, buffer_dir + (uint64_t)cluster_size * nbr_cluster, cluster_size, start) != cluster_size)
      {
	log_error("FAT: Can't read directory cluster.\n");
	stop=1;
      }
      if(stop==0 && nbr_cluster==0 &&
	  !(partition->upart_type==UP_FAT32 && first_cluster==0) &&
	  !(buffer_dir[0]=='.' && buffer_dir[0x20]=='.' && buffer_dir[0x21]=='.'))
      {
	stop=1;
      }
      if(stop==0)
      {
	if(fat_meth==FAT_FOLLOW_CLUSTER)
	{
	  const unsigned int next_cluster=get_next_cluster(disk_car, partition, partition->upart_type, start_fat1, cluster);
	  if((next_cluster>=2 && next_cluster<=no_of_cluster+2) ||
	      is_EOC(next_cluster, partition->upart_type))
	    cluster=next_cluster;
	  else if(next_cluster==0)
	  {
#if 0
	    /* FIXME: experimental */
	    if(cluster==first_cluster && (dir_data->param & FLAG_LIST_DELETED)==FLAG_LIST_DELETED)
	      fat_meth=FAT_NEXT_FREE_CLUSTER;	/* Recovery of a deleted directory */
	    else
	      cluster=0;			/* Stop directory listing */
#else
	    cluster=0;			/* Stop directory listing */
#endif
	  }
	  else
	    fat_meth=FAT_NEXT_CLUSTER;		/* FAT is corrupted, don't trust it */
	}
	if(fat_meth==FAT_NEXT_CLUSTER)
	  cluster++;
	else if(fat_meth==FAT_NEXT_FREE_CLUSTER)
	{	/* Deleted directories are composed of "free" clusters */
	  while(++cluster<no_of_cluster+2 &&
	      get_next_cluster(disk_car, partition, partition->upart_type, start_fat1, cluster)!=0);
	}
	nbr_cluster++;
      }
    }
    if(nbr_cluster>0)
      dir_list=dir_fat_aux(buffer_dir, cluster_size*nbr_cluster, cluster_size, dir_data->param);
    free(buffer_dir);
    return dir_list;
  }
}

static file_data_t *fat1x_rootdir(disk_t *disk_car, const partition_t *partition, const dir_data_t *dir_data, const struct fat_boot_sector*fat_header)
{
  const unsigned int root_size=(get_dir_entries(fat_header)*32+disk_car->sector_size-1)/disk_car->sector_size*disk_car->sector_size;
  if(root_size==0)
    return NULL;
  if(dir_data->verbose>1)
  {
    log_trace("fat1x_rootdir root_size=%u sectors\n",root_size/disk_car->sector_size);
  }
  {
    file_data_t *res=NULL;
    uint64_t start;
    unsigned char *buffer_dir;
    buffer_dir=(unsigned char*)MALLOC(root_size);
    start=partition->part_offset+(uint64_t)((le16(fat_header->reserved)+fat_header->fats*le16(fat_header->fat_length))*disk_car->sector_size);
    if((unsigned)disk_car->pread(disk_car, buffer_dir, root_size, start) != root_size)
    {
      log_error("FAT 1x: Can't read root directory.\n");
      /* Don't return yet, it may have been a partial read */
    }
    res=dir_fat_aux(buffer_dir, root_size, fat_header->sectors_per_cluster * fat_sector_size(fat_header), dir_data->param);
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
  if(disk_car->pread(disk_car, buffer, 0x200, partition->part_offset) != 0x200)
  {
    log_error("Can't read FAT boot sector.\n");
    free(buffer);
    return -1;
  }
  set_secwest();
  ls=(struct fat_dir_struct *)MALLOC(sizeof(*ls));
  ls->boot_sector=(struct fat_boot_sector*)buffer;
  strncpy(dir_data->current_directory,"/",sizeof(dir_data->current_directory));
  dir_data->current_inode=0;
  dir_data->param=FLAG_LIST_DELETED;
  if(partition->upart_type==UP_FAT12)
    dir_data->param|=FLAG_LIST_MASK12;
  else if(partition->upart_type==UP_FAT16)
    dir_data->param|=FLAG_LIST_MASK16;
  dir_data->verbose=verbose;
  dir_data->capabilities=CAPA_LIST_DELETED;
  dir_data->copy_file=fat_copy;
  dir_data->close=dir_partition_fat_close;
  dir_data->local_dir=NULL;
  dir_data->private_dir_data=ls;
  dir_data->get_dir=fat_dir;
  return 0;
}

static void dir_partition_fat_close(dir_data_t *dir_data)
{
  struct fat_dir_struct *ls=(struct fat_dir_struct*)dir_data->private_dir_data;
  free(ls->boot_sector);
  free(ls);
}

static int fat_copy(disk_t *disk_car, const partition_t *partition, dir_data_t *dir_data, const file_data_t *file)
{
  char *new_file;	
  FILE *f_out;
  const struct fat_dir_struct *ls=(const struct fat_dir_struct*)dir_data->private_dir_data;
  const struct fat_boot_sector *fat_header=ls->boot_sector;
  const unsigned int sectors_per_cluster=fat_header->sectors_per_cluster;
  const unsigned int block_size=fat_sector_size(fat_header)*sectors_per_cluster;
  unsigned char *buffer_file=(unsigned char *)MALLOC(block_size);
  unsigned int cluster;
  unsigned int file_size=file->stat.st_size;
  unsigned int fat_meth=FAT_FOLLOW_CLUSTER;
  uint64_t start_fat1,start_data,part_size;
  unsigned long int no_of_cluster,fat_length;
  f_out=fopen_local(&new_file, dir_data->local_dir, dir_data->current_directory);
  if(!f_out)
  {
    log_critical("Can't create file %s: \n",new_file);
    free(new_file);
    free(buffer_file);
    return -1;
  }
  cluster = file->stat.st_ino;
  fat_length=le16(fat_header->fat_length)>0?le16(fat_header->fat_length):le32(fat_header->fat32_length);
  part_size=(sectors(fat_header)>0?sectors(fat_header):le32(fat_header->total_sect));
  start_fat1=le16(fat_header->reserved);
  start_data=start_fat1+fat_header->fats*fat_length+(get_dir_entries(fat_header)*32+disk_car->sector_size-1)/disk_car->sector_size;
  no_of_cluster=(part_size-start_data)/sectors_per_cluster;
  log_trace("fat_copy dst=%s first_cluster=%u (%llu) size=%lu\n", new_file,
      cluster,
      (long long unsigned)start_data+(cluster-2)*sectors_per_cluster,
      (long unsigned)file_size);

  while(cluster>=2 && cluster<=no_of_cluster+2 && file_size>0)
  {
    const uint64_t start=partition->part_offset+(uint64_t)(start_data+(cluster-2)*sectors_per_cluster)*fat_sector_size(fat_header);
    unsigned int toread = block_size;
    if (toread > file_size)
      toread = file_size;
    if((unsigned)disk_car->pread(disk_car, buffer_file, toread, start) != toread)
    {
      log_error("fat_copy: Can't read cluster %u.\n", cluster);
    }
    if(fwrite(buffer_file, 1, toread, f_out) != toread)
    {
      log_error("fat_copy: failed to write data %s\n", strerror(errno));
      fclose(f_out);
      set_date(new_file, file->stat.st_atime, file->stat.st_mtime);
      free(new_file);
      free(buffer_file);
      return -1;
    }
    file_size -= toread;
    if(file_size>0)
    {
      if(fat_meth==FAT_FOLLOW_CLUSTER)
      {
	const unsigned int next_cluster=get_next_cluster(disk_car, partition, partition->upart_type, start_fat1, cluster);
	if(next_cluster>=2 && next_cluster<=no_of_cluster+2)
	  cluster=next_cluster;
	else if(cluster==file->stat.st_ino && next_cluster==0)
	  fat_meth=FAT_NEXT_FREE_CLUSTER;	/* Recovery of a deleted file */
	else
	  fat_meth=FAT_NEXT_CLUSTER;		/* FAT is corrupted, don't trust it */
      }
      if(fat_meth==FAT_NEXT_CLUSTER)
	cluster++;
      else if(fat_meth==FAT_NEXT_FREE_CLUSTER)
      {	/* Deleted file are composed of "free" clusters */
	while(++cluster<no_of_cluster+2 &&
	    get_next_cluster(disk_car, partition, partition->upart_type, start_fat1, cluster)!=0);
      }
    }
  }
  fclose(f_out);
  set_date(new_file, file->stat.st_atime, file->stat.st_mtime);
  free(new_file);
  free(buffer_file);
  return 0;
}
