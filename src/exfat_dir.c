/*

    File: exfat_dir.c

    Copyright (C) 2011 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifdef HAVE_ICONV_H
#include <iconv.h>
#endif
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
#include "exfat.h"
#include "lang.h"
#include "intrf.h"
#include "dir.h"
#include "exfat_dir.h"
#include "log.h"
#include "setdate.h"
#include "fat.h"

#define EXFAT_MKMODE(a,m) ((m & (a & ATTR_RO ? LINUX_S_IRUGO|LINUX_S_IXUGO : LINUX_S_IRWXUGO)) | (a & ATTR_DIR ? LINUX_S_IFDIR : LINUX_S_IFREG))
struct exfat_dir_struct
{
  struct exfat_super_block*boot_sector;
#ifdef HAVE_ICONV
  iconv_t cd;
#endif
};


static file_data_t *exfat_dir(disk_t *disk, const partition_t *partition, dir_data_t *dir_data, const unsigned long int first_cluster);
static inline void exfat16_towchar(wchar_t *dst, const uint8_t *src, size_t len);
static int exfat_copy(disk_t *disk, const partition_t *partition, dir_data_t *dir_data, const file_data_t *file);
static void dir_partition_exfat_close(dir_data_t *dir_data);

static inline void exfat16_towchar(wchar_t *dst, const uint8_t *src, size_t len)
{
	while (len--) {
		*dst++ = src[0] | (src[1] << 8);
		src += 2;
	}
}

#define ATTR_RO      1  /* read-only */
#define ATTR_HIDDEN  2  /* hidden */
#define ATTR_SYS     4  /* system */
#define ATTR_DIR     16 /* directory */
#define ATTR_ARCH    32 /* archived */
#define EXFAT_MKMODE(a,m) ((m & (a & ATTR_RO ? LINUX_S_IRUGO|LINUX_S_IXUGO : LINUX_S_IRWXUGO)) | (a & ATTR_DIR ? LINUX_S_IFDIR : LINUX_S_IFREG))

static file_data_t *dir_exfat_aux(const unsigned char*buffer, const unsigned int size, const unsigned int param)
{
  /*
   * 0x83 Volume label
   * 0x81 Allocation bitmap
   * 0x82 Upcase tabel
   * 0x85 File			-> 0x05
   * 0xC0 Stream extension	-> 0x40
   * 0xC1 File name extension	-> 0x41
   * 0xA0 Volume GUID
   * 0xA1 TexFAT padding
   * 0xE2 Windows CE ACL
   *
   */
  file_data_t *dir_list=NULL;
  file_data_t *current_file=NULL;
  unsigned int offset=0;
  unsigned int sec_count=0;
  for(offset=0; offset<size; offset+=0x20)
  {
    if((buffer[offset]&0x80)==0 &&
	(param & FLAG_LIST_DELETED)!=FLAG_LIST_DELETED)
      continue;
    if((buffer[offset]&0x7f)==0x05)
    { /* File directory entry */
      const struct exfat_file_entry *entry=(const struct exfat_file_entry *)&buffer[offset];
      file_data_t *new_file=(file_data_t *)MALLOC(sizeof(*new_file));
      sec_count=entry->sec_count;
      new_file->name[0]=0;
      new_file->stat.st_dev=0;
      new_file->stat.st_ino=0;
      new_file->stat.st_mode = EXFAT_MKMODE(entry->attr,(LINUX_S_IRWXUGO & ~(LINUX_S_IWGRP|LINUX_S_IWOTH)));
      new_file->stat.st_nlink=0;
      new_file->stat.st_uid=0;
      new_file->stat.st_gid=0;
      new_file->stat.st_rdev=0;
      new_file->stat.st_size=0;
#ifdef DJGPP
      new_file->file_size=0;
#endif
#ifdef HAVE_STRUCT_STAT_ST_BLKSIZE
      new_file->stat.st_blksize=0;
#ifdef HAVE_STRUCT_STAT_ST_BLOCKS
      if(new_file->stat.st_blksize!=0)
      {
	new_file->stat.st_blocks=0;
      }
#endif
#endif
      new_file->stat.st_atime=date_dos2unix(le16(entry->atime),le16(entry->adate));
      new_file->stat.st_ctime=date_dos2unix(le16(entry->ctime),le16(entry->cdate));
      new_file->stat.st_mtime=date_dos2unix(le16(entry->mtime),le16(entry->mdate));
      new_file->status=((entry->type&0x80)==0x80?0:FILE_STATUS_DELETED);
      new_file->prev=current_file;
      new_file->next=NULL;
      /* log_debug("exfat: new file %s de=%p size=%u\n",new_file->name,de,le32(de->size)); */
      if(current_file!=NULL)
        current_file->next=new_file;
      else
        dir_list=new_file;
      current_file=new_file;
    }
    else if(sec_count>0 && current_file!=NULL)
    {
      if((buffer[offset]&0x7f)==0x40)
      {
	/* Stream extension */
	const struct exfat_stream_ext_entry *entry=(const struct exfat_stream_ext_entry*)&buffer[offset];
	current_file->stat.st_size=le64(entry->data_length);
#ifdef DJGPP
	current_file->file_size=le64(entry->data_length);
#endif
	current_file->stat.st_ino=le32(entry->first_cluster);
#if 0
	if((entry->first_cluster&2)!=0)
	  current_file->stat.st_size=0;
#endif
      }
      else if((buffer[offset]&0x7f)==0x41)
      {
	unsigned int i,j;
	for(j=0; j<255 && current_file->name[j]!='\0'; j++);
	/* FIXME see ntfs_ucstoutf8 && ntfs_ucstombs*/
	for(i=2; i<32; i+=2)
	  current_file->name[j++]=buffer[offset+i];
	current_file->name[j]='\0';
      }
      sec_count--;
    }
  }
  return dir_list;
}

enum {exFAT_FOLLOW_CLUSTER, exFAT_NEXT_FREE_CLUSTER, exFAT_NEXT_CLUSTER};

static int is_EOC(const unsigned int cluster)
{
  return(cluster==0xFFFFFFFF);
}

#define NBR_CLUSTER_MAX 30
static file_data_t *exfat_dir(disk_t *disk, const partition_t *partition, dir_data_t *dir_data, const unsigned long int first_cluster)
{
  const struct exfat_dir_struct *ls=(const struct exfat_dir_struct*)dir_data->private_dir_data;
  const struct exfat_super_block*exfat_header=ls->boot_sector;
  const unsigned int cluster_shift=exfat_header->block_per_clus_bits + exfat_header->blocksize_bits;
  file_data_t *dir_list=NULL;
  unsigned int cluster;
  unsigned char *buffer_dir=(unsigned char *)MALLOC(NBR_CLUSTER_MAX << cluster_shift);
  unsigned int nbr_cluster;
  unsigned int clus_blocknr;
  unsigned int total_clusters;
  unsigned int exfat_meth=exFAT_FOLLOW_CLUSTER;
  int stop=0;
  if(first_cluster<2)
    cluster=le32(exfat_header->rootdir_clusnr);
  else
    cluster=first_cluster;
  memset(buffer_dir, 0, NBR_CLUSTER_MAX<<cluster_shift);
  clus_blocknr=le32(exfat_header->clus_blocknr);
  total_clusters=le32(exfat_header->total_clusters);
  nbr_cluster=0;
  while(!is_EOC(cluster) && cluster>=2 && nbr_cluster<NBR_CLUSTER_MAX && stop==0)
  {
    if(exfat_read_cluster(disk, partition, exfat_header, buffer_dir + (uint64_t) (nbr_cluster<< cluster_shift), cluster) != (1<<cluster_shift))
    {
      log_error("exFAT: Can't read directory cluster.\n");
      stop=1;
    }
    if(stop==0)
    {
      if(exfat_meth==exFAT_FOLLOW_CLUSTER)
      {
//	const unsigned int next_cluster=get_next_cluster(disk, partition, partition->upart_type, start_exfat1, cluster);
	const unsigned int next_cluster=0;
	if((next_cluster>=2 && next_cluster<=total_clusters) ||
	    is_EOC(next_cluster))
	  cluster=next_cluster;
	else if(next_cluster==0)
	{
#if 0
	  /* FIXME: experimental */
	  if(cluster==first_cluster && (dir_data->param & FLAG_LIST_DELETED)==FLAG_LIST_DELETED)
	    exfat_meth=exFAT_NEXT_FREE_CLUSTER;	/* Recovery of a deleted directory */
	  else
	    cluster=0;			/* Stop directory listing */
#else
	  cluster=0;			/* Stop directory listing */
#endif
	}
	else
	  exfat_meth=exFAT_NEXT_CLUSTER;		/* exFAT is corrupted, don't trust it */
      }
      if(exfat_meth==exFAT_NEXT_CLUSTER)
	cluster++;
      else if(exfat_meth==exFAT_NEXT_FREE_CLUSTER)
      {	/* Deleted directories are composed of "free" clusters */
#if 0
	while(++cluster<total_clusters &&
	    get_next_cluster(disk, partition, partition->upart_type, start_exfat1, cluster)!=0);
#endif
      }
      nbr_cluster++;
    }
  }
  if(nbr_cluster>0)
    dir_list=dir_exfat_aux(buffer_dir, nbr_cluster<<cluster_shift, dir_data->param);
  free(buffer_dir);
  return dir_list;
}

int dir_partition_exfat_init(disk_t *disk, const partition_t *partition, dir_data_t *dir_data, const int verbose)
{
  static struct exfat_dir_struct *ls;
  struct exfat_super_block *exfat_header;
  set_secwest();
  /* Load boot sector */
  exfat_header=(struct exfat_super_block *)MALLOC(0x200);
  if(disk->pread(disk, exfat_header, 0x200, partition->part_offset) != 0x200)
  {
    log_error("Can't read exFAT boot sector.\n");
    free(exfat_header);
    return -1;
  }
  if(le16(exfat_header->signature)!=0xAA55 ||
      memcmp(exfat_header->oem_id, "EXFAT   ", sizeof(exfat_header->oem_id))!=0)
  {
    log_error("Not an exFAT boot sector.\n");
    free(exfat_header);
    return -1;
  }
  ls=(struct exfat_dir_struct *)MALLOC(sizeof(*ls));
  ls->boot_sector=exfat_header;
#ifdef HAVE_ICONV
  if ((ls->cd = iconv_open("UTF-8", "UTF-16LE")) == (iconv_t)(-1))
  {
    log_error("dir_partition_exfat_init: iconv_open failed\n");
  }
#endif
  strncpy(dir_data->current_directory,"/",sizeof(dir_data->current_directory));
  dir_data->current_inode=0;
  dir_data->param=FLAG_LIST_DELETED;
  dir_data->verbose=verbose;
  dir_data->capabilities=CAPA_LIST_DELETED;
  dir_data->copy_file=exfat_copy;
  dir_data->close=dir_partition_exfat_close;
  dir_data->local_dir=NULL;
  dir_data->private_dir_data=ls;
  dir_data->get_dir=exfat_dir;
  return 0;
}

static void dir_partition_exfat_close(dir_data_t *dir_data)
{
  struct exfat_dir_struct *ls=(struct exfat_dir_struct*)dir_data->private_dir_data;
  free(ls->boot_sector);
#ifdef HAVE_ICONV
  if (ls->cd != (iconv_t)(-1))
    iconv_close(ls->cd);
#endif
  free(ls);
}

static int exfat_copy(disk_t *disk, const partition_t *partition, dir_data_t *dir_data, const file_data_t *file)
{
  char *new_file;	
  FILE *f_out;
  const struct exfat_dir_struct *ls=(const struct exfat_dir_struct*)dir_data->private_dir_data;
  const struct exfat_super_block *exfat_header=ls->boot_sector;
  const unsigned int cluster_shift=exfat_header->block_per_clus_bits + exfat_header->blocksize_bits;
  unsigned char *buffer_file=(unsigned char *)MALLOC(1<<cluster_shift);
  unsigned int cluster;
#ifdef DJGPP
  unsigned int file_size=file->file_size;
#else
  unsigned int file_size=file->stat.st_size;
#endif
  unsigned int exfat_meth=exFAT_FOLLOW_CLUSTER;
  uint64_t start_exfat1,clus_blocknr;
  unsigned long int total_clusters;
  f_out=fopen_local(&new_file, dir_data->local_dir, dir_data->current_directory);
  if(!f_out)
  {
    log_critical("Can't create file %s: \n",new_file);
    free(new_file);
    free(buffer_file);
    return -1;
  }
  cluster = file->stat.st_ino;
  start_exfat1=le32(exfat_header->fat_blocknr) << exfat_header->blocksize_bits;
  clus_blocknr=le32(exfat_header->clus_blocknr);
  total_clusters=le32(exfat_header->total_clusters);
  log_trace("exfat_copy dst=%s first_cluster=%u (%llu) size=%lu\n", new_file,
      cluster,
      (long long unsigned)(((cluster-2) << exfat_header->block_per_clus_bits) + clus_blocknr),
      (long unsigned)file_size);

  while(cluster>=2 && cluster<=total_clusters && file_size>0)
  {
    unsigned int toread = 1 << cluster_shift;
    if (toread > file_size)
      toread = file_size;
    if((unsigned)exfat_read_cluster(disk, partition, exfat_header, buffer_file, cluster) < toread)
    {
      log_error("exfat_copy: Can't read cluster %u.\n", cluster);
    }
    if(fwrite(buffer_file, 1, toread, f_out) != toread)
    {
      log_error("exfat_copy: no space left on destination.\n");
      fclose(f_out);
      set_date(new_file, file->stat.st_atime, file->stat.st_mtime);
      free(new_file);
      free(buffer_file);
      return -1;
    }
    file_size -= toread;
    if(file_size>0)
    {
      if(exfat_meth==exFAT_FOLLOW_CLUSTER)
      {
	const unsigned int next_cluster=get_next_cluster(disk, partition, UP_FAT32, start_exfat1, cluster);
	if(next_cluster>=2 && next_cluster<=total_clusters)
	  cluster=next_cluster;
	else if(cluster==file->stat.st_ino && next_cluster==0)
	  exfat_meth=exFAT_NEXT_FREE_CLUSTER;	/* Recovery of a deleted file */
	else
	  exfat_meth=exFAT_NEXT_CLUSTER;		/* exFAT is corrupted, don't trust it */
      }
      if(exfat_meth==exFAT_NEXT_CLUSTER)
	cluster++;
      else if(exfat_meth==exFAT_NEXT_FREE_CLUSTER)
      {	/* Deleted file are composed of "free" clusters */
	while(++cluster<total_clusters &&
	    get_next_cluster(disk, partition, partition->upart_type, start_exfat1, cluster)!=0);
      }
    }
  }
  fclose(f_out);
  set_date(new_file, file->stat.st_atime, file->stat.st_mtime);
  free(new_file);
  free(buffer_file);
  return 0;
}
