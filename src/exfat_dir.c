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
#include <errno.h>
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

#define EXFAT_MKMODE(a,m) ((m & ((a & ATTR_RO) ? LINUX_S_IRUGO|LINUX_S_IXUGO : LINUX_S_IRWXUGO)) | ((a & ATTR_DIR) ? LINUX_S_IFDIR : LINUX_S_IFREG))
struct exfat_dir_struct
{
  struct exfat_super_block*boot_sector;
#ifdef HAVE_ICONV
  iconv_t cd;
#endif
};


static int exfat_dir(disk_t *disk, const partition_t *partition, dir_data_t *dir_data, const unsigned long int first_cluster, file_info_t *dir_list);
static copy_file_t exfat_copy(disk_t *disk, const partition_t *partition, dir_data_t *dir_data, const file_info_t *file);
static void dir_partition_exfat_close(dir_data_t *dir_data);

#if 0
static inline void exfat16_towchar(wchar_t *dst, const uint8_t *src, size_t len)
{
	while (len--) {
		*dst++ = src[0] | (src[1] << 8);
		src += 2;
	}
}
#endif

#ifdef HAVE_ICONV
static int exfat_ucstoutf8(iconv_t cd, const unsigned char *ins, const unsigned int ins_len, char **outs, const unsigned int outs_len)
{
  const char *inp;
  char *outp;
  size_t inb_left, outb_left;
  if (cd == (iconv_t)(-1))
    return -1;

  outp = *outs;
  inp = (const char *)ins;
  inb_left = ins_len;
  outb_left = outs_len - 1;   // reserve 1 byte for NUL

  if (iconv(cd, (char **)&inp, &inb_left, &outp, &outb_left) == (size_t)(-1))
  {
    // Regardless of the value of errno
    log_error("exfat_ucstoutf8: iconv failed %s\n", strerror(errno));
    return -1;
  }
  *outp = '\0';
  return 0;
}
#else
/*
 *              Convert a UTF-16LE text to UTF-8
 *      Note : wcstombs() not used because on Linux it fails for characters
 *      not present in current locale
 *      Returns size or zero for invalid input
 */

static unsigned int makeutf8(char *utf8, const char *utf16, int length)
{
        int i;
        unsigned int size;
        unsigned int rem;
        enum { BASE, SURR, ERR } state;

        size = 0;
        rem = 0;
        state = BASE;
        for (i=0; i<2*length; i+=2) {
                switch (state) {
                case BASE :
                        if (utf16[i+1] & 0xf8) {
                                if ((utf16[i+1] & 0xf8) == 0xd8) {
                                        if (utf16[i+1] & 4)
                                                state = ERR;
                                        else {
                                                utf8[size++] = 0xf0 + (utf16[i+1] & 7)
                                                                    + ((utf16[i] & 0xc0) == 0xc0);
                                                utf8[size++] = 0x80 + (((utf16[i] + 64) >> 2) & 63);
                                                rem = utf16[i] & 3;
                                                state = SURR;
                                        }
                                } else {
                                        utf8[size++] = 0xe0 + ((utf16[i+1] >> 4) & 15);
                                        utf8[size++] = 0x80
                                                + ((utf16[i+1] & 15) << 2)
                                                + ((utf16[i] >> 6) & 3);
                                        utf8[size++] = 0x80 + (utf16[i] & 63);
                                }
                        } else
                                if ((utf16[i] & 0x80) || utf16[i+1]) {
                                        utf8[size++] = 0xc0
                                                + ((utf16[i+1] & 15) << 2)
                                                + ((utf16[i] >> 6) & 3);
                                        utf8[size++] = 0x80 + (utf16[i] & 63);
                                } else
                                        utf8[size++] = utf16[i];
                        break;
                case SURR :
                        if ((utf16[i+1] & 0xfc) == 0xdc) {
                                utf8[size++] = 0x80 + (rem << 4)
                                                 + ((utf16[i+1] & 3) << 2)
                                                 + ((utf16[i] >> 6) & 3);
                                utf8[size++] = 0x80 + (utf16[i] & 63);
                                state = BASE;
                        } else
                                state = ERR;
                        break;
                case ERR :
                        break;
                }
        }
        utf8[size] = 0;
        if (state != BASE)
                state = ERR;
        return (state == ERR ? 0 : size);
}
#endif

#define ATTR_RO      1  /* read-only */
#define ATTR_HIDDEN  2  /* hidden */
#define ATTR_SYS     4  /* system */
#define ATTR_DIR     16 /* directory */
#define ATTR_ARCH    32 /* archived */

static unsigned int exfat_get_next_cluster(disk_t *disk_car,const partition_t *partition, const uint64_t offset, const unsigned int cluster)
{
  unsigned char *buffer=(unsigned char*)MALLOC(disk_car->sector_size);
  unsigned int next_cluster;
  const uint32_t *p32=(const uint32_t*)buffer;
  const uint64_t offset_s=cluster / (disk_car->sector_size/4);
  const uint64_t offset_o=cluster % (disk_car->sector_size/4);
  if((unsigned)disk_car->pread(disk_car, buffer, disk_car->sector_size,
	partition->part_offset + offset + offset_s * disk_car->sector_size) != disk_car->sector_size)
  {
    log_error("exfat_get_next_cluster read error\n");
    free(buffer);
    return 0;
  }
  /* 0x00000000: free cluster
   * 0xFFFFFFF7: bad cluster
   * 0xFFFFFFFF: EOC End of cluster
   * */
  next_cluster=le32(p32[offset_o]);
  free(buffer);
  return next_cluster;
}

static int dir_exfat_aux(const unsigned char*buffer, const unsigned int size, const dir_data_t *dir_data, file_info_t *dir_list)
{
#ifdef HAVE_ICONV
  const struct exfat_dir_struct *ls=(const struct exfat_dir_struct*)dir_data->private_dir_data;
#endif
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
  file_info_t *current_file=NULL;
  unsigned int offset=0;
  unsigned int sec_count=0;
  for(offset=0; offset<size; offset+=0x20)
  {
    if((buffer[offset]&0x80)==0 &&
	(dir_data->param & FLAG_LIST_DELETED)!=FLAG_LIST_DELETED)
      continue;
    if((buffer[offset]&0x7f)==0x05)
    { /* File directory entry */
      const struct exfat_file_entry *entry=(const struct exfat_file_entry *)&buffer[offset];
      file_info_t *new_file=(file_info_t *)MALLOC(sizeof(*new_file));
      sec_count=entry->sec_count;
      new_file->name=(char *)MALLOC(512);
      new_file->name[0]=0;
      new_file->st_ino=0;
      new_file->st_mode = EXFAT_MKMODE(entry->attr,(LINUX_S_IRWXUGO & ~(LINUX_S_IWGRP|LINUX_S_IWOTH)));
      new_file->st_uid=0;
      new_file->st_gid=0;
      new_file->st_size=0;
      new_file->td_atime=date_dos2unix(le16(entry->atime),le16(entry->adate));
      new_file->td_ctime=date_dos2unix(le16(entry->ctime),le16(entry->cdate));
      new_file->td_mtime=date_dos2unix(le16(entry->mtime),le16(entry->mdate));
      new_file->status=((entry->type&0x80)==0x80?0:FILE_STATUS_DELETED);
      current_file=new_file;
      td_list_add_tail(&new_file->list, &dir_list->list);
    }
    else if(sec_count>0 && current_file!=NULL)
    {
      if((buffer[offset]&0x7f)==0x40)
      {
	/* Stream extension */
	const struct exfat_stream_ext_entry *entry=(const struct exfat_stream_ext_entry*)&buffer[offset];
	current_file->st_size=le64(entry->data_length);
	current_file->st_ino=le32(entry->first_cluster);
#if 0
	if((entry->first_cluster&2)!=0)
	  current_file->st_size=0;
#endif
      }
      else if((buffer[offset]&0x7f)==0x41)
      {
	char *outs;
	unsigned int i;
	unsigned int j;
	for(j=0;
	    j<255 && current_file->name[j]!='\0';
	    j++);
	for(i=2;
	    i<32 && (buffer[offset+i]!=0 || buffer[offset+i+1]!=0);
	    i+=2);
	i-=2;
	outs=&current_file->name[j];
#ifdef HAVE_ICONV
	if(exfat_ucstoutf8(ls->cd, &buffer[offset+2], i, &outs, 512-j) < 0)
	{
	  for(i=2; i<32; i+=2)
	    current_file->name[j++]=buffer[offset+i];
	  current_file->name[j]='\0';
	}
#else
	makeutf8(outs, &buffer[offset+2], i);
#endif
      }
      sec_count--;
    }
  }
  return 0;
}

typedef enum {exFAT_FOLLOW_CLUSTER, exFAT_NEXT_FREE_CLUSTER, exFAT_NEXT_CLUSTER} exfat_method_t;

static int is_EOC(const unsigned int cluster)
{
  return(cluster==0xFFFFFFFF);
}

#define NBR_CLUSTER_MAX 30
static int exfat_dir(disk_t *disk, const partition_t *partition, dir_data_t *dir_data, const unsigned long int first_cluster, file_info_t *dir_list)
{
  const struct exfat_dir_struct *ls=(const struct exfat_dir_struct*)dir_data->private_dir_data;
  const struct exfat_super_block*exfat_header=ls->boot_sector;
  const unsigned int cluster_shift=exfat_header->block_per_clus_bits + exfat_header->blocksize_bits;
  unsigned int cluster;
  unsigned char *buffer_dir=(unsigned char *)MALLOC(NBR_CLUSTER_MAX << cluster_shift);
  unsigned int nbr_cluster;
  const unsigned int total_clusters=le32(exfat_header->total_clusters);
  exfat_method_t exfat_meth=exFAT_FOLLOW_CLUSTER;
  int stop=0;
  const uint64_t start_exfat1=(uint64_t)le32(exfat_header->fat_blocknr) << exfat_header->blocksize_bits;
  if(first_cluster<2)
    cluster=le32(exfat_header->rootdir_clusnr);
  else
    cluster=first_cluster;
  memset(buffer_dir, 0, NBR_CLUSTER_MAX<<cluster_shift);
  nbr_cluster=0;
  while(!is_EOC(cluster) && cluster>=2 && nbr_cluster<NBR_CLUSTER_MAX && stop==0)
  {
    if(exfat_read_cluster(disk, partition, exfat_header, buffer_dir + ((uint64_t) nbr_cluster << cluster_shift), cluster) != (1<<cluster_shift))
    {
      log_error("exFAT: Can't read directory cluster.\n");
      stop=1;
    }
    if(stop==0)
    {
      if(exfat_meth==exFAT_FOLLOW_CLUSTER)
      {
	const unsigned int next_cluster=exfat_get_next_cluster(disk, partition, start_exfat1, cluster);
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
	    exfat_get_next_cluster(disk, partition, start_exfat1, cluster)!=0);
#endif
      }
      nbr_cluster++;
    }
  }
  if(nbr_cluster>0)
    dir_exfat_aux(buffer_dir, nbr_cluster<<cluster_shift, dir_data, dir_list);
  free(buffer_dir);
  return 0;
}

dir_partition_t dir_partition_exfat_init(disk_t *disk, const partition_t *partition, dir_data_t *dir_data, const int verbose)
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
    return DIR_PART_EIO;
  }
  if(le16(exfat_header->signature)!=0xAA55 ||
      memcmp(exfat_header->oem_id, "EXFAT   ", sizeof(exfat_header->oem_id))!=0)
  {
    log_error("Not an exFAT boot sector.\n");
    free(exfat_header);
    return DIR_PART_EIO;
  }
  ls=(struct exfat_dir_struct *)MALLOC(sizeof(*ls));
  ls->boot_sector=exfat_header;
#ifdef HAVE_ICONV
  if ((ls->cd = iconv_open("UTF-8", "UTF-16LE")) == (iconv_t)(-1))
  {
    log_error("dir_partition_exfat_init: iconv_open failed\n");
  }
#endif
#ifdef DEBUG_EXFAT
  log_info("start_sector=%llu\n", (long long unsigned)le64(exfat_header->start_sector));
  log_info("nr_sectors  =%llu\n", (long long unsigned)le64(exfat_header->nr_sectors));
  log_info("fat_blocknr =%u\n",le32(exfat_header->fat_blocknr));
  log_info("fat_block_counts=%u\n", le32(exfat_header->fat_block_counts));
  log_info("clus_blocknr=%u\n",	le32(exfat_header->clus_blocknr));
  log_info("total_clusters=%u\n",	le32(exfat_header->total_clusters));
  log_info("rootdir_clusnr=%u\n",	le32(exfat_header->rootdir_clusnr));
  log_info("serial_number=0x%08x\n", le32(exfat_header->serial_number));
  log_info("state=0x%x\n",	le16(exfat_header->state));
  log_info("blocksize_bits=%u\n",	exfat_header->blocksize_bits);
  log_info("block_per_clus_bits=%u\n",	exfat_header->block_per_clus_bits);
  log_info("number_of_fats=%u\n",		exfat_header->number_of_fats);
  log_info("drive_select=0x%x\n",		exfat_header->drive_select);
  log_info("allocated_percent=%u\n",	exfat_header->allocated_percent);
#endif
  strncpy(dir_data->current_directory,"/",sizeof(dir_data->current_directory));
  dir_data->current_inode=0;
  dir_data->param=FLAG_LIST_DELETED;
  dir_data->verbose=verbose;
  dir_data->capabilities=CAPA_LIST_DELETED;
  dir_data->copy_file=&exfat_copy;
  dir_data->close=&dir_partition_exfat_close;
  dir_data->local_dir=NULL;
  dir_data->private_dir_data=ls;
  dir_data->get_dir=&exfat_dir;
  return DIR_PART_OK;
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

static copy_file_t exfat_copy(disk_t *disk, const partition_t *partition, dir_data_t *dir_data, const file_info_t *file)
{
  char *new_file;	
  FILE *f_out;
  const struct exfat_dir_struct *ls=(const struct exfat_dir_struct*)dir_data->private_dir_data;
  const struct exfat_super_block *exfat_header=ls->boot_sector;
  const unsigned int cluster_shift=exfat_header->block_per_clus_bits + exfat_header->blocksize_bits;
  unsigned char *buffer_file=(unsigned char *)MALLOC(1<<cluster_shift);
  unsigned int cluster;
  uint64_t file_size=file->st_size;
  exfat_method_t exfat_meth=exFAT_FOLLOW_CLUSTER;
  uint64_t start_exfat1;
  unsigned long int clus_blocknr;
  unsigned long int total_clusters;
  f_out=fopen_local(&new_file, dir_data->local_dir, dir_data->current_directory);
  if(!f_out)
  {
    log_critical("Can't create file %s: \n",new_file);
    free(new_file);
    free(buffer_file);
    return CP_CREATE_FAILED;
  }
  cluster = file->st_ino;
  start_exfat1=(uint64_t)le32(exfat_header->fat_blocknr) << exfat_header->blocksize_bits;
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
      set_date(new_file, file->td_atime, file->td_mtime);
      free(new_file);
      free(buffer_file);
      return CP_NOSPACE;
    }
    file_size -= toread;
    if(file_size>0)
    {
      if(exfat_meth==exFAT_FOLLOW_CLUSTER)
      {
	const unsigned int next_cluster=exfat_get_next_cluster(disk, partition, start_exfat1, cluster);
	if(next_cluster>=2 && next_cluster<=total_clusters)
	  cluster=next_cluster;
	else if(cluster==file->st_ino && next_cluster==0)
	  exfat_meth=exFAT_NEXT_FREE_CLUSTER;	/* Recovery of a deleted file */
	else
	  exfat_meth=exFAT_NEXT_CLUSTER;		/* exFAT is corrupted, don't trust it */
      }
      if(exfat_meth==exFAT_NEXT_CLUSTER)
	cluster++;
      else if(exfat_meth==exFAT_NEXT_FREE_CLUSTER)
      {	/* Deleted file are composed of "free" clusters */
	while(++cluster<total_clusters &&
	    exfat_get_next_cluster(disk, partition, start_exfat1, cluster)!=0);
      }
    }
  }
  fclose(f_out);
  set_date(new_file, file->td_atime, file->td_mtime);
  free(new_file);
  free(buffer_file);
  return CP_OK;
}
