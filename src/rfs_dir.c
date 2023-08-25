/*

    File: rfs_dir.c

    Copyright (C) 1998-2008 Christophe GRENIER <grenier@cgsecurity.org>
    Some code from Yury Umanets <torque@ukrpost.net>
  
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
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#include "types.h"
#include "common.h"
#include "intrf.h"
#include "rfs.h"
#include "dir.h"
#include "rfs_dir.h"
#include "log.h"
#include "setdate.h"

#ifdef HAVE_LIBREISERFS
#include "dal/dal.h"
#ifdef HAVE_DAL_FILE_DAL_H
#include "dal/file_dal.h"
#endif
#ifdef HAVE_DAL_FILE_H
#include "dal/file.h"
#endif
#include "reiserfs/reiserfs.h"

struct rfs_dir_struct {
	file_info_t *dir_list;
	reiserfs_fs_t *current_fs;
	dal_t *dal;
	int flags;
};
static int reiser_dir(disk_t *disk_car, const partition_t *partition, dir_data_t *dir_data, const unsigned long int cluster, file_info_t *dir_list);
static void dir_partition_reiser_close(dir_data_t *dir_data);

#ifdef HAVE_STRUCT_DAL_OPS_DEV
dev_t dal_dev(dal_t *dal) {
    
    if (!dal)
	return 0;
    return (dev_t)dal->dev;
}
#endif

#ifdef HAVE_STRUCT_DAL_OPS_DEV
size_t dal_block_size(dal_t *dal) {
    if (!dal) return 0;
#ifdef HAVE_DAL_T_BLOCK_SIZE
    return dal->block_size;
#else
    return dal->blocksize;
#endif
}
#else
unsigned dal_get_blocksize(dal_t *dal) {
  if (!dal)
    return 0;
#ifdef HAVE_DAL_T_BLOCK_SIZE
    return dal->block_size;
#else
    return dal->blocksize;
#endif
}
#endif

/*
size_t dal_blocksize(dal_t *dal) {

	if (!dal) return 0;
#ifdef HAVE_DAL_T_BLOCK_SIZE
    return dal->block_size;
#else
    return dal->blocksize;
#endif

}
*/

char *dal_error(dal_t *dal) {
#ifdef HAVE_DAL_T_ERROR
    return dal->error;
#else
    return "";
#endif
}

static int file_read(dal_t *dal, void *buff, blk_t block, blk_t count) {
  uint64_t off;
  unsigned int blocklen;
  my_data_t *my_data;
/* log_trace("reiser file_read(dal=%p,buff=%p,block=%ld, count=%ld)\n",dal,buff,block,count); */
  if (!dal || !buff)
    return 0;
  my_data=(my_data_t*)dal->data;
#ifdef HAVE_DAL_T_BLOCK_SIZE
  off = (uint64_t)block * (uint64_t)dal->block_size;
  blocklen = count * dal->block_size;
#else
  off = (uint64_t)block * (uint64_t)dal->blocksize;
  blocklen = count * dal->blocksize;
#endif
/* log_debug("blocklen=%ld\n",blocklen); */
  if(my_data->disk_car->pread(my_data->disk_car, buff, blocklen, my_data->partition->part_offset + off) != blocklen)
    return 0;
  return 1;
}

static int file_write(dal_t *dal, void *buff, blk_t block, blk_t count)
{
  if (!dal || !buff)
    return 0;
#ifdef ENABLE_REISERFS_WRITE
  {
    uint64_t off, blocklen;
#ifdef HAVE_DAL_T_BLOCK_SIZE
    off = (uint64_t)block * (uint64_t)dal->block_size;
    blocklen = (uint64_t)count * (uint64_t)dal->block_size;
#else
    off = (uint64_t)block * (uint64_t)dal->blocksize;
    blocklen = (uint64_t)count * (uint64_t)dal->blocksize;
#endif
    if(my_data->disk_car->pwrite(my_data->disk_car, buff, blocklen, my_data->partition->part_offset + off) != blocklen)
      return 0;
    return 1;
  }
#else
  log_info("reiser file_write not implemented\n");
  return 0;
#endif
}

static int file_sync(dal_t *dal)
{
  if (!dal) return 0;
/* log_trace("reiser file_sync\n"); */
  return 1;
}

static int file_flags(dal_t *dal)
{
/* log_trace("reiser file_flags\n"); */
  if (!dal) return 0;
  return dal->flags;
}

static int file_equals(dal_t *dal1, dal_t *dal2)
{
/* log_trace("reiser file_equals\n"); */
  if (!dal1 || !dal2)
    return 0;
/* return !strcmp((char *)dal1->data, (char *)dal2->data); */
  {
    my_data_t *data1=(my_data_t*)dal1->data;
    my_data_t *data2=(my_data_t*)dal2->data;
    return (data1->disk_car==data2->disk_car) && (data1->partition==data2->partition) && (data1->offset==data2->offset);
  }
}

#ifdef HAVE_STRUCT_DAL_OPS_DEV
static int file_stat(dal_t *dal,struct stat *st)
{
/* log_trace("reiser file_stat\n"); */
  if (!dal)
    return 0;
/* return (unsigned int)st.st_dev; */
  return 1;
}
#else
static unsigned int file_stat(dal_t *dal)
{
/* log_trace("reiser file_stat\n"); */
  if (!dal)
    return 0;
/* return (unsigned int)st.st_dev; */
  return 1;
}
#endif

#ifdef HAVE_STRUCT_DAL_OPS_DEV
static blk_t   file_len(dal_t *dal) {
#else
static count_t file_len(dal_t *dal) {
#endif
  my_data_t *my_data;
/* log_trace("reiser file_len\n"); */
  if (!dal) return 0;
  my_data=(my_data_t*)dal->data;
#ifdef HAVE_DAL_T_BLOCK_SIZE
  return my_data->partition->part_size / dal->block_size;
#else
  return my_data->partition->part_size / dal->blocksize;
#endif
}

static struct dal_ops ops = {
	read: file_read, 
	write: file_write, 
	sync: file_sync, 
	flags: file_flags, 
	equals: file_equals, 
	stat: file_stat, 
	len: file_len,
#ifdef HAVE_STRUCT_DAL_OPS_DEV
	dev: dal_dev
#endif
};

void dal_close(dal_t *dal) {
/* log_trace("reiser dal_close\n"); */
	
	if (!dal) return;
	
	dal->ops = NULL;
	free(dal->data);
	dal->data = NULL;
	free(dal);
}

void file_close(dal_t *dal) {
/* log_trace("reiser file_close\n"); */
	if (!dal) return;
	dal_close(dal);
}

static int power_of_two(unsigned long value) {
	return (value & -value) == value;
}

#ifdef HAVE_STRUCT_DAL_OPS_DEV
dal_t *dal_open(struct dal_ops *myops, const void *dev, size_t blocksize, int flags, void *data)
#else
dal_t *dal_open(struct dal_ops *myops, unsigned blocksize, int flags, void *data) 
#endif
{
	dal_t *dal;
/* log_trace("reiser dal_open\n"); */
	
	if (!myops) return NULL;
	
	if (!power_of_two(blocksize)) {
		fprintf(stderr, "Block size isn't power of two.\n");
		return NULL;
	}	
	
	if (!(dal = (dal_t *)MALLOC(sizeof(*dal))))
		return NULL;

	memset(dal, 0, sizeof(*dal));
	
	dal->ops = myops;
#ifdef HAVE_DAL_T_BLOCK_SIZE
	dal->block_size = blocksize;
#else
	dal->blocksize = blocksize;
#endif
#ifdef HAVE_DAL_T_ENTITY
	dal->entity= NULL;
#endif
#ifdef HAVE_DAL_T_NAME
	strncpy(dal->name, "/dev/reiserfs",sizeof(dal->name));
#endif
#ifdef HAVE_DAL_T_ERROR
	dal->error[0]=0;
#endif
	dal->data = data;
	dal->flags = flags;
	return dal;
}

#ifdef HAVE_STRUCT_DAL_OPS_DEV
int dal_set_block_size(dal_t *dal, size_t blocksize) {

	if (!dal) return 0;
	
	if (!power_of_two(blocksize))
		return 0;
#ifdef HAVE_DAL_T_BLOCK_SIZE
	dal->block_size = blocksize;
#else
	dal->blocksize = blocksize;
#endif
	return 1;
}
#else
int dal_set_blocksize(dal_t *dal, unsigned blocksize) {

	if (!dal) return 0;
	
	if (!power_of_two(blocksize))
		return 0;
#ifdef HAVE_DAL_T_BLOCK_SIZE
	dal->block_size = blocksize;
#else
	dal->blocksize = blocksize;
#endif

	return 1;
}
#endif


int dal_read(dal_t *dal, void *buff, blk_t block, blk_t count) {

/* log_trace("reiser dal_read\n"); */
	if (!dal) return 0;

	if (dal->ops->read)
		return dal->ops->read(dal, buff, block, count);
	
	return 0;
}

int dal_write(dal_t *dal, void *buff, blk_t block, blk_t count) {

/* log_trace("reiser dal_write\n"); */
	if (!dal) return 0;
	
	if (dal->ops->write)
		return dal->ops->write(dal, buff, block, count);
		
	return 0;
}
	
int dal_sync(dal_t *dal) {

	if (!dal) return 0;

	if (dal->ops->sync)
		return dal->ops->sync(dal);
	
	return 0;	
}

int dal_flags(dal_t *dal) {

	if (!dal) return 0;

	if (dal->ops->flags)
		return dal->ops->flags(dal);
	
	return 0;
}

int dal_equals(dal_t *dal1, dal_t *dal2) {
/* log_trace("reiserfs dal_equals\n"); */
	
	if (!dal1 || !dal2) return 0;

	if (dal1->ops->equals)
		return dal1->ops->equals(dal1, dal2);
	
	return 0;	
}

#if defined(HAVE_STRUCT_DAL_OPS_DEV)
int dal_stat(dal_t *dal, struct stat *mystat)
{
/* log_trace("reiserfs dal_stat\n"); */
	if (!dal) return 0;
	if (dal->ops->stat)
		return dal->ops->stat(dal,mystat);
	return 0;
}
#else
unsigned int dal_stat(dal_t *dal) {
/* log_trace("reiserfs dal_stat\n"); */
	if (!dal) return 0;
	if (dal->ops->stat)
		return dal->ops->stat(dal);
	return 0;
}
#endif

blk_t dal_len(dal_t *dal) {
/* log_trace("reiserfs dal_len\n"); */
	
	if (!dal) 
		return 0;

	if (dal->ops->len)
		return dal->ops->len(dal);

	return 0;
}

static int reiser_dir(disk_t *disk_car, const partition_t *partition, dir_data_t *dir_data, const unsigned long int cluster, file_info_t *dir_list)
{
  struct rfs_dir_struct *ls=(struct rfs_dir_struct*)dir_data->private_dir_data;
  reiserfs_dir_t *dir;
  reiserfs_dir_entry_t entry;
  ls->dir_list=dir_list;
  if (!(dir = reiserfs_dir_open(ls->current_fs, dir_data->current_directory))) {
    screen_buffer_add("Couldn't open dir\n");
    log_error("Couldn't open dir\n");
    return -1;
  }
  while (reiserfs_dir_read(dir, &entry))
  {
    char name[MAX_NAME_LEN(DEFAULT_BLOCK_SIZE)];
    reiserfs_object_t *entity;
    strncpy(name,dir_data->current_directory,sizeof(name));
    strcat(name,"/");
    strcat(name,entry.de_name);
    if((entity=reiserfs_object_create(ls->current_fs,name,1)))
    {
      unsigned int thislen;
      file_info_t *new_file=(file_info_t *)MALLOC(sizeof(*new_file));
      thislen=(MAX_NAME_LEN(DEFAULT_BLOCK_SIZE)<DIR_NAME_LEN?MAX_NAME_LEN(DEFAULT_BLOCK_SIZE):DIR_NAME_LEN);
      memcpy(new_file->name,entry.de_name,thislen);
      new_file->name[thislen-1]='\0';

      new_file->status=0;
      new_file->st_ino=entity->stat.st_ino;
      new_file->st_mode=entity->stat.st_mode;
//      new_file->st_nlink=entity->stat.st_nlink;
      new_file->st_uid=entity->stat.st_uid;
      new_file->st_gid=entity->stat.st_gid;
      new_file->st_size=entity->stat.st_size;
//      new_file->st_blksize=entity->stat.st_blksize;
      new_file->td_atime=entity->stat.st_atime;
      new_file->td_mtime=entity->stat.st_mtime;
      new_file->td_ctime=entity->stat.st_ctime;
      reiserfs_object_free(entity);
      td_list_add_tail(&new_file->list, &dir_list->list);
    }
  }
  reiserfs_dir_close(dir);
  return 0;
}

static void dir_partition_reiser_close(dir_data_t *dir_data)
{
  struct rfs_dir_struct *ls=(struct rfs_dir_struct*)dir_data->private_dir_data;
  reiserfs_fs_close(ls->current_fs);
  file_close(ls->dal);
  free(ls);
}

static copy_file_t reiser_copy(disk_t *disk_car, const partition_t *partition, dir_data_t *dir_data, const file_info_t *file)
{
  reiserfs_file_t *in;
  FILE *f_out;
  char *new_file;
  struct rfs_dir_struct *ls=(struct rfs_dir_struct*)dir_data->private_dir_data;
  copy_file_t error=CP_OK;
  uint64_t file_size;
  f_out=fopen_local(&new_file, dir_data->local_dir, dir_data->current_directory);
  if(!f_out)
  {
    log_critical("Can't create file %s: %s\n", new_file, strerror(errno));
    free(new_file);
    return CP_CREATE_FAILED;
  }
  log_error("Try to open rfs file %s\n", dir_data->current_directory);
  log_flush();
  in=reiserfs_file_open(ls->current_fs, dir_data->current_directory, O_RDONLY);
  if (in==NULL)
  {
    log_error("Error while opening rfs file %s\n", dir_data->current_directory);
    free(new_file);
    fclose(f_out);
    return CP_OPEN_FAILED;
  }
  log_error("open rfs file %s done\n", dir_data->current_directory);
  log_flush();
  file_size = reiserfs_file_size(in);
#if 0
  /* TODO: do not use so much memory */
  {
    void *buf=MALLOC(file_size+1);
    if (reiserfs_file_read(in, buf, file_size) != file_size)
    {
      log_error("Error while reading rfs file %s\n", dir_data->current_directory);
      error = CP_READ_FAILED;
    }
    else if (fwrite(buf, file_size, 1, f_out) != 1)
    {
      log_error("Error while writing file %s\n", new_file);
      error = CP_NOSPACE;
    }
    free(buf);
  }
#else
  {
    /* require progsreiserfs-file-read.patch */
    char buf[4096];
    while(file_size > 0)
    {
      int read_size=(file_size < sizeof(buf) ? file_size : sizeof(buf));
      if (reiserfs_file_read(in, buf, read_size) == 0)
      {
	log_error("Error while reading rfs file %s\n", dir_data->current_directory);
	error = CP_READ_FAILED;
      }
      else if (fwrite(buf, read_size, 1, f_out) != 1)
      {
	log_error("Error while writing file %s\n", new_file);
	error = CP_NOSPACE;
      }
      file_size -= read_size;
    }
  }
#endif
  reiserfs_file_close(in);
  fclose(f_out);
  set_date(new_file, file->td_atime, file->td_mtime);
  (void)set_mode(new_file, file->st_mode);
  free(new_file);
  return error;
}
#endif

dir_partition_t dir_partition_reiser_init(disk_t *disk_car, const partition_t *partition, dir_data_t *dir_data, const int verbose)
{
#ifdef HAVE_LIBREISERFS
  dal_t *dal;
  reiserfs_fs_t *fs;
  my_data_t *my_data;
  my_data=(my_data_t *)MALLOC(sizeof(*my_data));
  my_data->partition=partition;
  my_data->disk_car=disk_car;
  my_data->offset=0;
#ifdef HAVE_STRUCT_DAL_OPS_DEV
  dal=dal_open(&ops, "",DEFAULT_BLOCK_SIZE, O_RDONLY, my_data);
#else
  dal=dal_open(&ops, DEFAULT_BLOCK_SIZE, O_RDONLY, my_data);
#endif
  if (!dal)
  {
    log_error("Couldn't open device\n");
    free(my_data);
    return DIR_PART_EIO;
  }
  /* log_debug("file_open ok\n"); */

#ifdef HAVE_REISERFS_FS_OPEN_FAST
  if (!(fs = reiserfs_fs_open_fast(dal, dal)))
#else
    if (!(fs = reiserfs_fs_open(dal, dal)))
#endif
    {
      log_error("Couldn't open reiser filesystem %s\n",dal_error(dal));
      /* file_close call free(my_data) */
      file_close(dal);
      return DIR_PART_EIO;
    }
  /* log_debug("reiserfs_fs_open_fast ok\n"); */
  {
    struct rfs_dir_struct *ls=(struct rfs_dir_struct *)MALLOC(sizeof(*ls));
    ls->dir_list=NULL;
    ls->current_fs=fs;
    ls->dal=dal;
    ls->flags = 0; /*DIRENT_FLAG_INCLUDE_EMPTY; */
    strncpy(dir_data->current_directory,"/",sizeof(dir_data->current_directory));
    dir_data->current_inode=2;
    dir_data->param=0;
    dir_data->verbose=verbose;
    dir_data->capabilities=0;
    dir_data->get_dir=reiser_dir;
    dir_data->copy_file=reiser_copy;
    dir_data->close=&dir_partition_reiser_close;
    dir_data->local_dir=NULL;
    dir_data->private_dir_data=ls;
  }
  return DIR_PART_OK;
#else
  return DIR_PART_ENOSYS;
#endif
}

const char*td_reiserfs_version(void)
{
#ifdef HAVE_LIBREISERFS
  return libreiserfs_get_version();
#else
  return "none";
#endif
}
