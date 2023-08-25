/*

    File: ext2_dir.c

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

#if defined(DISABLED_FOR_FRAMAC)
#undef HAVE_LIBEXT2FS
#endif

#include <stdio.h>
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#if defined(HAVE_LIBEXT2FS)
#ifdef HAVE_EXT2FS_EXT2_FS_H
#include "ext2fs/ext2_fs.h"
#endif
#ifdef HAVE_EXT2FS_EXT2FS_H
#include "ext2fs/ext2fs.h"
#endif
#endif

#include "types.h"
#include "common.h"
#include "intrf.h"
#include "dir.h"
#include "ext2_dir.h"
#include "ext2_inc.h"
#include "log.h"
#include "setdate.h"

#if defined(HAVE_LIBEXT2FS)
#define DIRENT_DELETED_FILE	4
/*
 * list directory
 */

#define LONG_OPT	0x0001

/*
 * I/O Manager routine prototypes
 */
static errcode_t my_open(const char *dev, int flags, io_channel *channel);
static errcode_t my_close(io_channel channel);
static errcode_t my_set_blksize(io_channel channel, int blksize);
static errcode_t my_read_blk(io_channel channel, unsigned long block, int count, void *buf);
static errcode_t my_write_blk(io_channel channel, unsigned long block, int count, const void *buf);
static errcode_t my_flush(io_channel channel);
static errcode_t my_read_blk64(io_channel channel, unsigned long long block, int count, void *buf);
static errcode_t my_write_blk64(io_channel channel, unsigned long long block, int count, const void *buf);

static void dir_partition_ext2_close(dir_data_t *dir_data);
static copy_file_t ext2_copy(disk_t *disk_car, const partition_t *partition, dir_data_t *dir_data, const file_info_t *file);

static struct struct_io_manager my_struct_manager = {
        .magic = EXT2_ET_MAGIC_IO_MANAGER,
        .name ="TestDisk I/O Manager",
        .open = &my_open,
        .close = &my_close,
        .set_blksize = &my_set_blksize,
        .read_blk = &my_read_blk,
        .write_blk= &my_write_blk,
        .flush = &my_flush,
	.write_byte= NULL,
#ifdef HAVE_STRUCT_STRUCT_IO_MANAGER_SET_OPTION
	.set_option= NULL,
#endif
#ifdef HAVE_STRUCT_STRUCT_IO_MANAGER_READ_BLK64
	.read_blk64=&my_read_blk64,
#endif
#ifdef HAVE_STRUCT_STRUCT_IO_MANAGER_WRITE_BLK64
	.write_blk64=&my_write_blk64,
#endif
};

static io_channel shared_ioch=NULL;
/*
 * Macro taken from unix_io.c
 * For checking structure magic numbers...
 */

#define EXT2_CHECK_MAGIC(struct, code) \
          if ((struct)->magic != (code)) return (code)

/*
 * Allocate libext2fs structures associated with I/O manager
 */
static io_channel alloc_io_channel(const disk_t *disk_car,my_data_t *my_data)
{
  io_channel     ioch;
#ifdef DEBUG_EXT2
  log_info("alloc_io_channel start\n");
#endif
  ioch = (io_channel)MALLOC(sizeof(struct struct_io_channel));
  if (ioch==NULL)
    return NULL;
  memset(ioch, 0, sizeof(struct struct_io_channel));
  ioch->magic = EXT2_ET_MAGIC_IO_CHANNEL;
  ioch->manager = &my_struct_manager;
  ioch->name=strdup(my_data->partition->fsname);
  if (ioch->name==NULL) {
	  free(ioch);
	  return NULL;
  }
  ioch->private_data = my_data;
  ioch->block_size = 1024; /* The smallest ext2fs block size */
  ioch->read_error = 0;
  ioch->write_error = 0;
#ifdef DEBUG_EXT2
  log_info("alloc_io_channel end\n");
#endif
  return ioch;
}

static errcode_t my_open(const char *dev, int flags, io_channel *channel)
{
  *channel = shared_ioch;
#ifdef DEBUG_EXT2
  log_info("my_open %s done\n", dev);
#endif
  return 0;
}

static errcode_t my_close(io_channel channel)
{
  free(channel->private_data);
  free(channel->name);
  free(channel);
#ifdef DEBUG_EXT2
  log_info("my_close done\n");
#endif
  return 0;
}

static errcode_t my_set_blksize(io_channel channel, int blksize)
{
  channel->block_size = blksize;
#ifdef DEBUG_EXT2
  log_info("my_set_blksize done\n");
#endif
  return 0;
}

static errcode_t my_read_blk64(io_channel channel, unsigned long long block, int count, void *buf)
{
  ssize_t size;
  const my_data_t *my_data=(const my_data_t*)channel->private_data;
  EXT2_CHECK_MAGIC(channel, EXT2_ET_MAGIC_IO_CHANNEL);

  size = (count < 0) ? -count : count * channel->block_size;
#ifdef DEBUG_EXT2
  log_info("my_read_blk start size=%lu, offset=%lu name=%s, block=%lu, count=%d, buf=%p\n",
      (long unsigned)size, (unsigned long)(block*channel->block_size),
      my_data->partition->fsname, block, count, buf);
#endif
  if(my_data->disk_car->pread(my_data->disk_car, buf, size, my_data->partition->part_offset + (uint64_t)block * channel->block_size) != size)
    return 1;
#ifdef DEBUG_EXT2
  log_info("my_read_blk done\n");
#endif
  return 0;
}

static errcode_t my_read_blk(io_channel channel, unsigned long block, int count, void *buf)
{
  return my_read_blk64(channel, block, count, buf);
}

static errcode_t my_write_blk64(io_channel channel, unsigned long long block, int count, const void *buf)
{
  EXT2_CHECK_MAGIC(channel, EXT2_ET_MAGIC_IO_CHANNEL);
#if 1
  {
    const my_data_t *my_data=(const my_data_t*)channel;
    if(my_data->disk_car->pwrite(my_data->disk_car, buf, count * channel->block_size, my_data->partition->part_offset + (uint64_t)block * channel->block_size) != count * channel->block_size)
      return 1;
    return 0;
  }
#else
  return 1;
#endif
}

static errcode_t my_write_blk(io_channel channel, unsigned long block, int count, const void *buf)
{
  return my_write_blk64(channel, block, count, buf);
}

static errcode_t my_flush(io_channel channel)
{
  return 0;
}

static int list_dir_proc2(ext2_ino_t dir,
			 int    entry,
			 struct ext2_dir_entry *dirent,
			 int	offset,
			 int	blocksize,
			 char	*buf,
			 void	*privateinfo)
{
  struct ext2_inode	inode;
  ext2_ino_t		ino;
  const struct ext2_dir_struct *ls = (const struct ext2_dir_struct *) privateinfo;
  file_info_t *new_file;
  errcode_t retval;
  if(entry==DIRENT_DELETED_FILE && (ls->dir_data->param & FLAG_LIST_DELETED)==0)
    return 0;
  ino = dirent->inode;
  if(ino==0)
    return 0;
  if ((retval=ext2fs_read_inode(ls->current_fs,ino, &inode))!=0)
  {
    log_error("ext2fs_read_inode(ino=%u) failed with error %ld.\n",(unsigned)ino, (long)retval);
    return 0;
  }
  if(inode.i_mode==0)
    return 0;
  new_file=(file_info_t *)MALLOC(sizeof(*new_file));
  {
    const unsigned int thislen = ((dirent->name_len & 0xFF) < EXT2_NAME_LEN) ?
      (dirent->name_len & 0xFF) : EXT2_NAME_LEN;
    new_file->name=(char *)MALLOC(thislen+1);
    memcpy(new_file->name, dirent->name, thislen);
    new_file->name[thislen] = '\0';
  }
  if(entry==DIRENT_DELETED_FILE)
    new_file->status=FILE_STATUS_DELETED;
  else
    new_file->status=0;
  new_file->st_ino=ino;
  new_file->st_mode=inode.i_mode;
//  new_file->st_nlink=inode.i_links_count;
  new_file->st_uid=inode.i_uid;
  new_file->st_gid=inode.i_gid;
  new_file->st_size=LINUX_S_ISDIR(inode.i_mode)?inode.i_size:
    inode.i_size| ((uint64_t)inode.i_size_high << 32);
//  new_file->st_blksize=blocksize;
//  new_file->st_blocks=inode.i_blocks;
  new_file->td_atime=inode.i_atime;
  new_file->td_mtime=inode.i_mtime;
  new_file->td_ctime=inode.i_ctime;
  td_list_add_tail(&new_file->list, &ls->dir_list->list);
  return 0;
}

static int ext2_dir(disk_t *disk_car, const partition_t *partition, dir_data_t *dir_data, const unsigned long int cluster, file_info_t *dir_list)
{
  errcode_t       retval;
  struct ext2_dir_struct *ls=(struct ext2_dir_struct*)dir_data->private_dir_data;
  ls->dir_list=dir_list;
  if((retval=ext2fs_dir_iterate2(ls->current_fs, cluster, ls->flags, 0, list_dir_proc2, ls))!=0)
  {
    log_error("ext2fs_dir_iterate failed with error %ld.\n",(long)retval);
    return -1;
  }
  return 0;
}

static void dir_partition_ext2_close(dir_data_t *dir_data)
{
  struct ext2_dir_struct *ls=(struct ext2_dir_struct *)dir_data->private_dir_data;
  ext2fs_close (ls->current_fs);
  /* ext2fs_close call the close function that freed my_data */
  free(ls);
}

static copy_file_t ext2_copy(disk_t *disk_car, const partition_t *partition, dir_data_t *dir_data, const file_info_t *file)
{
  copy_file_t error=CP_OK;
  FILE *f_out;
  const struct ext2_dir_struct *ls = (const struct ext2_dir_struct *)dir_data->private_dir_data;
  char *new_file;
  f_out=fopen_local(&new_file, dir_data->local_dir, dir_data->current_directory);
  if(!f_out)
  {
    log_critical("Can't create file %s: %s\n", new_file, strerror(errno));
    free(new_file);
    return CP_CREATE_FAILED;
  }
  {
    errcode_t retval;
    struct ext2_inode       inode;
    char            buffer[8192];
    ext2_file_t     e2_file;

    if (ext2fs_read_inode(ls->current_fs, file->st_ino, &inode)!=0)
    {
      free(new_file);
      fclose(f_out);
      return CP_STAT_FAILED;
    }

    retval = ext2fs_file_open(ls->current_fs, file->st_ino, 0, &e2_file);
    if (retval) {
      log_error("Error while opening ext2 file %s\n", dir_data->current_directory);
      free(new_file);
      fclose(f_out);
      return CP_OPEN_FAILED;
    }
    while (error!=CP_NOSPACE)
    {
      int             nbytes; 
      unsigned int    got;
      retval = ext2fs_file_read(e2_file, buffer, sizeof(buffer), &got);
      if (retval)
      {
	log_error("Error while reading ext2 file %s\n", dir_data->current_directory);
	error = CP_READ_FAILED;
      }
      if (got == 0)
	break;
      nbytes = fwrite(buffer, 1, got, f_out);
      if ((unsigned) nbytes != got)
      {
	log_error("Error while writing file %s\n", new_file);
	error = CP_NOSPACE;
      }
    }
    retval = ext2fs_file_close(e2_file);
    if (retval)
    {
      log_error("Error while closing ext2 file\n");
      error = CP_CLOSE_FAILED;
    }
    fclose(f_out);
    set_date(new_file, file->td_atime, file->td_mtime);
    (void)set_mode(new_file, file->st_mode);
  }
  free(new_file);
  return error;
}
#endif

dir_partition_t dir_partition_ext2_init(disk_t *disk_car, const partition_t *partition, dir_data_t *dir_data, const int verbose)
{
#if defined(HAVE_LIBEXT2FS)
  struct ext2_dir_struct *ls=(struct ext2_dir_struct *)MALLOC(sizeof(*ls));
  io_channel ioch;
  my_data_t *my_data;
  ls->dir_list=NULL;
  /*  ls->flags = DIRENT_FLAG_INCLUDE_EMPTY; */
  ls->flags = DIRENT_FLAG_INCLUDE_REMOVED;
  ls->dir_data=dir_data;
  my_data=(my_data_t *)MALLOC(sizeof(*my_data));
  my_data->partition=partition;
  my_data->disk_car=disk_car;
  ioch=alloc_io_channel(disk_car,my_data);
  shared_ioch=ioch;
  /* An alternate superblock may be used if the calling function has set an IO redirection */
  if(ext2fs_open ("/dev/testdisk", 0, 0, 0, &my_struct_manager, &ls->current_fs)!=0)
  {
//    free(my_data);
    free(ls);
    return DIR_PART_EIO;
  }
  strncpy(dir_data->current_directory,"/",sizeof(dir_data->current_directory));
  dir_data->current_inode=EXT2_ROOT_INO;
  dir_data->param=FLAG_LIST_DELETED;
  dir_data->verbose=verbose;
  dir_data->capabilities=CAPA_LIST_DELETED;
  dir_data->get_dir=&ext2_dir;
  dir_data->copy_file=&ext2_copy;
  dir_data->close=&dir_partition_ext2_close;
  dir_data->local_dir=NULL;
  dir_data->private_dir_data=ls;
  return DIR_PART_OK;
#else
  return DIR_PART_ENOSYS;
#endif
}

const char*td_ext2fs_version(void)
{
  const char *ext2fs_version="none";
#if defined(HAVE_LIBEXT2FS)
  ext2fs_get_library_version(&ext2fs_version,NULL);
#endif
  return ext2fs_version;
}
