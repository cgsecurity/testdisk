/**
 * ntfs_dir.c - Part of the TestDisk project.
 *
 * Copyright (c) 2004-2008 Christophe Grenier
 *
 * Original version comes from the Linux-NTFS project.
 * Copyright (c) 2003 Lode Leroy
 * Copyright (c) 2003 Anton Altaparmakov
 * Copyright (c) 2003 Richard Russon
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the Linux-NTFS
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation,Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
 
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <stdio.h>
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_MACHINE_ENDIAN_H
#include <machine/endian.h>
#endif
#ifdef HAVE_ICONV_H
#include <iconv.h>
#endif
#include <ctype.h>      /* isalpha */
#include <stdarg.h>
#include "types.h"

#ifdef HAVE_LIBNTFS
#include <ntfs/volume.h>
#include <ntfs/attrib.h>
#ifdef HAVE_NTFS_VERSION_H
#include <ntfs/version.h>
#endif
#endif
#ifdef HAVE_LIBNTFS3G
#include <ntfs-3g/volume.h>
#include <ntfs-3g/attrib.h>
#endif

#include "common.h"
#include "intrf.h"
#include "ntfs.h"
#include "dir.h"
#include "ntfs_dir.h"
#include "ntfs_utl.h"
#include "ntfs_inc.h"
#include "log.h"
#include "setdate.h"

#if defined(HAVE_LIBNTFS) || defined(HAVE_LIBNTFS3G)
#define MAX_PATH    1024
#define PATH_SEP      '/'
#define NTFS_DT_DIR               4
#define NTFS_DT_REG             8
#define NTFS_TIME_OFFSET ((s64)(369 * 365 + 89) * 24 * 3600 * 10000000)
#ifndef FILE_first_user
#define FILE_first_user 16
#endif

/*
 * This is the "ntfs_filldir" function type, used by ntfs_readdir() to let
 * the caller specify what kind of dirent layout it wants to have.
 * This allows the caller to read directories into their application or
 * to have different dirent layouts depending on the binary type.
 */
typedef int (*ntfs_filldir_t)(void *dirent, const ntfschar *name,
                const int name_len, const int name_type, const s64 pos,
                const MFT_REF mref, const unsigned dt_type);

extern struct ntfs_device_operations ntfs_device_testdisk_io_ops;

extern int ntfs_readdir(ntfs_inode *dir_ni, s64 *pos,
                void *dirent, ntfs_filldir_t filldir);
static time_t td_ntfs2utc (s64 ntfstime);
static int ntfs_td_list_entry(  struct ntfs_dir_struct *ls, const ntfschar *name, 
		const int name_len, const int name_type, const s64 pos,
		const MFT_REF mref, const unsigned dt_type);
static file_data_t *ntfs_dir(disk_t *disk_car, const partition_t *partition, dir_data_t *dir_data, const unsigned long int cluster);
static int ntfs_copy(disk_t *disk_car, const partition_t *partition, dir_data_t *dir_data, const file_data_t *file);
static void dir_partition_ntfs_close(dir_data_t *dir_data);

/**
 * index_get_size - Find the INDX block size from the index root
 * @inode:  Inode of the directory to be checked
 *
 * Find the size of a directory's INDX block from the INDEX_ROOT attribute.
 *
 * Return:  n  Success, the INDX blocks are n bytes in size
 *	    0  Error, not a directory
 */
static int index_get_size(ntfs_inode *inode)
{
	ATTR_RECORD *attr90;
	INDEX_ROOT *iroot;

	attr90 = find_first_attribute(AT_INDEX_ROOT, inode->mrec);
	if (!attr90)
		return 0;	// not a directory

	iroot = (INDEX_ROOT*)((u8*)attr90 + le16_to_cpu(attr90->value_offset));

	return iroot->index_block_size;
}

/**
 * td_ntfs2utc - Convert an NTFS time to Unix time
 * @time:  An NTFS time in 100ns units since 1601
 *
 * NTFS stores times as the number of 100ns intervals since January 1st 1601 at
 * 00:00 UTC.  This system will not suffer from Y2K problems until ~57000AD.
 *
 * Return:  n  A Unix time (number of seconds since 1970)
 */
static time_t td_ntfs2utc (s64 ntfstime)
{
  return (ntfstime - (NTFS_TIME_OFFSET)) / 10000000;
}

#ifdef HAVE_ICONV
static int ntfs_ucstoutf8(iconv_t cd, const ntfschar *ins, int ins_len, char **outs, int outs_len)
{
    const char *inp;
    char *outp;
    size_t inb_left, outb_left;
    if (cd == (iconv_t)(-1))
      return -1;

    outp = *outs;
    inp = (const char *) ins;
    inb_left = ins_len << 1;    // ntfschar is 16-bit
    outb_left = outs_len - 1;   // reserve 1 byte for NUL

    if (iconv(cd, (char**)&inp, &inb_left, &outp, &outb_left) == (size_t)(-1))
    {
      // Regardless of the value of errno
      log_error("ntfs_ucstoutf8: iconv failed\n");
      return -1;
    }
    *outp = '\0';
    return 0;
}
#endif

/**
 * ntfs_td_list_entry
 * FIXME: Should we print errors as we go along? (AIA)
 */
static int ntfs_td_list_entry(  struct ntfs_dir_struct *ls, const ntfschar *name, 
		const int name_len, const int name_type, const s64 pos,
		const MFT_REF mref, const unsigned dt_type)
{
  char *filename = NULL;
  int result = 0;
  filename = (char *)calloc (1, MAX_PATH);
  if (!filename)
  {
    log_critical("ntfs_td_list_entry calloc failed\n");
    return -1;
  }

#ifdef HAVE_ICONV
  if (ntfs_ucstoutf8(ls->cd, name, name_len, &filename, MAX_PATH) < 0 &&
      ntfs_ucstombs (name, name_len, &filename, MAX_PATH) < 0) {
    log_error("Cannot represent filename in current locale.\n");
    goto free;
  }
#else
  if (ntfs_ucstombs (name, name_len, &filename, MAX_PATH) < 0) {
    log_error("Cannot represent filename in current locale.\n");
    goto free;
  }
#endif

  result = 0;					/* These are successful */
  if (MREF(mref) < FILE_first_user && filename[0] == '$')	/* Hide system file */
      goto free;
  /* Keep FILE_NAME_WIN32 and FILE_NAME_POSIX */
  if ((name_type & FILE_NAME_WIN32_AND_DOS) == FILE_NAME_DOS)
    goto free;
  {
    s64 filesize = 0;
    ntfs_inode *ni;
    ntfs_attr_search_ctx *ctx = NULL;
    ATTR_RECORD *attr;
    STANDARD_INFORMATION *si;

    result = -1;				/* Everything else is bad */

    ni = ntfs_inode_open(ls->vol, mref);
    if (!ni)
      goto release;

    ctx = ntfs_attr_get_search_ctx(ni, ni->mrec);
    if (!ctx)
      goto release;
    if (ntfs_attr_lookup(AT_STANDARD_INFORMATION, AT_UNNAMED, 0, 0, 0, NULL,
	  0, ctx))
      goto release;
    attr = ctx->attr;

    si = (STANDARD_INFORMATION*)((char*)attr +
                            le16_to_cpu(attr->value_offset));

    if (!si)
      goto release;

    if (dt_type != NTFS_DT_DIR) {
      if (!ntfs_attr_lookup(AT_DATA, AT_UNNAMED, 0, 0, 0,
	    NULL, 0, ctx))
	filesize = ntfs_get_attribute_value_length(
	    ctx->attr);
    }

    {
      file_data_t *new_file=(file_data_t *)MALLOC(sizeof(*new_file));
      memcpy(new_file->name,filename,(MAX_PATH<sizeof(new_file->name)?MAX_PATH:sizeof(new_file->name)));
      new_file->status=0;
      new_file->prev=ls->current_file;
      new_file->next=NULL;
      new_file->stat.st_dev=0;
      new_file->stat.st_ino=MREF(mref);
      new_file->stat.st_mode = (dt_type == NTFS_DT_DIR?LINUX_S_IFDIR| LINUX_S_IRUGO | LINUX_S_IXUGO:LINUX_S_IFREG | LINUX_S_IRUGO);
      new_file->stat.st_nlink=1;
      new_file->stat.st_uid=0;
      new_file->stat.st_gid=0;
      new_file->stat.st_rdev=0;
      new_file->stat.st_size=filesize;
#ifdef DJGPP
      new_file->file_size=filesize;
#endif
      new_file->stat.st_blksize=DEFAULT_SECTOR_SIZE;
#ifdef HAVE_STRUCT_STAT_ST_BLOCKS
      if(new_file->stat.st_blksize!=0)
      {
	new_file->stat.st_blocks=(filesize + new_file->stat.st_blksize - 1) / new_file->stat.st_blksize;
      }
#endif
      new_file->stat.st_atime=td_ntfs2utc(sle64_to_cpu(si->last_access_time));
      new_file->stat.st_mtime=td_ntfs2utc(sle64_to_cpu(si->last_data_change_time));
      new_file->stat.st_ctime=td_ntfs2utc(sle64_to_cpu(si->creation_time));
      new_file->prev=ls->current_file;
      new_file->next=NULL;
      /* log_debug("fat: new file %s de=%p size=%u\n",new_file->name,de,de->size); */
      if(ls->current_file!=NULL)
        ls->current_file->next=new_file;
      else
        ls->dir_list=new_file;
      ls->current_file=new_file;
    }

    result = 0;
release:
    /* Release atrtibute search context and close the inode. */
    if (ctx)
      ntfs_attr_put_search_ctx(ctx);
    if (ni)
      ntfs_inode_close(ni);
  }
free:
  free (filename);
  return result;
}

static file_data_t *ntfs_dir(disk_t *disk_car, const partition_t *partition, dir_data_t *dir_data, const unsigned long int cluster)
{
  ntfs_inode *inode;
  s64 pos;
  struct ntfs_dir_struct *ls=(struct ntfs_dir_struct*)dir_data->private_dir_data;
  ls->dir_list=NULL;
  ls->current_file=NULL;

  inode = ntfs_inode_open (ls->vol, cluster);
  if (!inode) {
    log_error("ntfs_dir: ntfs_inode_open failed\n");
    return NULL;
  }

  /*
   * We now are at the final path component.  If it is a file just
   * list it.  If it is a directory, list its contents.
   */
  pos = 0;
  if (inode->mrec->flags & MFT_RECORD_IS_DIRECTORY) {
    if(ntfs_readdir(inode, &pos, ls, (ntfs_filldir_t)ntfs_td_list_entry)<0)
    {
      log_error("ntfs_readdir failed\n");
    }
  }
  else
    log_critical("ntfs_readdir BUG not MFT_RECORD_IS_DIRECTORY\n");
  /* Finished with the inode; release it. */
  ntfs_inode_close(inode);
  return ls->dir_list;
}

enum { bufsize = 4096 };

static int ntfs_copy(disk_t *disk_car, const partition_t *partition, dir_data_t *dir_data, const file_data_t *file)
{
  const unsigned long int first_inode=file->stat.st_ino;
  ntfs_inode *inode;
  struct ntfs_dir_struct *ls=(struct ntfs_dir_struct*)dir_data->private_dir_data;
  inode = ntfs_inode_open (ls->vol, first_inode);
  if (!inode) {
    log_error("ntfs_copy: ntfs_inode_open failed\n");
    return -1;
  }
  {
    char *buffer;
    char *new_file;
    ntfs_attr *attr;
    FILE *f_out;
    s64 bytes_read, written;
    s64 offset;
    u32 block_size;
    buffer = (char *)MALLOC(bufsize);
    if (!buffer)
    {
      ntfs_inode_close(inode);
      return -2;
    }
    attr = ntfs_attr_open(inode, AT_DATA, NULL, 0);
    if (!attr)
    {
      log_error("Cannot find attribute type 0x%lx.\n", (long) AT_DATA);
      free(buffer);
      ntfs_inode_close(inode);
      return -3;
    }
    if ((inode->mft_no < 2) && (attr->type == AT_DATA))
      block_size = ls->vol->mft_record_size;
    else if (attr->type == AT_INDEX_ALLOCATION)
      block_size = index_get_size(inode);
    else
      block_size = 0;
    f_out=fopen_local(&new_file, dir_data->local_dir, dir_data->current_directory);
    if(!f_out)
    {
      log_critical("Can't create file %s: %s\n",new_file, strerror(errno));
      free(new_file);
      ntfs_attr_close(attr);
      free(buffer);
      ntfs_inode_close(inode);
      return -4;
    }
    offset = 0;
    for (;;)
    {
      if (block_size > 0) {
	// These types have fixup
	bytes_read = ntfs_attr_mst_pread(attr, offset, 1, block_size, buffer);
	bytes_read *= block_size;
      } else {
	bytes_read = ntfs_attr_pread(attr, offset, bufsize, buffer);
      }
      //ntfs_log_info("read %lld bytes\n", bytes_read);
      if (bytes_read == -1) {
	log_error("ERROR: Couldn't read file");
	break;
      }
      if (!bytes_read)
	break;

      written = fwrite(buffer, 1, bytes_read, f_out);
      if (written != bytes_read)
      {
	log_error("ERROR: Couldn't output all data!");
	break;
      }
      offset += bytes_read;
    }
    fclose(f_out);
    set_date(new_file, file->stat.st_atime, file->stat.st_mtime);
    free(new_file);
    ntfs_attr_close(attr);
    free(buffer);
  }
  /* Finished with the inode; release it. */
  ntfs_inode_close(inode);
  return 0;
}

static void dir_partition_ntfs_close(dir_data_t *dir_data)
{
  struct ntfs_dir_struct *ls=(struct ntfs_dir_struct*)dir_data->private_dir_data;
  /* ntfs_umount() will invoke ntfs_device_free() for us. */
  ntfs_umount(ls->vol, FALSE);
  free(ls->my_data);
#ifdef HAVE_ICONV
  if (ls->cd != (iconv_t)(-1))
    iconv_close(ls->cd);
#endif
  free(ls);
}
#endif

int dir_partition_ntfs_init(disk_t *disk_car, const partition_t *partition, dir_data_t *dir_data, const int verbose)
{
#if defined(HAVE_LIBNTFS) || defined(HAVE_LIBNTFS3G)
  struct ntfs_device *dev;
  my_data_t *my_data=NULL;
  ntfs_volume *vol=NULL;
#ifdef NTFS_LOG_LEVEL_VERBOSE
  ntfs_log_set_levels(NTFS_LOG_LEVEL_VERBOSE);
  ntfs_log_set_handler(ntfs_log_handler_stderr);
#endif

  dev = ntfs_device_alloc("/", 0, &ntfs_device_testdisk_io_ops, NULL);
  if (dev)
  {
    my_data=(my_data_t *)MALLOC(sizeof(*my_data));
    my_data->partition=partition;
    my_data->disk_car=disk_car;
    my_data->offset=0;
    dev->d_private=my_data;
    /* Call ntfs_device_mount() to do the actual mount. */
#ifdef MS_RDONLY
    vol = ntfs_device_mount(dev, MS_RDONLY);
#else
    vol = ntfs_device_mount(dev, NTFS_MNT_RDONLY);
#endif
#ifdef HAVE_NTFS_VOLUME_STARTUP
    if(!vol) {
#ifdef MS_RDONLY
      vol = ntfs_volume_startup(dev, MS_RDONLY);
#else
      vol = ntfs_volume_startup(dev, NTFS_MNT_RDONLY);
#endif
      if(vol)
      {
	log_warning("NTFS filesystem need to be repaired.\n");
      }
    }
#endif
  }
  if (!vol) {
    free(my_data);
    ntfs_device_free(dev);
    return -1;
  }
  if (vol->flags & VOLUME_IS_DIRTY) {
    log_warning("NTFS Volume is dirty.\n");
  }
  {
    struct ntfs_dir_struct *ls=(struct ntfs_dir_struct *)MALLOC(sizeof(*ls));
    ls->dir_list=NULL;
    ls->current_file=NULL;
    ls->vol=vol;
    ls->my_data=my_data;
#ifdef HAVE_ICONV
    if ((ls->cd = iconv_open("UTF-8", "UTF-16LE")) == (iconv_t)(-1))
    {
      log_error("ntfs_ucstoutf8: iconv_open failed\n");
    }
#endif
    strncpy(dir_data->current_directory,"/",sizeof(dir_data->current_directory));
    dir_data->current_inode=FILE_root;
    dir_data->param=0;
    dir_data->verbose=verbose;
    dir_data->capabilities=0;
    dir_data->get_dir=ntfs_dir;
    dir_data->copy_file=ntfs_copy;
    dir_data->close=&dir_partition_ntfs_close;
    dir_data->local_dir=NULL;
    dir_data->private_dir_data=ls;
  }
  return 0;
#else
  return -2;
#endif
}

const char*td_ntfs_version(void)
{
#ifdef HAVE_LIBNTFS
#ifdef HAVE_NTFS_LIBNTFS_VERSION
  return ntfs_libntfs_version();
#else
  return "available";
#endif
#elif defined(HAVE_LIBNTFS3G)
  return "libntfs-3g";
#else
  return "none";
#endif
}
