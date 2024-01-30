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

#if defined(DISABLED_FOR_FRAMAC)
#undef HAVE_LIBNTFS
#undef HAVE_LIBNTFS3G
#undef HAVE_SYS_PARAM_H
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
#if defined(HAVE_SYS_PARAM_H)
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

#if defined(HAVE_LIBNTFS)
#include <ntfs/volume.h>
#include <ntfs/attrib.h>
#ifdef HAVE_NTFS_VERSION_H
#include <ntfs/version.h>
#endif
#endif
#if defined(HAVE_LIBNTFS3G)
#include <ntfs-3g/volume.h>
#include <ntfs-3g/attrib.h>
#endif

#include "common.h"
#include "intrf.h"
#include "list.h"
#include "list_sort.h"
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
static int ntfs_td_list_entry(  struct ntfs_dir_struct *ls, const ntfschar *name, 
		const int name_len, const int name_type, const s64 pos,
		const MFT_REF mref, const unsigned dt_type);
static int ntfs_dir(disk_t *disk_car, const partition_t *partition, dir_data_t *dir_data, const unsigned long int cluster, file_info_t *dir_list);
static copy_file_t ntfs_copy(disk_t *disk_car, const partition_t *partition, dir_data_t *dir_data, const file_info_t *file);
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

#ifdef HAVE_ICONV
static int ntfs_ucstoutf8(iconv_t cd, const ntfschar *ins, const int ins_len, char **outs, const int outs_len)
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

    *outp = '\0';
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
  int result = 0;
  char *filename;
  ntfs_inode *ni;
  ntfs_attr_search_ctx *ctx_si = NULL;
  file_info_t *new_file=NULL;
  /* Keep FILE_NAME_WIN32 and FILE_NAME_POSIX */
  if ((name_type & FILE_NAME_WIN32_AND_DOS) == FILE_NAME_DOS)
    return 0;

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
    goto freefn;
  }
#else
  if (ntfs_ucstombs (name, name_len, &filename, MAX_PATH) < 0) {
    log_error("Cannot represent filename in current locale.\n");
    goto freefn;
  }
#endif

  result = 0;					/* These are successful */
  if ((ls->dir_data->param & FLAG_LIST_SYSTEM)!=FLAG_LIST_SYSTEM &&
      MREF(mref) < FILE_first_user && filename[0] == '$')	/* Hide system file */
      goto freefn;
  result = -1;				/* Everything else is bad */

  ni = ntfs_inode_open(ls->vol, mref);
  if (!ni)
    goto freefn;
  new_file=(file_info_t*)MALLOC(sizeof(*new_file));
  new_file->status=0;
  new_file->st_ino=MREF(mref);
  new_file->st_uid=0;
  new_file->st_gid=0;

  ctx_si = ntfs_attr_get_search_ctx(ni, ni->mrec);
  if (ctx_si)
  {
    if (ntfs_attr_lookup(AT_STANDARD_INFORMATION, AT_UNNAMED, 0, CASE_SENSITIVE, 0, NULL, 0, ctx_si)==0)
    {
      const ATTR_RECORD *attr = ctx_si->attr;
      const STANDARD_INFORMATION *si = (const STANDARD_INFORMATION*)((const char*)attr +
	  le16_to_cpu(attr->value_offset));
      if(si)
      {
	new_file->td_atime=td_ntfs2utc(sle64_to_cpu(si->last_access_time));
	new_file->td_mtime=td_ntfs2utc(sle64_to_cpu(si->last_data_change_time));
	new_file->td_ctime=td_ntfs2utc(sle64_to_cpu(si->creation_time));
      }
    }
    ntfs_attr_put_search_ctx(ctx_si);
  }
  {
    ATTR_RECORD *rec;
    int first=1;
    ntfs_attr_search_ctx *ctx = NULL;
    if (dt_type == NTFS_DT_DIR)
    {
      new_file->name=strdup(filename);
      new_file->st_mode = LINUX_S_IFDIR| LINUX_S_IRUGO | LINUX_S_IXUGO;
      new_file->st_size=0;
      td_list_add_tail(&new_file->list, &ls->dir_list->list);
      first=0;
    }
    ctx = ntfs_attr_get_search_ctx(ni, ni->mrec);
    /* A file has always an unnamed date stream and
     * may have named alternate data streams (ADS) */
    while((rec = find_attribute(AT_DATA, ctx)))
    {
      const s64 filesize = ntfs_get_attribute_value_length(ctx->attr);
      if(rec->name_length &&
	  (ls->dir_data->param & FLAG_LIST_ADS)!=FLAG_LIST_ADS)
	continue;
      if(first==0)
      {
	const file_info_t *old_file=new_file;
	new_file=(file_info_t *)MALLOC(sizeof(*new_file));
	memcpy(new_file, old_file, sizeof(*new_file));
      }
      new_file->st_mode = LINUX_S_IFREG | LINUX_S_IRUGO;
      new_file->st_size=filesize;
      if (rec->name_length)
      {
	char *stream_name=NULL;
	new_file->status=FILE_STATUS_ADS;
	new_file->name = (char *)MALLOC(MAX_PATH);
	if (ntfs_ucstombs((ntfschar *) ((char *) rec + le16_to_cpu(rec->name_offset)),
	      rec->name_length, &stream_name, 0) < 0)
	{
	  log_error("ERROR: Cannot translate name into current locale.\n");
	  snprintf(new_file->name, MAX_PATH, "%s:???", filename);
	}
	else
	{
	  snprintf(new_file->name, MAX_PATH, "%s:%s", filename, stream_name);
	}
	free(stream_name);
      }
      else
      {
	new_file->name=strdup(filename);
      }
      td_list_add_tail(&new_file->list, &ls->dir_list->list);
      first=0;
    }
    ntfs_attr_put_search_ctx(ctx);
    if(first)
    {
      free(new_file);
    }
  }

  result = 0;
  /* close the inode. */
  ntfs_inode_close(ni);
freefn:
  free (filename);
  return result;
}

static int ntfs_dir(disk_t *disk_car, const partition_t *partition, dir_data_t *dir_data, const unsigned long int cluster, file_info_t *dir_list)
{
  ntfs_inode *inode;
  s64 pos;
  struct ntfs_dir_struct *ls=(struct ntfs_dir_struct*)dir_data->private_dir_data;
  ls->dir_list=dir_list;

  inode = ntfs_inode_open (ls->vol, cluster);
  if (!inode) {
    log_error("ntfs_dir: ntfs_inode_open failed\n");
    return -1;
  }

  /*
   * We now are at the final path component.  If it is a file just
   * list it.  If it is a directory, list its contents.
   */
  pos = 0;
  if (inode->mrec->flags & MFT_RECORD_IS_DIRECTORY) {
    if(ntfs_readdir(inode, &pos, ls, (ntfs_filldir_t)ntfs_td_list_entry)<0)
    {
      log_error("ntfs_readdir failed for cluster %lu: %s\n", cluster,
	  strerror(errno));
    }
  }
  else
    log_critical("ntfs_readdir BUG not MFT_RECORD_IS_DIRECTORY\n");
  /* Finished with the inode; release it. */
  ntfs_inode_close(inode);
  td_list_sort(&dir_list->list, filesort);
  return 0;
}

enum { bufsize = 4096 };

static copy_file_t ntfs_copy(disk_t *disk_car, const partition_t *partition, dir_data_t *dir_data, const file_info_t *file)
{
  const unsigned long int first_inode=file->st_ino;
  ntfs_inode *inode;
  struct ntfs_dir_struct *ls=(struct ntfs_dir_struct*)dir_data->private_dir_data;
  copy_file_t res=CP_OK;
  inode = ntfs_inode_open (ls->vol, first_inode);
  if (!inode) {
    log_error("ntfs_copy: ntfs_inode_open failed for %s\n", dir_data->current_directory);
    return CP_STAT_FAILED;
  }
  {
    char *buffer;
    char *new_file;
    ntfs_attr *attr=NULL;
    FILE *f_out;
    char *stream_name;
    s64 offset;
    u32 block_size;
    buffer = (char *)MALLOC(bufsize);
    if (!buffer)
    {
      ntfs_inode_close(inode);
      return CP_NOMEM;
    }
    stream_name=strrchr(dir_data->current_directory, ':');
    if(stream_name)
      stream_name++;
    if(stream_name != NULL)
    {
      ntfschar *stream_name_ucs=NULL;
#ifdef NTFS_MBSTOUCS_HAVE_TWO_ARGUMENTS
      const int len=ntfs_mbstoucs(stream_name, &stream_name_ucs);
#else
      const int len=ntfs_mbstoucs(stream_name, &stream_name_ucs, 0);
#endif
      if(len < 0)
	log_error("ntfs_mbstoucs failed\n");
      else
	attr = ntfs_attr_open(inode, AT_DATA, stream_name_ucs, len);
    }
    else
      attr = ntfs_attr_open(inode, AT_DATA, NULL, 0);
    if (!attr)
    {
      log_error("Cannot find attribute type 0x%lx.\n", (long) AT_DATA);
      free(buffer);
      ntfs_inode_close(inode);
      return CP_STAT_FAILED;
    }
    if ((inode->mft_no < 2) && (attr->type == AT_DATA))
      block_size = ls->vol->mft_record_size;
    else if (attr->type == AT_INDEX_ALLOCATION)
      block_size = index_get_size(inode);
    else
      block_size = 0;
#if defined(__CYGWIN__) || defined(__MINGW32__)
    if(stream_name)
    {
      /* fopen() create normal files instead of ADS with ':' replaced by an UTF char
       * replace ':' by '_' instead */
      stream_name--;
      *stream_name='_';
      f_out=fopen_local(&new_file, dir_data->local_dir, dir_data->current_directory);
    }
    else
      f_out=fopen_local(&new_file, dir_data->local_dir, dir_data->current_directory);
#else
    f_out=fopen_local(&new_file, dir_data->local_dir, dir_data->current_directory);
#endif
    if(!f_out)
    {
      log_critical("Can't create file %s: %s\n",new_file, strerror(errno));
      free(new_file);
      ntfs_attr_close(attr);
      free(buffer);
      ntfs_inode_close(inode);
      return CP_CREATE_FAILED;
    }
    offset = 0;
    for (;;)
    {
      s64 bytes_read, written;
      if (block_size > 0) {
	// These types have fixup
	bytes_read = ntfs_attr_mst_pread(attr, offset, 1, block_size, buffer);
	bytes_read *= block_size;
      } else {
	bytes_read = ntfs_attr_pread(attr, offset, bufsize, buffer);
      }
      //ntfs_log_info("read %lld bytes\n", bytes_read);
      if (bytes_read < 0) {
	log_error("ERROR: Couldn't read file");
	res=CP_READ_FAILED;
	break;
      }
      if (!bytes_read)
	break;

      written = fwrite(buffer, 1, bytes_read, f_out);
      if (written != bytes_read)
      {
	log_error("ERROR: Couldn't output all data!");
	res=CP_NOSPACE;
	break;
      }
      offset += bytes_read;
    }
    fclose(f_out);
    set_date(new_file, file->td_atime, file->td_mtime);
    free(new_file);
    ntfs_attr_close(attr);
    free(buffer);
  }
  /* Finished with the inode; release it. */
  ntfs_inode_close(inode);
  return res;
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

dir_partition_t dir_partition_ntfs_init(disk_t *disk_car, const partition_t *partition, dir_data_t *dir_data, const int verbose, const int expert)
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
	log_warning("NTFS filesystem needs to be repaired.\n");
      }
    }
#endif
  }
  if (!vol) {
    free(my_data);
    ntfs_device_free(dev);
    return DIR_PART_EIO;
  }
  if (vol->flags & VOLUME_IS_DIRTY) {
    log_warning("NTFS Volume is dirty.\n");
  }
  {
    struct ntfs_dir_struct *ls=(struct ntfs_dir_struct *)MALLOC(sizeof(*ls));
    ls->dir_list=NULL;
    ls->vol=vol;
    ls->my_data=my_data;
    ls->dir_data=dir_data;
#ifdef HAVE_ICONV
    if ((ls->cd = iconv_open("UTF-8", "UTF-16LE")) == (iconv_t)(-1))
    {
      log_error("ntfs_ucstoutf8: iconv_open failed\n");
    }
#endif
    strncpy(dir_data->current_directory,"/",sizeof(dir_data->current_directory));
    dir_data->current_inode=FILE_root;
    dir_data->param=FLAG_LIST_ADS;
    if(expert!=0)
      dir_data->param|=FLAG_LIST_SYSTEM;
    dir_data->verbose=verbose;
    dir_data->capabilities=CAPA_LIST_ADS;
    dir_data->get_dir=&ntfs_dir;
    dir_data->copy_file=&ntfs_copy;
    dir_data->close=&dir_partition_ntfs_close;
    dir_data->local_dir=NULL;
    dir_data->private_dir_data=ls;
  }
  return DIR_PART_OK;
#else
  return DIR_PART_ENOSYS;
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
