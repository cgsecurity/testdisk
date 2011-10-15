/*

    File: ewf.c

    Copyright (C) 2006-2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#if defined(HAVE_LIBEWF_H) && defined(HAVE_LIBEWF)

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>	/* lseek, read, write, close */
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h> 	/* open */
#endif

#include <stdio.h>
#include <errno.h>

#ifdef HAVE_STDLIB_H
#include <stdlib.h>     /* free */
#endif

#ifdef HAVE_GLOB_H
#include <glob.h>
#endif

#include "types.h"
#include "common.h"
#include "ewf.h"
#include "fnctdsk.h"

#ifndef O_BINARY
#define O_BINARY 0
#endif

#include <libewf.h>

#if !defined( LIBEWF_HANDLE )
/* libewf version 2 no longer defines LIBEWF_HANDLE
 */
#define HAVE_LIBEWF_V2_API
#endif

#include "log.h"
#include "hdaccess.h"

static const char *fewf_description(disk_t *disk);
static const char *fewf_description_short(disk_t *disk);
static int fewf_clean(disk_t *disk);
static void *fewf_pread_fast(disk_t *disk, void *buffer, const unsigned int count, const uint64_t offset);
static int fewf_pread(disk_t *disk, void *buffer, const unsigned int count, const uint64_t offset);
static int fewf_nopwrite(disk_t *disk, const void *buffer, const unsigned int count, const uint64_t offset);
static int fewf_sync(disk_t *disk);

struct info_fewf_struct
{
#if defined( HAVE_LIBEWF_V2_API )
  libewf_handle_t *handle;
#else
  LIBEWF_HANDLE *handle;
#endif
  uint64_t offset;
  char file_name[DISKNAME_MAX];
  int mode;
  void *buffer;
  unsigned int buffer_size;
};

disk_t *fewf_init(const char *device, const arch_fnct_t *arch, const int mode)
{
  unsigned int num_files=0;
  char **filenames= NULL;
  disk_t *disk=NULL;
  struct info_fewf_struct *data;
#ifdef HAVE_GLOB_H
  glob_t globbuf;
#endif

#ifdef DEBUG_EWF
#if defined( HAVE_LIBEWF_V2_API )
  libewf_notify_set_stream( stderr, NULL );
  libewf_notify_set_verbose( 1 );
#else
  libewf_set_notify_values( stderr, 1 );
#endif
#endif

  data=(struct info_fewf_struct *)MALLOC(sizeof(*data));
  data->offset=0;
  strncpy(data->file_name,device,sizeof(data->file_name));
  data->file_name[sizeof(data->file_name)-1]='\0';
  data->buffer=NULL;
  data->buffer_size=0;
  data->mode=mode;
  data->handle=NULL;
#ifdef HAVE_GLOB_H
  {
    globbuf.gl_offs = 0;
    glob(data->file_name, GLOB_DOOFFS, NULL, &globbuf);
    if(globbuf.gl_pathc>0)
    {
      filenames=(char **)MALLOC(globbuf.gl_pathc * sizeof(*filenames));
      for (num_files=0; num_files<globbuf.gl_pathc; num_files++) {
	filenames[num_files]=globbuf.gl_pathv[num_files];
      }
    }
  }
#else
  filenames=(char **)MALLOC(1*sizeof(*filenames));
  filenames[num_files] = data->file_name;
  num_files++;
#endif /*HAVE_GLOB_H*/
  if(filenames!=NULL)
  {
#if defined( HAVE_LIBEWF_V2_API )
    data->handle = NULL;

    if( libewf_handle_initialize(
         &( data->handle ),
         NULL ) != 1 )
    {
      log_error("libewf_handle_initialize failed\n");

#ifdef HAVE_GLOB_H
      globfree(&globbuf);
#endif
      free(filenames);
      free(data);
      return NULL;
    }
    if( libewf_handle_open(
         data->handle,
         filenames,
         num_files,
         LIBEWF_OPEN_READ,
         NULL ) != 1 )
    {
      log_error("libewf_handle_open(%s) failed\n", device);

      libewf_handle_free(
       &( data->handle ),
       NULL );

#ifdef HAVE_GLOB_H
      globfree(&globbuf);
#endif
      free(filenames);
      free(data);
      return NULL;
    }
#else
    data->handle=libewf_open(filenames, num_files, LIBEWF_OPEN_READ);
    if(data->handle==NULL)
    {
      log_error("libewf_open(%s) failed\n", device);

#ifdef HAVE_GLOB_H
      globfree(&globbuf);
#endif
      free(filenames);
      free(data);
      return NULL;
    }
#endif /* defined( HAVE_LIBEWF_V2_API ) */
  }

#if defined( HAVE_LIBEWF_V2_API )
  if( libewf_handle_set_header_values_date_format(
       data->handle,
       LIBEWF_DATE_FORMAT_DAYMONTH,
       NULL ) != 1 )
  {
    log_error("%s Unable to set header values date format\n", device);
  }
#else
  if( libewf_parse_header_values( data->handle, LIBEWF_DATE_FORMAT_DAYMONTH) != 1 )
  {
    log_error("%s Unable to parse EWF header values\n", device);
  }
#endif
  disk=(disk_t *)MALLOC(sizeof(*disk));
  init_disk(disk);
  disk->arch=arch;
  disk->device=strdup(device);
  disk->data=data;
  disk->description=fewf_description;
  disk->description_short=fewf_description_short;
  disk->pread_fast=fewf_pread_fast;
  disk->pread=fewf_pread;
  disk->pwrite=fewf_nopwrite;
  disk->sync=fewf_sync;
  disk->access_mode=TESTDISK_O_RDONLY;
  disk->clean=fewf_clean;
#if defined( HAVE_LIBEWF_V2_API ) || defined( LIBEWF_GET_BYTES_PER_SECTOR_HAVE_TWO_ARGUMENTS )
  {
    uint32_t bytes_per_sector = 0;

#if defined( HAVE_LIBEWF_V2_API )
    if( libewf_handle_get_bytes_per_sector(
         data->handle,
         &bytes_per_sector,
         NULL ) != 1 )
#else
    if( libewf_get_bytes_per_sector(data->handle, &bytes_per_sector)<0)
#endif
    {
      disk->sector_size=DEFAULT_SECTOR_SIZE;
    }
    else
    {
      disk->sector_size=bytes_per_sector;
    }
  }
#else
  disk->sector_size=libewf_get_bytes_per_sector(data->handle);
#endif

//  printf("libewf_get_bytes_per_sector %u\n",disk->sector_size);
  if(disk->sector_size==0)
    disk->sector_size=DEFAULT_SECTOR_SIZE;
  /* Set geometry */
  disk->geom.cylinders=0;
  disk->geom.heads_per_cylinder=1;
  disk->geom.sectors_per_head=1;
  disk->geom.bytes_per_sector=disk->sector_size;
  /* Get disk_real_size */
#if defined( HAVE_LIBEWF_V2_API ) || defined( LIBEWF_GET_MEDIA_SIZE_HAVE_TWO_ARGUMENTS )
  {
    size64_t media_size = 0;

#if defined( HAVE_LIBEWF_V2_API )
    if( libewf_handle_get_media_size(
         data->handle,
         &media_size,
         NULL ) != 1 )
#else
    if(libewf_get_media_size(data->handle, &media_size)<0)
#endif
    {
      disk->disk_real_size=0;
    }
    else
    {
      disk->disk_real_size=media_size;
    }
  }
#else
  disk->disk_real_size=libewf_get_media_size(data->handle);
#endif
  update_disk_car_fields(disk);
#ifdef HAVE_GLOB_H
  globfree(&globbuf);
#endif
  free(filenames);
  return disk;
}

static const char *fewf_description(disk_t *disk)
{
  const struct info_fewf_struct *data=(const struct info_fewf_struct *)disk->data;
  char buffer_disk_size[100];
  size_to_unit(disk->disk_size, buffer_disk_size);
  snprintf(disk->description_txt, sizeof(disk->description_txt),"Image %s - %s - CHS %lu %u %u%s",
      data->file_name, buffer_disk_size,
      disk->geom.cylinders, disk->geom.heads_per_cylinder, disk->geom.sectors_per_head,
      ((data->mode&O_RDWR)==O_RDWR?"":" (RO)"));
  return disk->description_txt;
}

static const char *fewf_description_short(disk_t *disk)
{
  const struct info_fewf_struct *data=(const struct info_fewf_struct *)disk->data;
  char buffer_disk_size[100];
  size_to_unit(disk->disk_size, buffer_disk_size);
  snprintf(disk->description_short_txt, sizeof(disk->description_txt),"Image %s - %s%s",
      data->file_name, buffer_disk_size,
      ((data->mode&O_RDWR)==O_RDWR?"":" (RO)"));
  return disk->description_short_txt;
}

static int fewf_clean(disk_t *disk)
{
  if(disk->data!=NULL)
  {
    struct info_fewf_struct *data=(struct info_fewf_struct *)disk->data;
#if defined( HAVE_LIBEWF_V2_API )
    libewf_handle_close(
     data->handle,
     NULL);
    libewf_handle_free(
     &( data->handle ),
     NULL );
#else
    libewf_close(data->handle);
#endif
    free(data->buffer);
    data->buffer=NULL;
    free(disk->data);
    disk->data=NULL;
  }
  return 0;
}

static int fewf_sync(disk_t *disk)
{
  errno=EINVAL;
  return -1;
}

static int fewf_pread(disk_t *disk, void *buffer, const unsigned int count, const uint64_t offset)
{
  struct info_fewf_struct *data=(struct info_fewf_struct *)disk->data;
  int64_t taille;
#if defined( HAVE_LIBEWF_V2_API )
  taille = libewf_handle_read_random(
            data->handle,
            buffer,
            count,
            offset,
            NULL );
#else
  taille=libewf_read_random(data->handle, buffer, count, offset);
#endif
  if(taille!=count)
  {
    log_error("fewf_pread(xxx,%u,buffer,%lu(%u/%u/%u)) read err: ",
	(unsigned)(count/disk->sector_size), (long unsigned)(offset/disk->sector_size),
	offset2cylinder(disk,offset), offset2head(disk,offset), offset2sector(disk,offset));
    if(taille<0)
      log_error("%s\n", strerror(errno));
    else if(taille==0)
      log_error("read after end of file\n");
    else
      log_error("Partial read\n");
    if(taille<=0)
      return -1;
  }
  return taille;
}

static void *fewf_pread_fast(disk_t *disk, void *buf, const unsigned int count, const uint64_t offset)
{
  if(fewf_pread(disk, buf, count, offset)==offset)
    return buf;
  return NULL;
}

static int fewf_nopwrite(disk_t *disk, const void *buffer, const unsigned int count, const uint64_t offset)
{
  log_error("fewf_nopwrite(xx,%u,buffer,%lu(%u/%u/%u)) write refused\n",
      (unsigned)(count/disk->sector_size), (long unsigned)(offset/disk->sector_size),
      offset2cylinder(disk,offset), offset2head(disk,offset), offset2sector(disk,offset));
  return -1;
}

const char*td_ewf_version(void)
{
#ifdef LIBEWF_VERSION_STRING
  return (const char*)LIBEWF_VERSION_STRING;
#elif defined(LIBEWF_VERSION)
  return LIBEWF_VERSION;
#else
  return "available";
#endif
}
#else
#include "ewf.h"
const char*td_ewf_version(void)
{
  return "none";
}
#endif /* defined(HAVE_LIBEWF_H) && defined(HAVE_LIBEWF) */

