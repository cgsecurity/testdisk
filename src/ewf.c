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
#include "log.h"
#include "hdaccess.h"

static const char *fewf_description(disk_t *disk_car);
static const char *fewf_description_short(disk_t *disk_car);
static int fewf_clean(disk_t *disk_car);
static int fewf_read(disk_t *disk_car, const unsigned int count, void *nom_buffer, const uint64_t offset);
static int fewf_nowrite(disk_t *disk_car, const unsigned int count, const void *nom_buffer, const uint64_t offset);
static int fewf_sync(disk_t *disk_car);

struct info_fewf_struct
{
  LIBEWF_HANDLE *handle;
  uint64_t offset;
  char file_name[DISKNAME_MAX];
  int mode;
  void *buffer;
  unsigned int buffer_size;
};

disk_t *fewf_init(const char *device, const int verbose, const arch_fnct_t *arch, const int mode)
{
  unsigned int num_files=0;
  char **filenames= NULL;
  disk_t *disk_car=NULL;
  struct info_fewf_struct *data;
#ifdef HAVE_GLOB_H
  glob_t globbuf;
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
  if( libewf_parse_header_values( data->handle, LIBEWF_DATE_FORMAT_DAYMONTH) != 1 )
  {
    log_error("%s Unable to parse EWF header values\n", device);
  }
  disk_car=(disk_t *)MALLOC(sizeof(*disk_car));
  init_disk(disk_car);
  disk_car->arch=arch;
  disk_car->device=strdup(device);
  disk_car->data=data;
  disk_car->description=fewf_description;
  disk_car->description_short=fewf_description_short;
  disk_car->read=fewf_read;
  disk_car->write=fewf_nowrite;
  disk_car->sync=fewf_sync;
  disk_car->access_mode=TESTDISK_O_RDONLY;
  disk_car->clean=fewf_clean;
#ifdef LIBEWF_GET_BYTES_PER_SECTOR_HAVE_TWO_ARGUMENTS
  {
    uint32_t bytes_per_sector;
    if(libewf_get_bytes_per_sector(data->handle, &bytes_per_sector)<0)
      disk_car->sector_size=DEFAULT_SECTOR_SIZE;
    else
      disk_car->sector_size=bytes_per_sector;
  }
#else
  disk_car->sector_size=libewf_get_bytes_per_sector(data->handle);
#endif
//  printf("libewf_get_bytes_per_sector %u\n",disk_car->sector_size);
  if(disk_car->sector_size==0)
    disk_car->sector_size=DEFAULT_SECTOR_SIZE;
  /* Set geometry */
  disk_car->geom.cylinders=0;
  disk_car->geom.heads_per_cylinder=1;
  disk_car->geom.sectors_per_head=1;
  /* Get disk_real_size */
#ifdef LIBEWF_GET_MEDIA_SIZE_HAVE_TWO_ARGUMENTS
  {
    size64_t media_size;
    if(libewf_get_media_size(data->handle, &media_size)<0)
      disk_car->disk_real_size=0;
    else
      disk_car->disk_real_size=media_size;
  }
#else
  disk_car->disk_real_size=libewf_get_media_size(data->handle);
#endif
  update_disk_car_fields(disk_car);
#ifdef HAVE_GLOB_H
  globfree(&globbuf);
#endif
  free(filenames);
  return disk_car;
}

static const char *fewf_description(disk_t *disk_car)
{
  const struct info_fewf_struct *data=(const struct info_fewf_struct *)disk_car->data;
  char buffer_disk_size[100];
  snprintf(disk_car->description_txt, sizeof(disk_car->description_txt),"Image %s - %s - CHS %u %u %u%s",
      data->file_name, size_to_unit(disk_car->disk_size,buffer_disk_size),
      disk_car->geom.cylinders, disk_car->geom.heads_per_cylinder, disk_car->geom.sectors_per_head,
      ((data->mode&O_RDWR)==O_RDWR?"":" (RO)"));
  return disk_car->description_txt;
}

static const char *fewf_description_short(disk_t *disk_car)
{
  const struct info_fewf_struct *data=(const struct info_fewf_struct *)disk_car->data;
  char buffer_disk_size[100];
  snprintf(disk_car->description_short_txt, sizeof(disk_car->description_txt),"Image %s - %s%s",
      data->file_name, size_to_unit(disk_car->disk_size,buffer_disk_size),
      ((data->mode&O_RDWR)==O_RDWR?"":" (RO)"));
  return disk_car->description_short_txt;
}

static int fewf_clean(disk_t *disk_car)
{
  if(disk_car->data!=NULL)
  {
    struct info_fewf_struct *data=(struct info_fewf_struct *)disk_car->data;
    libewf_close(data->handle);
    if(data->buffer!=NULL)
    {
      free(data->buffer);
      data->buffer=NULL;
    }
    free(disk_car->data);
    disk_car->data=NULL;
  }
  return 0;
}

static int fewf_sync(disk_t *disk_car)
{
  errno=EINVAL;
  return -1;
}

static int fewf_read(disk_t *disk_car,const unsigned int count, void *nom_buffer, const uint64_t offset)
{
  struct info_fewf_struct *data=(struct info_fewf_struct *)disk_car->data;
  int64_t taille;
  taille=libewf_read_random(data->handle, nom_buffer, count, offset);
  if(taille!=count)
  {
    log_error("fewf_read(xxx,%u,buffer,%lu(%u/%u/%u)) read err: ",
	(unsigned)(count/disk_car->sector_size), (long unsigned)(offset/disk_car->sector_size),
	offset2cylinder(disk_car,offset), offset2head(disk_car,offset), offset2sector(disk_car,offset));
    if(taille<0)
      log_error("%s\n", strerror(errno));
    else if(taille==0)
      log_error("read after end of file\n");
    else
      log_error("Partial read\n");
    if(taille<=0)
      return -1;
  }
  return 0;
}

static int fewf_nowrite(disk_t *disk_car,const unsigned int count, const void *nom_buffer, const uint64_t offset)
{
  log_error("fewf_nowrite(xx,%u,buffer,%lu(%u/%u/%u)) write refused\n",
      (unsigned)(count/disk_car->sector_size), (long unsigned)(offset/disk_car->sector_size),
      offset2cylinder(disk_car,offset), offset2head(disk_car,offset), offset2sector(disk_car,offset));
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
#endif
