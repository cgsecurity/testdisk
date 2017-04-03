/*

    File: hdcache.c

    Copyright (C) 2005-2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include "types.h"
#include "common.h"
#include "hdcache.h"
#include "log.h"

#define CACHE_BUFFER_NBR 16
#define CACHE_DEFAULT_SIZE 64*512
//#define DEBUG_CACHE 1

struct cache_buffer_struct
{
  unsigned char *buffer;
  unsigned int	buffer_size;
  unsigned int	cache_size;
  uint64_t 	cache_offset;
  int		cache_status;
};

struct cache_struct
{
  disk_t *disk_car;
  struct cache_buffer_struct cache[CACHE_BUFFER_NBR];
#ifdef DEBUG_CACHE
  uint64_t 	nbr_fnct_sect;
  uint64_t 	nbr_pread_sect;
  unsigned int 	nbr_fnct_call;
  unsigned int 	nbr_pread_call;
#endif
  unsigned int  cache_buffer_nbr;
  unsigned int  cache_size_min;
  unsigned int  last_io_error_nbr;
};

static int cache_pread_aux(disk_t *disk_car, void *buffer, const unsigned int count, const uint64_t offset, const unsigned int read_ahead);
static int cache_pread(disk_t *disk_car, void *buffer, const unsigned int count, const uint64_t offset);
static int cache_pwrite(disk_t *disk_car, const void *buffer, const unsigned int count, const uint64_t offset);
static int cache_sync(disk_t *disk);
static void cache_clean(disk_t *disk);
static const char *cache_description(disk_t *disk_car);
static const char *cache_description_short(disk_t *disk_car);

static int cache_pread(disk_t *disk_car, void *buffer, const unsigned int count, const uint64_t offset)
{
  const struct cache_struct *data=(const struct cache_struct *)disk_car->data;
  return cache_pread_aux(disk_car, buffer, count, offset, (data->last_io_error_nbr==0));
}

static int cache_pread_aux(disk_t *disk_car, void *buffer, const unsigned int count, const uint64_t offset, const unsigned int read_ahead)
{
  struct cache_struct *data=(struct cache_struct *)disk_car->data;
#ifdef DEBUG_CACHE
  log_info("cache_pread(buffer, count=%u, offset=%llu, read_ahead=%u)\n", count,(long long unsigned)offset, read_ahead);
  data->nbr_fnct_call++;
#endif
  {
    unsigned int i;
    unsigned int cache_buffer_nbr;
    /* Data is probably in the last buffers */
    for(i=0, cache_buffer_nbr=data->cache_buffer_nbr;
	i<CACHE_BUFFER_NBR;
	i++, cache_buffer_nbr=(cache_buffer_nbr+CACHE_BUFFER_NBR-1)%CACHE_BUFFER_NBR)
    {
      const struct cache_buffer_struct *cache=&data->cache[cache_buffer_nbr];
      if(cache->cache_offset <= offset &&
	  offset < cache->cache_offset +cache->cache_size &&
	  cache->buffer!=NULL && cache->cache_size>0)
      {
	const unsigned int data_available= cache->cache_size + cache->cache_offset - offset;
	const int res=cache->cache_status + cache->cache_offset - offset;
	if(count<=data_available)
	{
#ifdef DEBUG_CACHE
	  log_info("cache use %5u count=%u, coffset=%llu, cstatus=%d\n",
	      cache_buffer_nbr, cache->cache_size, (long long unsigned)cache->cache_offset,
	      cache->cache_status);
	  data->nbr_fnct_sect+=count;
#endif
	  memcpy(buffer, cache->buffer + offset - cache->cache_offset, count);
	  return (res < (signed)count ?  res : (signed)count );
	}
	else
	{
#ifdef DEBUG_CACHE
	  log_info("cache USE %5u count=%u, coffset=%llu, ctstatus=%d, call again cache_pread_aux\n",
	      cache_buffer_nbr, cache->cache_size, (long long unsigned)cache->cache_offset,
	      cache->cache_status);
	  data->nbr_fnct_sect+=data_available;
#endif
	  memcpy(buffer, cache->buffer + offset - cache->cache_offset, data_available);
	  return res + cache_pread_aux(disk_car, (unsigned char*)buffer+data_available,
		count-data_available, offset+data_available, read_ahead);
	}
      }
    }
  }
  {
    struct cache_buffer_struct *cache;
    const unsigned int count_new=(read_ahead!=0 && count<data->cache_size_min && (offset+data->cache_size_min<data->disk_car->disk_real_size)?data->cache_size_min:count);
    data->cache_buffer_nbr=(data->cache_buffer_nbr+1)%CACHE_BUFFER_NBR;
    cache=&data->cache[data->cache_buffer_nbr];
    if(cache->buffer_size < count_new)
    {	/* Buffer is too small, drop it */
      free(cache->buffer);
      cache->buffer=NULL;
    }
    if(cache->buffer==NULL)
    {	/* Allocate buffer */
      cache->buffer_size=(count_new<CACHE_DEFAULT_SIZE?CACHE_DEFAULT_SIZE:count_new);
      cache->buffer=(unsigned char *)MALLOC(cache->buffer_size);
    }
    cache->cache_size=count_new;
    cache->cache_offset=offset;
    cache->cache_status=data->disk_car->pread(data->disk_car, cache->buffer, count_new, offset);
#ifdef DEBUG_CACHE
    data->nbr_fnct_sect+=count;
    data->nbr_pread_call++;
    data->nbr_pread_sect+=count_new;
    log_info("cache PREAD(buffer[%u], count=%u, count_new=%u, offset=%llu, cstatus=%d)\n",
	data->cache_buffer_nbr, count, count_new, (long long unsigned)offset,
	cache->cache_status);
#endif
    if(cache->cache_status >= (signed)count)
    {
      data->last_io_error_nbr=0;
      memcpy(buffer, cache->buffer, count);
      return count;
    }
    /* Read failure */
    data->last_io_error_nbr++;
    if(count_new<=disk_car->sector_size || disk_car->sector_size<=0 || data->last_io_error_nbr>1)
    {
      memcpy(buffer, cache->buffer, count);
      return cache->cache_status;
    }
    /* Free the existing cache */
    cache->cache_size=0;
    /* split the read sector by sector */
    {
      unsigned int off;
      memset(buffer, 0, count);
      for(off=0; off<count; off+=disk_car->sector_size)
      {
	if(cache_pread_aux(disk_car, 
	    (unsigned char*)buffer+off,
	    (disk_car->sector_size < count - off ? disk_car->sector_size : count - off),
	    offset+off, 0) <= 0)
	{
	  return off;
	}
      }
      return count;
    }
  }
}

static int cache_pwrite(disk_t *disk_car, const void *buffer, const unsigned int count, const uint64_t offset)
{
  struct cache_struct *data=(struct cache_struct *)disk_car->data;
  unsigned int i;
  for(i=0;i<CACHE_BUFFER_NBR;i++)
  {
    struct cache_buffer_struct *cache=&data->cache[i];
    if(!(cache->cache_offset+cache->cache_size-1 < offset || offset+count-1 < cache->cache_offset))
    {
      /* Discard the cache */
      cache->cache_size=0;
    }
  }
  disk_car->write_used=1;
  return data->disk_car->pwrite(data->disk_car, buffer, count, offset);
}

static void cache_clean(disk_t *disk_car)
{
  if(disk_car->data)
  {
    struct cache_struct *data=(struct cache_struct *)disk_car->data;
    unsigned int i;
#ifdef DEBUG_CACHE
    log_info("%s\ncache_pread total_call=%u, total_count=%llu\n      read total_call=%u, total_count=%llu\n",
	data->disk_car->description(data->disk_car),
	data->nbr_fnct_call, (long long unsigned)data->nbr_fnct_sect,
	data->nbr_pread_call, (long long unsigned)data->nbr_pread_sect);
#endif
    data->disk_car->clean(data->disk_car);
    for(i=0;i<CACHE_BUFFER_NBR;i++)
    {
      struct cache_buffer_struct *cache=&data->cache[i];
      free(cache->buffer);
    }
    free(disk_car->data);
    disk_car->data=NULL;
  }
  free(disk_car);
}

static int cache_sync(disk_t *disk_car)
{
  struct cache_struct *data=(struct cache_struct *)disk_car->data;
  return data->disk_car->sync(data->disk_car);
}

static void dup_geometry(CHSgeometry_t * CHS_dst, const CHSgeometry_t * CHS_source)
{
  CHS_dst->cylinders=CHS_source->cylinders;
  CHS_dst->heads_per_cylinder=CHS_source->heads_per_cylinder;
  CHS_dst->sectors_per_head=CHS_source->sectors_per_head;
}

disk_t *new_diskcache(disk_t *disk_car, const unsigned int testdisk_mode)
{
  unsigned int i;
  struct cache_struct*data=(struct cache_struct*)MALLOC(sizeof(*data));
  disk_t *new_disk_car=(disk_t *)MALLOC(sizeof(*new_disk_car));
  memcpy(new_disk_car,disk_car,sizeof(*new_disk_car));
  data->disk_car=disk_car;
#ifdef DEBUG_CACHE
  data->nbr_fnct_sect=0;
  data->nbr_pread_sect=0;
  data->nbr_fnct_call=0;
  data->nbr_pread_call=0;
#endif
  data->cache_buffer_nbr=0;
  data->last_io_error_nbr=0;
  if(testdisk_mode&TESTDISK_O_READAHEAD_8K)
    data->cache_size_min=16*512;
  else if(testdisk_mode&TESTDISK_O_READAHEAD_32K)
    data->cache_size_min=64*512;
  else
    data->cache_size_min=0;
  dup_geometry(&new_disk_car->geom,&disk_car->geom);
  new_disk_car->disk_size=disk_car->disk_size;
  new_disk_car->disk_real_size=disk_car->disk_real_size;
  new_disk_car->write_used=0;
  new_disk_car->data=data;
  new_disk_car->pread=&cache_pread;
  new_disk_car->pwrite=&cache_pwrite;
  new_disk_car->sync=&cache_sync;
  new_disk_car->clean=&cache_clean;
  new_disk_car->description=&cache_description;
  new_disk_car->description_short=&cache_description_short;
  new_disk_car->rbuffer=NULL;
  new_disk_car->wbuffer=NULL;
  new_disk_car->rbuffer_size=0;
  new_disk_car->wbuffer_size=0;
  for(i=0;i<CACHE_BUFFER_NBR;i++)
  {
    data->cache[i].buffer=NULL;
    data->cache[i].buffer_size=0;
  }
  return new_disk_car;
}

static const char *cache_description(disk_t *disk_car)
{
  struct cache_struct *data=(struct cache_struct *)disk_car->data;
  dup_geometry(&data->disk_car->geom,&disk_car->geom);
  data->disk_car->disk_size=disk_car->disk_size;
  return data->disk_car->description(data->disk_car);
}

static const char *cache_description_short(disk_t *disk_car)
{
  struct cache_struct *data=(struct cache_struct *)disk_car->data;
  dup_geometry(&data->disk_car->geom,&disk_car->geom);
  data->disk_car->disk_size=disk_car->disk_size;
  return data->disk_car->description_short(data->disk_car);
}
