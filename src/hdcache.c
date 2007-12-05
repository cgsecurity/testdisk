/*

    File: hdcache.c

    Copyright (C) 2005-2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include "types.h"
#include "common.h"
#include "hdcache.h"
#include "fnctdsk.h"
#include "log.h"

#define CACHE_BUFFER_NBR 128
#define CACHE_SIZE_MAX 64*512
//#define DEBUG_CACHE 1

struct cache_buffer_struct
{
  unsigned char *buffer;
  unsigned int	cache_size;
  uint64_t 	cache_offset;
  int		cache_status;
};

struct cache_struct
{
  disk_t *disk_car;
  struct cache_buffer_struct cache[CACHE_BUFFER_NBR];
  uint64_t 	nbr_fnct_sect;
  uint64_t 	nbr_read_sect;
  unsigned int 	nbr_fnct_call;
  unsigned int 	nbr_read_call;
  unsigned int  cache_buffer_nbr;
  unsigned int  cache_size_min;
};

static int cache_read(disk_t *disk_car,const unsigned int count, void *nom_buffer, const uint64_t offset);
static int cache_write(disk_t *disk_car,const unsigned int count, const void *nom_buffer, const uint64_t offset);
static int cache_sync(disk_t *clean);
static int cache_clean(disk_t *clean);
static const char *cache_description(disk_t *disk_car);
static const char *cache_description_short(disk_t *disk_car);
static int cache_read_aux(disk_t *disk_car,const unsigned int count, void *nom_buffer, const uint64_t offset, const unsigned int can_read_more);

static int cache_read(disk_t *disk_car,const unsigned int count, void *nom_buffer, const uint64_t offset)
{
  return cache_read_aux(disk_car, count, nom_buffer, offset, 1);
}

static int cache_read_aux(disk_t *disk_car,const unsigned int count, void *nom_buffer, const uint64_t offset, const unsigned int can_read_more)
{
  struct cache_struct *data=disk_car->data;
#ifdef DEBUG_CACHE
  log_trace("cache_read(count=%u,buffer,offset=%llu)\n", count,(long long unsigned)offset);
#endif
  data->nbr_fnct_call++;
  {
    unsigned int i;
    int res=0;
    /* Data is probably in the last two buffers */
    unsigned int cache_buffer_nbr=(data->cache_buffer_nbr+CACHE_BUFFER_NBR-1)%CACHE_BUFFER_NBR;
    for(i=0;i<CACHE_BUFFER_NBR;i++,cache_buffer_nbr=(cache_buffer_nbr+1)%CACHE_BUFFER_NBR)
    {
      struct cache_buffer_struct *cache=&data->cache[cache_buffer_nbr];
      if(cache->buffer!=NULL && cache->cache_size>0 &&
	  cache->cache_offset <= offset &&
	  offset < cache->cache_offset +cache->cache_size)
      {
	unsigned data_available=cache->cache_offset +cache->cache_size-offset;
	/*
	if(cache_buffer_nbr==data->cache_buffer_nbr)
	  log_trace("hit\n");
	else
	  log_trace("bid\n");
	  */
#ifdef DEBUG_CACHE
	log_trace("use cache %u count=%u, offset=%llu\n",i,
	    cache->cache_size, cache->cache_offset);
#endif
	res=cache->cache_status;
	if(count<=data_available)
	{
	  data->nbr_fnct_sect+=count;
	  memcpy(nom_buffer, cache->buffer+offset-cache->cache_offset, count);
	  return res;
	}
	else
	{
	  int newres;
	  data->nbr_fnct_sect+=data_available;
	  memcpy(nom_buffer, cache->buffer+offset-cache->cache_offset, data_available);
	  newres=cache_read_aux(disk_car, count-data_available,
	      (unsigned char*)nom_buffer+data_available, offset+data_available, can_read_more);
	  if(res>=0)
	    res=newres;
	  return res;
	}
      }
    }
  }
  if(count>CACHE_SIZE_MAX)
  {
    unsigned int i;
    int res=0;
    for(i=0;i*CACHE_SIZE_MAX<count;i++)
    {
      int newres;
      newres=cache_read_aux(disk_car, (count>(i+1)*CACHE_SIZE_MAX?CACHE_SIZE_MAX:count-i*CACHE_SIZE_MAX),
	  (unsigned char*)nom_buffer+i*CACHE_SIZE_MAX, offset+i*CACHE_SIZE_MAX, can_read_more);
      if(res>=0)
	res=newres;
    }
    return res;
  }
  {
    struct cache_buffer_struct *cache;
    int res;
    unsigned int count_new=(can_read_more!=0 && count<data->cache_size_min && (offset+data->cache_size_min<data->disk_car->disk_real_size)?data->cache_size_min:count);
    data->nbr_fnct_sect+=count;
    data->nbr_read_call++;
    data->nbr_read_sect+=count_new;
#ifdef DEBUG_CACHE
    log_trace("read(count=%u,buffer,offset=%llu)\n", count_new,(long long unsigned)offset);
#endif
    data->cache_buffer_nbr=(data->cache_buffer_nbr+1)%CACHE_BUFFER_NBR;
    cache=&data->cache[data->cache_buffer_nbr];
    if(cache->buffer==NULL)
      cache->buffer=MALLOC(CACHE_SIZE_MAX);
    res=data->disk_car->read(data->disk_car, count_new, cache->buffer, offset);
    cache->cache_size=count_new;
    cache->cache_offset=offset;
    cache->cache_status=res;
    if(res<0)
    { /* read failure */
      unsigned int i;
      if(count<=disk_car->sector_size || disk_car->sector_size<=0)
      {
	memset(cache->buffer, 0, cache->cache_size);
	memcpy(nom_buffer, cache->buffer, count);
	return res;
      }
      /* split the read sector by sector */
      cache->cache_size=0;
      res=-1;
      for(i=0;i*disk_car->sector_size<count;i++)
      {
	int newres;
	newres=cache_read_aux(disk_car, (count>(i+1)*disk_car->sector_size?disk_car->sector_size:count - i*disk_car->sector_size), (unsigned char*)nom_buffer+i*disk_car->sector_size, offset+i*disk_car->sector_size,0);
	/* If one read succeed, considered that's ok, we are doing data recovery */
	if(newres>=0)
	  res=0;
      }
      return res;
    }
    memcpy(nom_buffer, cache->buffer, count);
#ifdef DEBUG_CACHE
    log_trace("cache_read offset=%llu size=%lu, update cache %u, res=%d\n",
	(long long unsigned)cache->cache_offset,
	(long unsigned)cache->cache_size,
	data->cache_buffer_nbr-1, res);
#endif
    return res;
  }
}

static int cache_write(disk_t *disk_car,const unsigned int count, const void *nom_buffer, const uint64_t offset)
{
  struct cache_struct *data=disk_car->data;
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
  return data->disk_car->write(data->disk_car,count,nom_buffer,offset);
}

static int cache_clean(disk_t *disk_car)
{
  if(disk_car->data)
  {
    struct cache_struct *data=disk_car->data;
    unsigned int i;
#ifdef DEBUG_CACHE
    log_trace("%s\ncache_read total_call=%u, total_count=%llu\n      read total_call=%u, total_count=%llu\n",
	data->disk_car->description(data->disk_car),
	data->nbr_fnct_call, (long long unsigned)data->nbr_fnct_sect,
	data->nbr_read_call, (long long unsigned)data->nbr_read_sect);
#endif
    data->disk_car->clean(data->disk_car);
    for(i=0;i<CACHE_BUFFER_NBR;i++)
    {
      struct cache_buffer_struct *cache=&data->cache[i];
      if(cache->buffer!=NULL)
	free(cache->buffer);
    }
    free(data->disk_car);
    free(disk_car->data);
    disk_car->data=NULL;
  }
  return 0;
}

static int cache_sync(disk_t *disk_car)
{
  struct cache_struct *data=disk_car->data;
  return data->disk_car->sync(data->disk_car);
}

disk_t *new_diskcache(disk_t *disk_car, const unsigned int testdisk_mode)
{
  unsigned int i;
  struct cache_struct*data=MALLOC(sizeof(*data));
  disk_t *new_disk_car=MALLOC(sizeof(*new_disk_car));
  memcpy(new_disk_car,disk_car,sizeof(*new_disk_car));
  data->disk_car=disk_car;
  data->nbr_fnct_sect=0;
  data->nbr_read_sect=0;
  data->nbr_fnct_call=0;
  data->nbr_read_call=0;
  data->cache_buffer_nbr=0;
  if(testdisk_mode&TESTDISK_O_READAHEAD_8K)
    data->cache_size_min=16*512;
  else if(testdisk_mode&TESTDISK_O_READAHEAD_32K)
    data->cache_size_min=64*512;
  else
    data->cache_size_min=0;
  dup_CHS(&new_disk_car->CHS,&disk_car->CHS);
  new_disk_car->disk_size=disk_car->disk_size;
  new_disk_car->disk_real_size=disk_car->disk_real_size;
  new_disk_car->write_used=0;
  new_disk_car->data=data;
  new_disk_car->read=cache_read;
  new_disk_car->write=cache_write;
  new_disk_car->sync=cache_sync;
  new_disk_car->clean=cache_clean;
  new_disk_car->description=cache_description;
  new_disk_car->description_short=cache_description_short;
  new_disk_car->rbuffer=NULL;
  new_disk_car->wbuffer=NULL;
  new_disk_car->rbuffer_size=0;
  new_disk_car->wbuffer_size=0;
  for(i=0;i<CACHE_BUFFER_NBR;i++)
    data->cache[i].buffer=NULL;
  return new_disk_car;
}

static const char *cache_description(disk_t *disk_car)
{
  struct cache_struct *data=disk_car->data;
  dup_CHS(&data->disk_car->CHS,&disk_car->CHS);
  data->disk_car->disk_size=disk_car->disk_size;
  return data->disk_car->description(data->disk_car);
}

static const char *cache_description_short(disk_t *disk_car)
{
  struct cache_struct *data=disk_car->data;
  dup_CHS(&data->disk_car->CHS,&disk_car->CHS);
  data->disk_car->disk_size=disk_car->disk_size;
  return data->disk_car->description_short(data->disk_car);
}
