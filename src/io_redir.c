/*

    File: io_redir.c

    Copyright (C) 1998-2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include <errno.h>
#include "types.h"
#include "common.h"
#include "fnctdsk.h"
#include "io_redir.h"
#include "log.h"

//#define DEBUG_IO_REDIR 1

typedef struct struclist_redir_t list_redir_t;
struct struclist_redir_t
{
  uint64_t org_offset;
  uint64_t new_offset;
  unsigned int size;
  const void *mem;
  list_redir_t *prev;
  list_redir_t *next;
};

struct info_io_redir
{
  disk_t *disk_car;
  list_redir_t *list_redir;
};

static int io_redir_read(disk_t *disk_car,const unsigned int count, void *nom_buffer, const uint64_t offset);
static int io_redir_clean(disk_t *clean);

int io_redir_add_redir(disk_t *disk_car, const uint64_t org_offset, const unsigned int size, const uint64_t new_offset, const void *mem)
{
  if(disk_car->read!=io_redir_read)
  {
    struct info_io_redir*data=MALLOC(sizeof(*data));
    disk_t *old_disk_car=MALLOC(sizeof(*old_disk_car));
#ifdef DEBUG_IO_REDIR
    log_trace("io_redir_add_redir: install functions\n");
#endif
    memcpy(old_disk_car,disk_car,sizeof(*old_disk_car));
    data->disk_car=old_disk_car;
    data->list_redir=NULL;
    disk_car->write_used=0;
    disk_car->data=data;
    disk_car->description=old_disk_car->description;
    disk_car->write=old_disk_car->write;
    disk_car->read=io_redir_read;
    disk_car->clean=io_redir_clean;
  }
  {
    struct info_io_redir *data=disk_car->data;
    list_redir_t *prev_redir=NULL;
    list_redir_t *current_redir;
    for(current_redir=data->list_redir;(current_redir!=NULL) && org_offset<current_redir->org_offset+current_redir->size;current_redir=current_redir->next)
      prev_redir=current_redir;
    if(current_redir!=NULL && org_offset>=current_redir->org_offset)
    {
      log_critical("io_redir_add_redir failed: already redirected\n");
      return 1;
    }
    {
      list_redir_t *new_redir;
#ifdef DEBUG_IO_REDIR
      log_trace("io_redir_add_redir: add redirection\n");
#endif
      new_redir=(list_redir_t*)MALLOC(sizeof(*new_redir));
      new_redir->org_offset=org_offset;
      new_redir->size=size;
      new_redir->new_offset=new_offset;
      new_redir->mem=mem;
      new_redir->next=current_redir;
      if(prev_redir!=NULL)
	prev_redir->next=new_redir;
      else
	data->list_redir=new_redir;
    }
  }
  return 0;
}

int io_redir_del_redir(disk_t *disk_car, uint64_t org_offset)
{
  if(disk_car->read!=io_redir_read)
  {
    log_critical("io_redir_del_redir: BUG, no redirection present.\n");
    return 1;
  }
  {
    struct info_io_redir *data=disk_car->data;
    list_redir_t *current_redir;
    for(current_redir=data->list_redir;(current_redir!=NULL) && org_offset!=current_redir->org_offset;current_redir=current_redir->next);
    if(current_redir!=NULL)
    {
#ifdef DEBUG_IO_REDIR
      log_trace("io_redir_del_redir: remove redirection\n");
#endif
      if(current_redir->prev!=NULL)
	current_redir->prev->next=current_redir->next;
      if(current_redir->next!=NULL)
	current_redir->next->prev=current_redir->prev;
      if(data->list_redir==current_redir)
	data->list_redir=current_redir->next;
      free(current_redir);
      if(data->list_redir==NULL)
      {
#ifdef DEBUG_IO_REDIR
	log_trace("io_redir_del_redir: uninstall functions\n");
#endif
	memcpy(disk_car,data->disk_car,sizeof(*disk_car));
	free(data->disk_car);
	free(data);
      }
      return 0;
    }
    log_trace("io_redir_del_redir: redirection not found\n");
    return 1;
  }
}

static int io_redir_read(disk_t *disk_car,const unsigned int count, void *buffer, const uint64_t offset)
{
  struct info_io_redir *data=disk_car->data;
  uint64_t current_offset=offset;
  unsigned int current_count=count;
  int res=0;
  list_redir_t *current_redir;
#ifdef DEBUG_IO_REDIR
  log_trace("io_redir_read: offset=%llu count=%u\n",(long long unsigned) offset, count);
#endif
  while(current_count!=0)
  {
    unsigned int read_size;
    for(current_redir=data->list_redir;(current_redir!=NULL) && 
      !(current_redir->org_offset<=offset && offset<current_redir->org_offset+current_redir->size);
      current_redir=current_redir->next);
    if(current_redir!=NULL)
    {
      if(current_redir->org_offset>current_offset)
      {
	/* Read data before redirection */
	read_size=current_redir->org_offset-current_offset;
#ifdef DEBUG_IO_REDIR
	log_trace("io_redir_read: read %u bytes before redirection\n",read_size);
#endif
	res|=data->disk_car->read(data->disk_car,read_size,buffer,current_offset);
	current_count-=read_size;
	current_offset+=read_size;
	buffer=(unsigned char*)buffer+read_size;
      }
      /* Redirection */
      read_size=(current_count>current_redir->size?current_redir->size:current_count);
      if(current_redir->mem!=NULL)
      {
#ifdef DEBUG_IO_REDIR
	log_trace("io_redir_read: copy %u bytes from memory\n",read_size);
#endif
	memcpy(buffer, (const unsigned char*)current_redir->mem + current_offset - current_redir->org_offset, read_size);
      }
      else
      {
#ifdef DEBUG_IO_REDIR
	log_trace("io_redir_read: read %u from another position\n",read_size);
#endif
	res|=data->disk_car->read(data->disk_car, read_size, buffer,
	    current_redir->new_offset + current_offset - current_redir->org_offset);
      }
    }
    else
    {
      read_size=current_count;
#ifdef DEBUG_IO_REDIR
      log_trace("io_redir_read: normal read of %u bytes\n",read_size);
#endif
      res|=data->disk_car->read(data->disk_car,read_size,buffer,current_offset);
    }
    if(res!=0)
      return res;
    current_count-=read_size;
    current_offset+=read_size;
    buffer=(unsigned char*)buffer+read_size;
  }
  return 0;
}

static int io_redir_clean(disk_t *disk_car)
{
  if(disk_car->data)
  {
    struct info_io_redir *data=disk_car->data;
    data->disk_car->clean(data->disk_car);
    free(data->disk_car);
    free(disk_car->data);
    disk_car->data=NULL;
  }
  return 0;
}

