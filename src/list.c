/*

    File: list.c

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
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include "types.h"
#include "common.h"
#include "list.h"
#include "log.h"

/* #define DEBUG_LIST_APPEND_BLOCK */
void list_append_block(alloc_list_t *list, const uint64_t offset, const uint64_t blocksize, const unsigned int data)
{
  alloc_list_t *prev;
#ifdef DEBUG_LIST_APPEND_BLOCK
  log_debug("list_append_block([");
  for(prev=list;prev!=NULL;prev=prev->next)
  {
    log_debug("%llu-%llu", (long long unsigned)prev->start, (long long unsigned)prev->end);
  }
  log_debug("], %llu, %llu, %d)\n", (long long unsigned)offset,
      (long long unsigned) blocksize, data);
#endif
  if(list!=NULL && list->end==0)
  { /* Use preallocated list */
    list->start=offset;
    list->end=offset+blocksize-1;
    list->prev=NULL;
    list->next=NULL;
    list->data=data;
    return ;
  }
  for(prev=list;prev!=NULL && prev->next!=NULL; prev=prev->next);
  if(prev!=NULL && prev->end+1==offset && prev->data==data)
  {
    prev->end=offset+blocksize-1;
    return ;
  }
  {
    alloc_list_t *new_list=(alloc_list_t *)MALLOC(sizeof(*new_list));
    new_list->start=offset;
    new_list->end=offset+blocksize-1;
    new_list->prev=prev;
    new_list->next=(prev!=NULL?prev->next:NULL);
    new_list->data=data;
    if(prev!=NULL)
      prev->next=new_list;
    if(new_list->next!=NULL)
      new_list->next->prev=new_list;
  }
}

void list_truncate(alloc_list_t *list, uint64_t size)
{
  alloc_list_t *element;
  uint64_t file_size=0;
  /* uint64_t file_size_on_disk=0; */
  for(element=list;element!=NULL;element=element->next)
  {
    /* file_size_on_disk+=(element->end-element->start+1); */
    if(element->data>0)
    {
      file_size+=(element->end-element->start+1);
      if(file_size>=size)
      {
	element->end-=(file_size-size);
	td_list_delete(element->next);
//	element->next=NULL;	already done by td_list_delete
      }
    }
  }
}

void td_list_delete(alloc_list_t *list)
{
  alloc_list_t *next;
  if(list!=NULL && list->prev!=NULL)
    list->prev->next=NULL;
  for(;list!=NULL;list=next)
  {
    next=list->next;
    free(list);
  }
}
