/*

    File: list.c

    Copyright (C) 2006-2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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

void list_truncate(alloc_list_t *list, const uint64_t file_size)
{
  struct td_list_head *tmp;
  struct td_list_head *next;
  uint64_t size=0;
  td_list_for_each_safe(tmp, next, &list->list)
  {
    alloc_list_t *element=td_list_entry(tmp, alloc_list_t, list);
    if(size>=file_size)
    {
      td_list_del(tmp);
      free(element);
    }
    else if(element->data>0)
    {
      size+=(element->end-element->start+1);
      if(size>=file_size)
	element->end-=(size-file_size);
    }
  }
}
