/*

    File: file_found.c

    Copyright (C) 1998-2009 Christophe GRENIER <grenier@cgsecurity.org>

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
#include "intrf.h"
#ifdef HAVE_NCURSES
#include "intrfn.h"
#endif
#include "dir.h"
#include "list.h"
#include "lang.h"
#include "filegen.h"
#include "file_found.h"

alloc_data_t *file_found(alloc_data_t *current_search_space, const uint64_t offset, file_stat_t *file_stat)
{
  if(current_search_space==NULL)
    return current_search_space;
  if(current_search_space->start == offset)
  {
    current_search_space->file_stat=file_stat;
    current_search_space->data=1;
    return current_search_space;
  }
  if(current_search_space->start < offset && offset <= current_search_space->end)
  {
    alloc_data_t *next_search_space;
    next_search_space=(alloc_data_t*)MALLOC(sizeof(*next_search_space));
    memcpy(next_search_space, current_search_space, sizeof(*next_search_space));
    current_search_space->end=offset-1;
    next_search_space->start=offset;
    next_search_space->file_stat=file_stat;
    next_search_space->data=1;
    td_list_add(&next_search_space->list, &current_search_space->list);
    return next_search_space;
  }
  return current_search_space;
}
