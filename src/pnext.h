/*

    File: pnext.c

    Copyright (C) 2009 Christophe GRENIER <grenier@cgsecurity.org>

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

/* #define DEBUG_GET_NEXT_SECTOR */
static
#ifndef DEBUG_GET_NEXT_SECTOR
inline
#endif
void get_next_header(alloc_data_t *list_search_space, alloc_data_t **current_search_space, uint64_t *offset)
{
#ifdef DEBUG_GET_NEXT_SECTOR
  log_trace(" get_next_header %llu (%llu-%llu)\n",
      (unsigned long long)((*offset)/512),
      (unsigned long long)((*current_search_space)->start/512),
      (unsigned long long)((*current_search_space)->end)/512);
#endif
  if((*current_search_space) != list_search_space)
    *current_search_space=td_list_entry((*current_search_space)->list.next, alloc_data_t, list);
  *offset=(*current_search_space)->start;
}

static
#ifndef DEBUG_GET_NEXT_SECTOR
inline
#endif
void get_next_sector(alloc_data_t *list_search_space, alloc_data_t **current_search_space, uint64_t *offset, const unsigned int blocksize)
{
#ifdef DEBUG_GET_NEXT_SECTOR
  log_debug(" get_next_sector %llu (%llu-%llu)\n",
      (unsigned long long)((*offset)/512),
      (unsigned long long)((*current_search_space)->start/512),
      (unsigned long long)((*current_search_space)->end)/512);
#endif
  if((*current_search_space) == list_search_space)
  {
    return ;
  }
#ifdef DEBUG_GET_NEXT_SECTOR
  if(! ((*current_search_space)->start <= *offset && (*offset)<=(*current_search_space)->end))
  {
    log_critical("BUG: get_next_sector stop everything %llu (%llu-%llu)\n",
        (unsigned long long)((*offset)/512),
        (unsigned long long)((*current_search_space)->start/512),
        (unsigned long long)((*current_search_space)->end/512));
    log_flush();
    log_close();
    exit(1);
  }
#endif
  if((*offset)+blocksize <= (*current_search_space)->end)
    *offset+=blocksize;
  else
    get_next_header(list_search_space, current_search_space, offset);
}

static inline void get_prev_header(alloc_data_t *list_search_space, alloc_data_t **current_search_space, uint64_t *offset, const unsigned int blocksize)
{
  if((*current_search_space) != list_search_space)
    *current_search_space=td_list_entry((*current_search_space)->list.prev, alloc_data_t, list);
  *offset=(*current_search_space)->end + 1 - blocksize;
}

static inline void get_prev_sector(alloc_data_t *list_search_space, alloc_data_t **current_search_space, uint64_t *offset, const unsigned int blocksize)
{
  if((*current_search_space) == list_search_space)
  {
    return ;
  }
  if((*offset) >= (*current_search_space)->start + blocksize)
    *offset-=blocksize;
  else
    get_prev_header(list_search_space, current_search_space, offset, blocksize);
}
