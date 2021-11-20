/*

    File: psearch.h

    Copyright (C) 2020 Christophe GRENIER <grenier@cgsecurity.org>

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
#ifndef _PSEARCH_H
#define _PSEARCH_H

/*@
  @ requires \valid(data);
  @*/
static inline alloc_data_t *file_add_data(alloc_data_t *data, const uint64_t offset, const unsigned int content)
{
  if(!(data->start <= offset && offset <= data->end))
  {
    log_critical("file_add_data: bug\n");
    return data;
  }
  if(data->start==offset)
  {
    data->data=content;
    return data;
  }
  if(data->data==content)
    return data;
  {
    alloc_data_t *datanext=(alloc_data_t*)MALLOC(sizeof(*datanext));
    memcpy(datanext, data, sizeof(*datanext));
    data->end=offset-1;
    datanext->start=offset;
    datanext->file_stat=NULL;
    datanext->data=content;
    td_list_add(&datanext->list, &data->list);
    return datanext;
  }
}

/*@
  @ requires \valid(dst);
  @ requires \valid_read(src);
  @ requires \separated(dst, src);
  @*/
// assigns  *dst;
static inline void file_recovery_cpy(file_recovery_t *dst, const file_recovery_t *src)
{
  memcpy(dst, src, sizeof(*dst));
  dst->location.list.prev=&dst->location.list;
  dst->location.list.next=&dst->location.list;
}

/* Check if the block looks like an indirect/double-indirect block */
/*@
  @ requires blocksize >= 8;
  @ requires \valid_read(buffer + (0 .. blocksize-1));
  @ assigns \result;
  @*/
static inline int ind_block(const unsigned char *buffer, const unsigned int blocksize)
{
  const uint32_t *p32=(const uint32_t *)buffer;
  unsigned int i;
  unsigned int diff=1;	/* IND: Indirect block */
  if(le32(p32[0])==0)
    return 0;
  if(le32(p32[1])==le32(p32[0])+blocksize/4+1)
    diff=blocksize/4+1;	/* DIND: Double Indirect block */
  /*@
    @ loop assigns i;
    @*/
  for(i=0;i<blocksize/4-1 && le32(p32[i+1])!=0;i++)
  {
    if(le32(p32[i+1])!=le32(p32[i])+diff)
    {
      return 0;
    }
  }
  i++;
  /*@
    @ loop assigns i;
    @*/
  for(;i<blocksize/4 && le32(p32[i])==0;i++);
  if(i<blocksize/4)
  {
    return 0;
  }
  return 1;	/* Ok: ind_block points to non-fragmented block */
}

#endif
