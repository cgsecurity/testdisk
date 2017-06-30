/*

    File: next.c

    Copyright (C) 2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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
/*
   Instead of incrementing the sector number by one and checking if its value
   is aligned to a cylinder (PC) or similar boundary, return the next
   sector number that will be aligned to such boundary.
*/
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
 
#include "types.h"
#include "common.h"
#include "ext2.h"
#include "next.h"
extern const arch_fnct_t arch_i386;
extern const arch_fnct_t arch_mac;
extern const arch_fnct_t arch_none;
extern const arch_fnct_t arch_sun;

struct search_location
{
  uint64_t offset;
  uint64_t inc;
};
typedef struct search_location search_location_t;
static inline uint64_t CHS_to_offset(const unsigned int C, const int H, const int S,const disk_t *disk_car);

#define SEARCH_LOCATION_MAX 256
static unsigned int search_location_nbr=0;
static search_location_t search_location_info[SEARCH_LOCATION_MAX+1];

static inline uint64_t CHS_to_offset(const unsigned int C, const int H, const int S,const disk_t *disk_car)
{
  return (((uint64_t)C * disk_car->geom.heads_per_cylinder + H) * disk_car->geom.sectors_per_head +(S>0?S-1:S))*disk_car->sector_size;
}

static void update_location(void)
{
  unsigned int i;
  const search_location_t *src=&search_location_info[search_location_nbr];
  if(src->inc==0)
  {
    for(i=0; i<search_location_nbr; i++)
    {
      if(search_location_info[i].offset == src->offset)
	return ;
    }
    if(search_location_nbr < SEARCH_LOCATION_MAX)
      search_location_nbr++;
    return;
  }
  for(i=0; i<search_location_nbr; i++)
  {
    search_location_t *cur=&search_location_info[i];
    if(cur->offset == src->offset &&
	cur->inc >= src->inc &&
	cur->inc % src->inc==0)
    {
      cur->inc=src->inc;
      return ;
    }
    if(cur->inc == 0)
    {
      if(cur->offset == src->offset)
      {
	cur->inc = src->inc;
	return ;
      }
    }
    else
    {
      if(cur->offset == src->offset &&
	  src->inc >= cur->inc && src->inc % cur->inc==0)
	return ;
      if(cur->inc==src->inc &&
	  cur->offset >= src->offset &&
	  (cur->offset - src->offset)%cur->inc==0)
      {
	cur->offset=src->offset;
	return ;
      }
      if(cur->inc==src->inc &&
	  src->offset >= cur->offset &&
	  (src->offset - cur->offset)%cur->inc==0)
	return ;
    }
  }
  if(search_location_nbr < SEARCH_LOCATION_MAX)
    search_location_nbr++;
}

void search_location_init(const disk_t *disk_car, const unsigned int location_boundary, const int fast_mode)
{
  /* test_nbr==1... */
  if(disk_car->arch==&arch_i386)
  {
    if(fast_mode>1)
    {
      search_location_info[search_location_nbr].offset=CHS_to_offset(0,0,1,disk_car);
      search_location_info[search_location_nbr].inc= CHS_to_offset(0,1,0,disk_car);
      update_location();
    }
    else
    {
      //CHS H=0,1,2 S=1
      search_location_info[search_location_nbr].offset=CHS_to_offset(0,0,1,disk_car);
      search_location_info[search_location_nbr].inc=CHS_to_offset(1,0,0,disk_car);
      update_location();
      search_location_info[search_location_nbr].offset=CHS_to_offset(0,1,1,disk_car);
      search_location_info[search_location_nbr].inc=CHS_to_offset(1,0,0,disk_car);
      update_location();
      search_location_info[search_location_nbr].offset=CHS_to_offset(0,2,1,disk_car);
      search_location_info[search_location_nbr].inc=CHS_to_offset(1,0,0,disk_car);
    }
    search_location_info[search_location_nbr].offset=0;
    search_location_info[search_location_nbr].inc=2048*512;
    update_location();
  }
  else
  {
    search_location_info[search_location_nbr].offset=0;
    search_location_info[search_location_nbr].inc=location_boundary;
    update_location();
  }
  if(fast_mode>0)
  {
    /* test_nbr==2 FAT32 backup boot sector */
    if(disk_car->arch==&arch_i386)
    {
      //CHS H=0,1,2 S=7
      search_location_info[search_location_nbr].offset=CHS_to_offset(0,0,7,disk_car);
      search_location_info[search_location_nbr].inc=CHS_to_offset(1,0,0,disk_car);
      update_location();
      search_location_info[search_location_nbr].offset=CHS_to_offset(0,1,7,disk_car);
      search_location_info[search_location_nbr].inc=CHS_to_offset(1,0,0,disk_car);
      update_location();
      search_location_info[search_location_nbr].offset=CHS_to_offset(0,2,7,disk_car);
      search_location_info[search_location_nbr].inc=CHS_to_offset(1,0,0,disk_car);
      update_location();
    }
    else
    {
      search_location_info[search_location_nbr].offset=CHS_to_offset(0,0,7,disk_car);
      search_location_info[search_location_nbr].inc=location_boundary;
      update_location();
    }
    search_location_info[search_location_nbr].offset=CHS_to_offset(0,0,7,disk_car);
    search_location_info[search_location_nbr].inc=2048*512;
    update_location();
    /* test_nbr==3 ou test_nbr==4, NTFS or HFS backup boot sector */
    if(disk_car->arch==&arch_i386)
    {
      search_location_info[search_location_nbr].offset=CHS_to_offset(1,0,-1,disk_car);
      search_location_info[search_location_nbr].inc=CHS_to_offset(1,0,0,disk_car);
      update_location();
    }
    else
    {
      search_location_info[search_location_nbr].offset=location_boundary-512;
      search_location_info[search_location_nbr].inc=location_boundary;
      update_location();
    }
    search_location_info[search_location_nbr].offset=(2048-1)*512;
    search_location_info[search_location_nbr].inc=2048*512;
    update_location();
    /* test_nbr==5*/
    {
      int s_log_block_size;
      for(s_log_block_size=0;s_log_block_size<=2;s_log_block_size++)
      {
	const uint64_t hd_offset=3*(EXT2_MIN_BLOCK_SIZE<<s_log_block_size)*8*(EXT2_MIN_BLOCK_SIZE<<s_log_block_size)+(s_log_block_size==0?2*DEFAULT_SECTOR_SIZE:0);
	if(disk_car->arch==&arch_i386)
	{
	  search_location_info[search_location_nbr].offset=CHS_to_offset(0,0,1,disk_car)+hd_offset;
	  search_location_info[search_location_nbr].inc=CHS_to_offset(1,0,0,disk_car);
	  update_location();
	  search_location_info[search_location_nbr].offset=CHS_to_offset(0,1,1,disk_car)+hd_offset;
	  search_location_info[search_location_nbr].inc=CHS_to_offset(1,0,0,disk_car);
	  update_location();
	  search_location_info[search_location_nbr].offset=CHS_to_offset(0,2,1,disk_car)+hd_offset;
	  search_location_info[search_location_nbr].inc=CHS_to_offset(1,0,0,disk_car);
	  update_location();
	}
	else
	{
	  search_location_info[search_location_nbr].offset=CHS_to_offset(0,0,1,disk_car)+hd_offset;
	  search_location_info[search_location_nbr].inc=location_boundary;
	  update_location();
	}
      }
    }
  }
}

uint64_t search_location_update(const uint64_t location)
{
  unsigned int i;
  uint64_t min=(uint64_t)-1;
  for(i=0;i<search_location_nbr;i++)
  {
    while(search_location_info[i].offset<=location)
      search_location_info[i].offset+=search_location_info[i].inc;
    if(min>search_location_info[i].offset)
      min=search_location_info[i].offset;
  }
  return min;
}

