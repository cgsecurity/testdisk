/*

    File: swap.c

    Copyright (C) 1998-2006,2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include <stdio.h>
#include "types.h"
#include "common.h"
#include "swap.h"
static void set_Linux_SWAP_info(const union swap_header *swap_header, partition_t *partition);
static int test_Linux_SWAP(const union swap_header *swap_header);

/* Page size can be 4k or 8k */
#define MAX_PAGE_SIZE 8192

int check_Linux_SWAP(disk_t *disk_car, partition_t *partition)
{
  unsigned char *buffer=(unsigned char*)MALLOC(MAX_PAGE_SIZE);
  if(disk_car->pread(disk_car, buffer, MAX_PAGE_SIZE, partition->part_offset) != MAX_PAGE_SIZE)
  {
    free(buffer);
    return 1;
  }
  if(test_Linux_SWAP((union swap_header*)buffer)!=0)
  {
    free(buffer);
    return 1;
  }
  set_Linux_SWAP_info((union swap_header*)buffer,partition);
  free(buffer);
  return 0;
}

static void set_Linux_SWAP_info(const union swap_header *swap_header,partition_t *partition)
{
  partition->fsname[0]='\0';
  if(memcmp(swap_header->magic.magic,"SWAP-SPACE",10)==0)
  {
    partition->upart_type=UP_LINSWAP;
    partition->blocksize=4096;
    snprintf(partition->info, sizeof(partition->info), "SWAP version %u, pagesize=%u",
	le32(swap_header->info.version), partition->blocksize);
  }
  else if(memcmp(swap_header->magic.magic,"SWAPSPACE2",10)==0)
  {
    partition->upart_type=UP_LINSWAP2;
    partition->blocksize=4096;
    snprintf(partition->info, sizeof(partition->info), "SWAP2 version %u, pagesize=%u",
	le32(swap_header->info.version), partition->blocksize);
    /* set_part_name(partition,swap_header->info.volume_name,16); */
  }
  else if(memcmp(swap_header->magic8k.magic,"SWAP-SPACE",10)==0)
  {
    partition->upart_type=UP_LINSWAP_8K;
    partition->blocksize=8192;
    snprintf(partition->info, sizeof(partition->info), "SWAP version %u, pagesize=%u",
	le32(swap_header->info.version), partition->blocksize);
  }
  else if(memcmp(swap_header->magic8k.magic,"SWAPSPACE2",10)==0)
  {
    partition->blocksize=8192;
    if(le32(swap_header->info.version) <= be32(swap_header->info.version))
    {
      partition->upart_type=UP_LINSWAP2_8K;
      snprintf(partition->info, sizeof(partition->info), "SWAP2 version %u, pagesize=%u",
	  le32(swap_header->info.version), partition->blocksize);
    }
    else
    {
      partition->upart_type=UP_LINSWAP2_8KBE;
      snprintf(partition->info, sizeof(partition->info), "SWAP2 version %u, pagesize=%u",
	  (unsigned int)be32(swap_header->info.version), partition->blocksize);
    }
  }
}

static int test_Linux_SWAP(const union swap_header *swap_header)
{
  if( memcmp(swap_header->magic.magic,"SWAP-SPACE",10)==0 ||
      memcmp(swap_header->magic.magic,"SWAPSPACE2",10)==0 ||
      memcmp(swap_header->magic8k.magic,"SWAP-SPACE",10)==0 ||
      memcmp(swap_header->magic8k.magic,"SWAPSPACE2",10)==0)
    return 0;
  return 1;
}

int recover_Linux_SWAP(const union swap_header *swap_header, partition_t *partition)
{
  if(test_Linux_SWAP(swap_header)!=0)
    return 1;
  set_Linux_SWAP_info(swap_header,partition);
  partition->part_type_i386=P_LINSWAP;
  partition->part_type_sun=PSUN_LINSWAP;
  partition->part_type_mac=PMAC_SWAP;
  partition->part_type_gpt=GPT_ENT_TYPE_LINUX_SWAP;
  switch(partition->upart_type)
  {
    case UP_LINSWAP:
      {
	int i;
	for(i=PAGE_SIZE-10-1;i>=0;i--)
	  if(swap_header->magic.reserved[i]!=(char)0)
	    break;
	if(i>=0)
	{
	  int j;
	  for(j=7;j>=0;j--)
	    if((swap_header->magic.reserved[i]&(1<<j))!=(char)0)
	      break;
	  partition->part_size=(uint64_t)(8*i+j+1)*PAGE_SIZE;
	}
	else
	  partition->part_size=PAGE_SIZE;
      }
      break;
    case UP_LINSWAP2:
      if(swap_header->info.last_page==0)
	partition->part_size=PAGE_SIZE;
      else
	partition->part_size=(uint64_t)(le32(swap_header->info.last_page) - 1)*PAGE_SIZE;
      break;
    case UP_LINSWAP_8K:
      {
	int i;
	for(i=PAGE_8K - 10 - 1; i>=0; i--)
	  if(swap_header->magic8k.reserved[i]!=(char)0)
	    break;
	if(i>=0)
	{
	  int j;
	  for(j=7;j>=0;j--)
	    if((swap_header->magic8k.reserved[i]&(1<<j))!=(char)0)
	      break;
	  partition->part_size=(uint64_t)(8*i+j+1)*PAGE_8K;
	}
	else
	  partition->part_size=PAGE_8K;
      }
      break;
    case UP_LINSWAP2_8K:
      if(swap_header->info.last_page==0)
	partition->part_size=PAGE_8K;
      else
	partition->part_size=(uint64_t)(le32(swap_header->info.last_page) - 1)*PAGE_8K;
      break;
    case UP_LINSWAP2_8KBE:
      if(swap_header->info.last_page==0)
	partition->part_size=PAGE_8K;
      else
	partition->part_size=(uint64_t)(be32(swap_header->info.last_page) - 1)*PAGE_8K;
      break;
    default:
      return 1;
  }
  return 0;
}
