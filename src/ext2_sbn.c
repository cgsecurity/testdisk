/*

    File: ext2_sbn.c

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
#include "types.h"
#include "common.h"
#include "intrf.h"
#include "intrfn.h"
#include "fnctdsk.h"
#include "log.h"
#include "lang.h"
#include "ext2.h"
#include "ext2_sbn.h"

// blocksize=1024, 2048, 4096, 65536
// blocks per blocksgroup=8*blocksize
static const  uint64_t group_size[4]={
  (EXT2_MIN_BLOCK_SIZE<<0)*8*(EXT2_MIN_BLOCK_SIZE<<0),
  (EXT2_MIN_BLOCK_SIZE<<1)*8*(EXT2_MIN_BLOCK_SIZE<<1),
  (EXT2_MIN_BLOCK_SIZE<<2)*8*(EXT2_MIN_BLOCK_SIZE<<2),
  (uint64_t)(EXT2_MIN_BLOCK_SIZE<<6)*8*(EXT2_MIN_BLOCK_SIZE<<6),
};
static const  uint64_t factors[3]={3,5,7};

static uint64_t next_sb(const uint64_t hd_offset_old)
{
  uint64_t hd_offset=0;
  int j;
  for(j=0; j<4; j++)
  {
    int i;
    const uint64_t offset=(j==0?2*512:0);
    for(i=0; i<3; i++)
    {
      uint64_t val;
      for(val=1; val * group_size[j] + offset <= hd_offset_old; val*=factors[i])
	;
      if(hd_offset==0 || val * group_size[j] + offset < hd_offset)
	hd_offset=val* group_size[j] + offset;
    }
  }
  if(hd_offset_old < EXT2_MIN_BLOCK_SIZE<<0 && EXT2_MIN_BLOCK_SIZE<<0 < hd_offset)
    hd_offset=EXT2_MIN_BLOCK_SIZE<<0;
  else if(hd_offset_old < EXT2_MIN_BLOCK_SIZE<<1 && EXT2_MIN_BLOCK_SIZE<<1 < hd_offset)
    hd_offset=EXT2_MIN_BLOCK_SIZE<<1;
  else if(hd_offset_old < EXT2_MIN_BLOCK_SIZE<<2 && EXT2_MIN_BLOCK_SIZE<<2 < hd_offset)
    hd_offset=EXT2_MIN_BLOCK_SIZE<<2;
  else if(hd_offset_old < EXT2_MIN_BLOCK_SIZE<<6 && EXT2_MIN_BLOCK_SIZE<<6 < hd_offset)
    hd_offset=EXT2_MIN_BLOCK_SIZE<<6;
  return hd_offset;
}

list_part_t *search_superblock(disk_t *disk_car, partition_t *partition, const int verbose, const int dump_ind)
{
  unsigned char *buffer=(unsigned char *)MALLOC(2*0x200);
  uint64_t hd_offset;
  int nbr_sb=0;
  list_part_t *list_part=NULL;
  int ind_stop=0;
#ifdef HAVE_NCURSES
  unsigned long int old_percent=0;
#endif
  struct ext2_super_block *sb=(struct ext2_super_block *)buffer;
  partition_t *new_partition=partition_new(disk_car->arch);
  log_trace("search_superblock\n");
#ifdef HAVE_NCURSES
  aff_copy(stdscr);
  wmove(stdscr,4,0);
  wprintw(stdscr,"%s",disk_car->description(disk_car));
  mvwaddstr(stdscr,5,0,msg_PART_HEADER_LONG);
  wmove(stdscr,6,0);
  aff_part(stdscr,AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition);
  wmove(stdscr,22,0);
  wattrset(stdscr, A_REVERSE);
  waddstr(stdscr,"  Stop  ");
  wattroff(stdscr, A_REVERSE);
#endif
  for(hd_offset=0;
      hd_offset<partition->part_size && nbr_sb<10 && ind_stop==0;
      hd_offset=next_sb(hd_offset))
  {
#ifdef HAVE_NCURSES
    const unsigned long int percent=hd_offset*100/partition->part_size;
    if(percent!=old_percent)
    {
      wmove(stdscr,9,0);
      wclrtoeol(stdscr);
      wprintw(stdscr, "Search ext2/ext3/ext4 superblock %10lu/%lu %lu%%",
	  (long unsigned)(hd_offset/disk_car->sector_size),
	  (long unsigned)(partition->part_size/disk_car->sector_size),
	  percent);
      wrefresh(stdscr);
      ind_stop|=check_enter_key_or_s(stdscr);
      old_percent=percent;
    }
#endif
    if(disk_car->pread(disk_car, buffer, 1024, partition->part_offset + hd_offset) == 1024)
    {
      /* ext2/ext3/ext4 */
      if(le16(sb->s_magic)==EXT2_SUPER_MAGIC)
      {
	dup_partition_t(new_partition,partition);
	new_partition->part_offset+=hd_offset;
	if(recover_EXT2(disk_car,sb,new_partition,verbose,dump_ind)==0)
	{
	  int insert_error=0;
	  if(hd_offset<=(EXT2_MIN_BLOCK_SIZE<<2))
	    new_partition->part_offset-=hd_offset;
	  if(partition->blocksize==0)
	  {
	    partition->sborg_offset=new_partition->sborg_offset;
	    partition->sb_offset   =new_partition->sb_offset;
	    partition->sb_size     =new_partition->sb_size;
	    partition->blocksize   =new_partition->blocksize;
	  }
	  log_info("Ext2 superblock found at sector %llu (block=%llu, blocksize=%u)\n",
	      (long long unsigned) hd_offset/DEFAULT_SECTOR_SIZE,
	      (long long unsigned) hd_offset>>(EXT2_MIN_BLOCK_LOG_SIZE+le32(sb->s_log_block_size)),
	      (unsigned int)EXT2_MIN_BLOCK_SIZE<<le32(sb->s_log_block_size));
#ifdef HAVE_NCURSES
	  wmove(stdscr,10+nbr_sb,0);
	  wprintw(stdscr,"Ext2 superblock found at sector %llu (block=%llu, blocksize=%u)        \n",
	      (long long unsigned) hd_offset/DEFAULT_SECTOR_SIZE,
	      (long long unsigned) hd_offset>>(EXT2_MIN_BLOCK_LOG_SIZE+le32(sb->s_log_block_size)),
	      EXT2_MIN_BLOCK_SIZE<<le32(sb->s_log_block_size));
#endif
	  list_part=insert_new_partition(list_part, new_partition, 1, &insert_error);
	  new_partition=partition_new(disk_car->arch);
	  nbr_sb++;
	}
      }
    }
  }
  free(new_partition);
  free(buffer);
  return list_part;
}

