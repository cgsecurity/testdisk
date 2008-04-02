/*

    File: ntfsp.c

    Copyright (C) 2007-2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifdef HAVE_ICONV_H
#include <iconv.h>
#endif
#include "types.h"
#include "common.h"
#include "list.h"
#include "filegen.h"
#ifdef HAVE_LIBNTFS
#include <ntfs/attrib.h>
#include "ntfsp.h"
#endif
#include "intrf.h"
#include "intrfn.h"
#include "dir.h"
#include "ntfs.h"
#include "ntfs_dir.h"
#include "ntfs_inc.h"
#include "log.h"

#ifdef HAVE_LIBNTFS
#define SIZEOF_BUFFER ((const unsigned int)512)

unsigned int ntfs_remove_used_space(disk_t *disk_car,const partition_t *partition, alloc_data_t *list_search_space)
{
  dir_data_t dir_data;
  unsigned int res;
  switch(dir_partition_ntfs_init(disk_car,partition,&dir_data,0))
  {
    case -2:
    case -1:
      screen_buffer_to_log();
      {
#ifdef HAVE_NCURSES
	WINDOW *window;
	window=newwin(0,0,0,0);	/* full screen */
	aff_copy(window);
	wmove(window,4,0);
	aff_part(window,AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition);
#endif
	log_partition(disk_car,partition);
	screen_buffer_add("Can't open filesystem. Filesystem seems damaged.\n");
	screen_buffer_to_log();
#ifdef HAVE_NCURSES
	screen_buffer_display(window,"",NULL);
	delwin(window);
	(void) clearok(stdscr, TRUE);
#ifdef HAVE_TOUCHWIN
	touchwin(stdscr);
#endif
#endif
      }
      return 0;
  }
  {
    struct ntfs_dir_struct *ls=(struct ntfs_dir_struct *)dir_data.private_dir_data;
    unsigned char *buffer;
    uint64_t start_free=0;
    uint64_t end_free=0;
    unsigned long int lcn;
    unsigned long int no_of_cluster;
    unsigned int cluster_size;
    unsigned int sector_size;
    log_trace("ntfs_remove_used_space\n");
    buffer=(unsigned char *)MALLOC(SIZEOF_BUFFER);
    {
      const struct ntfs_boot_sector*ntfs_header=(const struct ntfs_boot_sector*)buffer;
      if(disk_car->read(disk_car,512, buffer, partition->part_offset)!=0)
      {
	free(buffer);
	return 0;
      }
      no_of_cluster=le64(ntfs_header->sectors_nbr)/ntfs_header->sectors_per_cluster;
      cluster_size=ntfs_header->sectors_per_cluster;
      sector_size=ntfs_sector_size(ntfs_header);
      res=cluster_size * sector_size;
    }
    for(lcn=0;lcn<no_of_cluster;lcn++)
    {
      static long long int bmplcn = -SIZEOF_BUFFER - 1;	/* Which bit of $Bitmap is in the buffer */
      int byte, bit;
      if ((lcn < bmplcn) || (lcn >= (bmplcn + (SIZEOF_BUFFER << 3))))
      {
	ntfs_attr *attr;
	/* Mark the buffer as not in use, in case the read is shorter. */
	memset(buffer, 0x00, SIZEOF_BUFFER);
	bmplcn = lcn & (~((SIZEOF_BUFFER << 3) - 1));
	attr = ntfs_attr_open(ls->vol->lcnbmp_ni, AT_DATA, AT_UNNAMED, 0);
	if(attr)
	{
	  if (ntfs_attr_pread(attr, (bmplcn>>3), SIZEOF_BUFFER, buffer) < 0)
	  {
	    log_error("Couldn't read $Bitmap\n");
	  }
	  ntfs_attr_close(attr);
	}
	else
	{
	  log_error("Couldn't open $Bitmap\n");
	}
      }

      bit  = 1 << (lcn & 7);
      byte = (lcn >> 3) & (SIZEOF_BUFFER - 1);
      if((buffer[byte] & bit)!=0)
      {
	/* Not free */
	if(end_free+1==partition->part_offset+(uint64_t)lcn*cluster_size*sector_size)
	  end_free+=cluster_size*sector_size;
	else
	{
	  if(start_free != end_free)
	    del_search_space(list_search_space, start_free, end_free);
	  start_free=partition->part_offset+(uint64_t)lcn*cluster_size*sector_size;
	  end_free=start_free+(uint64_t)cluster_size*sector_size-1;
	}
      }
    }
    free(buffer);
    if(start_free != end_free)
      del_search_space(list_search_space, start_free, end_free);
    dir_data.close(&dir_data);
    return cluster_size * sector_size;
  }
}
#endif
