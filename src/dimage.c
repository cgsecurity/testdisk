/*

    File: dimage.c

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

#include <stdio.h>
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <sys/types.h>
#include <fcntl.h>
#include "types.h"
#include "common.h"
#include "intrf.h"
#include "intrfn.h"
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include "log.h"
#include "dimage.h"

#define READ_SIZE 256*512

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif
#ifndef O_BINARY
#define O_BINARY 0
#endif

int disk_image(disk_t *disk_car, const partition_t *partition, const char *image_dd)
{
  int ind_stop=0;
  uint64_t nbr_read_error=0;
  uint64_t offset=partition->part_offset;
  const uint64_t offset_end=partition->part_offset+partition->part_size;
  const uint64_t offset_inc=(offset_end-offset)/100;
  uint64_t offset_next=offset;
  unsigned char *buffer_disk=(unsigned char *)MALLOC(READ_SIZE);
  int disk_dst;
#ifdef HAVE_NCURSES
  WINDOW *window;
#endif
  if((disk_dst=open(image_dd,O_LARGEFILE|O_RDWR|O_BINARY|O_CREAT,0644))<0)
  {
    log_error("Can't create file %s.\n",image_dd);
    display_message("Can't create file!\n");
    free(buffer_disk);
    return -1;
  }
#ifdef HAVE_NCURSES
  window=newwin(0,0,0,0);	/* full screen */
  aff_copy(window);
  wmove(window,5,0);
  wprintw(window,"%s\n",disk_car->description_short(disk_car));
  wmove(window,6,0);
  aff_part(window,AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition);
  wmove(window,22,0);
  wattrset(window, A_REVERSE);
  waddstr(window,"  Stop  ");
  wattroff(window, A_REVERSE);
#endif
  while(ind_stop==0 && offset < offset_end)
  {
    unsigned int readsize=READ_SIZE;
    int update=0;
    if(offset_end-offset < READ_SIZE)
      readsize=offset_end-offset;
    if((unsigned)disk_car->pread(disk_car, buffer_disk, readsize, offset) != readsize)
    {
      update=1;
      nbr_read_error++;
    }
    offset+=READ_SIZE;
    if(offset>offset_next)
    {
      update=1;
      offset_next+=offset_inc;
    }
    if(update)
    {
#ifdef HAVE_NCURSES
      unsigned int i;
      unsigned int percent=(offset-partition->part_offset)*100/partition->part_size;
      wmove(window,7,0);
      wprintw(window,"%3u %% ", percent);
      for(i=0;i<percent*3/5;i++)
	wprintw(window,"=");
      wprintw(window,">");
      wrefresh(window);
      ind_stop=check_enter_key_or_s(window);
#endif
    }
    if(write(disk_dst,buffer_disk,readsize)<0)
    {
      ind_stop=2;
    }
  }
  close(disk_dst);
#ifdef HAVE_NCURSES
  delwin(window);
  (void) clearok(stdscr, TRUE);
#ifdef HAVE_TOUCHWIN
  touchwin(stdscr);
#endif
#endif
  if(ind_stop==2)
  {
    display_message("No space left for the file image.\n");
    free(buffer_disk);
    return -2;
  }
  if(ind_stop)
  {
    if(nbr_read_error==0)
      display_message("Incomplete image created.\n");
    else
      display_message("Incomplete image created: read errors have occured.\n");
    free(buffer_disk);
    return 0;
  }
  if(nbr_read_error==0)
    display_message("Image created successfully.\n");
  else
    display_message("Image created successfully but read errors have occured.\n");
  free(buffer_disk);
  return 0;
}
