/*

    File: dimage.c

    Copyright (C) 2007-2009 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#include <fcntl.h>
#include "types.h"
#include "common.h"
#include "intrf.h"
#include "intrfn.h"
#include "log.h"
#include "dimage.h"


#define READ_SIZE 256*512
/* Skip 10Mb when there is a read error */
#define SKIP_SIZE 10*1024*1024

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif
#ifndef O_BINARY
#define O_BINARY 0
#endif

static void disk_image_backward(int disk_dst, disk_t *disk, const uint64_t src_offset_start, const uint64_t src_offset_end, uint64_t dst_offset)
{
  uint64_t src_offset;
  unsigned char *buffer=(unsigned char *)MALLOC(disk->sector_size);
  for(src_offset=src_offset_end-disk->sector_size; src_offset > src_offset_start; src_offset-=disk->sector_size, dst_offset-=disk->sector_size)
  {
    const ssize_t pread_res=disk->pread(disk, buffer, disk->sector_size, src_offset);
    if((unsigned)pread_res != disk->sector_size)
    {
      free(buffer);
      return;
    }
#if defined(HAVE_PWRITE)
    if(pwrite(disk_dst, buffer, pread_res, src_offset)<0)
    {
      free(buffer);
      return;
    }
#else
    if(lseek(disk_dst, src_offset, SEEK_SET)<0)
    {
      free(buffer);
      return;
    }
    if(write(disk_dst, buffer, pread_res) != pread_res)
    {
      free(buffer);
      return;
    }
#endif
  }
  free(buffer);
}

int disk_image(disk_t *disk, const partition_t *partition, const char *image_dd)
{
  int ind_stop=0;
  uint64_t nbr_read_error=0;
  uint64_t src_offset=partition->part_offset;
  uint64_t src_offset_old;
  uint64_t dst_offset=0;
  const uint64_t src_offset_end=partition->part_offset+partition->part_size;
  const uint64_t offset_inc=(src_offset_end-src_offset)/10000;
  uint64_t src_offset_next=src_offset;
  struct stat stat_buf;
  unsigned char *buffer=(unsigned char *)MALLOC(READ_SIZE);
  unsigned int readsize=READ_SIZE;
  int disk_dst;
#ifdef HAVE_NCURSES
  WINDOW *window;
#endif
  if((disk_dst=open(image_dd, O_CREAT|O_LARGEFILE|O_RDWR|O_BINARY, 0644)) < 0)
  {
    log_error("Can't create file %s.\n",image_dd);
    display_message("Can't create file!\n");
    free(buffer);
    return -1;
  }
  if(fstat(disk_dst, &stat_buf)==0)
  {
    int res=1;
#ifdef HAVE_NCURSES
    if(stat_buf.st_size > 0)
      res=ask_confirmation("Append to existing file ? (Y/N)");
#endif
    if(res>0)
    {
      dst_offset=stat_buf.st_size;
      src_offset+=dst_offset;
    }
  }
  src_offset_old=src_offset;
#ifdef HAVE_NCURSES
  window=newwin(LINES, COLS, 0, 0);	/* full screen */
  aff_copy(window);
  wmove(window,5,0);
  wprintw(window,"%s\n",disk->description_short(disk));
  wmove(window,6,0);
  aff_part(window,AFF_PART_ORDER|AFF_PART_STATUS,disk,partition);
  wmove(window,10,0);
  waddstr(window, "Disk images are mainly used ");
  wmove(window,11,0);
  waddstr(window, "- for forensics purpose");
  wmove(window,12,0);
  waddstr(window, "- or to deal with media with bad sectors");
#ifdef WIN32
  wmove(window,14,0);
  waddstr(window, "To use TestDisk or PhotoRec with this disk image, go in command line and run");
  wmove(window,15,0);
  waddstr(window, "   testdisk_win.exe image.dd");
  wmove(window,16,0);
  waddstr(window, "or photorec_win.exe image.dd");
#else
  wmove(window,14,0);
  waddstr(window, "To use TestDisk or PhotoRec with this disk image, start a Terminal and run");
  wmove(window,15,0);
  waddstr(window, "   testdisk image.dd");
  wmove(window,16,0);
  waddstr(window, "or photorec image.dd");
#endif
  wmove(window,22,0);
  wattrset(window, A_REVERSE);
  waddstr(window,"  Stop  ");
  wattroff(window, A_REVERSE);
#endif
  while(ind_stop==0 && src_offset < src_offset_end)
  {
    ssize_t pread_res;
    int update=0;
    if(src_offset_end-src_offset < readsize)
      readsize=src_offset_end-src_offset;
    pread_res=disk->pread(disk, buffer, readsize, src_offset);
    if(pread_res > 0)
    {
#if defined(HAVE_PWRITE)
      if(pwrite(disk_dst, buffer, pread_res, dst_offset)<0)
      {
	ind_stop=2;
      }
#else
      if(lseek(disk_dst, dst_offset, SEEK_SET)<0)
      {
	ind_stop=2;
      }
      if(write(disk_dst, buffer, pread_res) != pread_res)
      {
	ind_stop=2;
      }
#endif
      if(src_offset_old + SKIP_SIZE==src_offset)
      {
	disk_image_backward(disk_dst, disk, src_offset_old, src_offset, dst_offset);
      }
    }
    src_offset_old=src_offset;
    if((unsigned)pread_res == readsize)
    {
      src_offset+=readsize;
      dst_offset+=readsize;
      readsize=READ_SIZE;
    }
    else
    {
      update=1;
      nbr_read_error++;
      readsize=disk->sector_size;
      src_offset+=SKIP_SIZE;
      dst_offset+=SKIP_SIZE;
    }
    if(src_offset>src_offset_next)
    {
      update=1;
      src_offset_next=src_offset+offset_inc;
    }
    if(update)
    {
#ifdef HAVE_NCURSES
      unsigned int i;
      const float percent=(src_offset-partition->part_offset)*100.00/partition->part_size;
      wmove(window,7,0);
      wprintw(window,"%3.2f %% ", percent);
      for(i=0;i<percent*3/5;i++)
	wprintw(window,"=");
      wprintw(window,">");
      wrefresh(window);
      ind_stop=check_enter_key_or_s(window);
#endif
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
    free(buffer);
    return -2;
  }
  if(ind_stop)
  {
    if(nbr_read_error==0)
      display_message("Incomplete image created.\n");
    else
      display_message("Incomplete image created: read errors have occured.\n");
    free(buffer);
    return 0;
  }
  if(nbr_read_error==0)
    display_message("Image created successfully.\n");
  else
    display_message("Image created successfully but read errors have occured.\n");
  free(buffer);
  return 0;
}
