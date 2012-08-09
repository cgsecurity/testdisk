/*

    File: diskcp.c

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
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_SYS_MOUNT_H
#include <sys/mount.h>	/* BLKFLSBUF */
#endif
#ifdef HAVE_SYS_DISK_H
#include <sys/disk.h>
#endif
#include "types.h"
#ifndef O_BINARY
#define O_BINARY 0
#endif

enum { STATUS_NON_TRIED = '?', STATUS_NON_SPLIT = '/', STATUS_BAD_BLOCK = '-', STATUS_DONE = '+' };

const char *size_to_unit(uint64_t disk_size, char *buffer)
{
  if(disk_size<(uint64_t)10*1024)
    sprintf(buffer,"%u B", (unsigned)disk_size);
  else if(disk_size<(uint64_t)10*1024*1024)
    sprintf(buffer,"%u KB / %u KiB", (unsigned)(disk_size/1000), (unsigned)(disk_size/1024));
  else if(disk_size<(uint64_t)10*1024*1024*1024)
    sprintf(buffer,"%u MB / %u MiB", (unsigned)(disk_size/1000/1000), (unsigned)(disk_size/1024/1024));
  else if(disk_size<(uint64_t)10*1024*1024*1024*1024)
    sprintf(buffer,"%u GB / %u GiB", (unsigned)(disk_size/1000/1000/1000), (unsigned)(disk_size/1024/1024/1024));
  else
    sprintf(buffer,"%u TB / %u TiB", (unsigned)(disk_size/1000/1000/1000/1000), (unsigned)(disk_size/1024/1024/1024/1024));
  return buffer;
}

int main(int argc, char **argv)
{
  int i;
  int readsize;
  int readsize_min;
  int readsize_max;
  uint64_t readok=0;
  uint64_t location;
  uint64_t old_status_location=0;
  int old_status=STATUS_DONE;
  int sector_size=512;
  int current_disk=0;
  int first_disk;
  int nbr_disk=0;
  int disk_src[1];
  int disk_dst;
  FILE *log;
  char *buffer;
  uint64_t disk_size=0;
  int gap=-1;
  if(argc<=2)
  {
    printf("disk_cp src dst\n");
    return 1;
  }
  /* O_DIRECT ? */
  if((disk_src[nbr_disk++]=open(argv[1],O_LARGEFILE|O_RDONLY|O_BINARY))<0)
  {
    printf("Can't open file %s\n",argv[1]);
    return 1;
  }
  if((disk_dst=open(argv[2],O_LARGEFILE|O_RDWR|O_BINARY|O_CREAT,0644))<0)
  {
    printf("Can't open file %s\n",argv[2]);
    return 1;
  }
  {
    void *res;
    uint64_t longsectors64=0;
    if (ioctl(disk_src[0], BLKGETSIZE64, &longsectors64)>=0)
    {
      disk_size=longsectors64;
    }
    readsize_min=sector_size;
    /* 1,2,4,8,16,32 */
    readsize_max=16*sector_size;
    readsize=readsize_min;
    first_disk=current_disk;
    if(posix_memalign(&res,4096,readsize_max)!=0)
    {
      printf("posix_memalign failed\n");
      close(disk_dst);
      return 1;
    }
    buffer=(char*)res;
  }
  if(1==2)
  {
    if((log=fopen("diskcp.log","w"))==NULL)
    {
      printf("Can't create diskcp.log file\n");
      return 1;
    }
    /* It may be possible to improve the speed by using readv, a ttl (or a timestamp) may be used for bad disks */
    for(location=0;location<disk_size;)
    {
      int status;
      lseek(disk_src[current_disk], location, SEEK_SET);
      do
      {
	if(read(disk_src[current_disk],buffer,readsize)==readsize)
	{
	  lseek(disk_dst, location, SEEK_SET);
	  /* FIXME need to check write return value */
	  write(disk_dst,buffer,readsize);
	  readok+=readsize;
	  status=STATUS_DONE;
	}
	else
	{
	  status=((readsize==readsize_min)?STATUS_BAD_BLOCK:STATUS_NON_SPLIT);
	  if(status==STATUS_NON_SPLIT)
	  {
	    readsize=readsize_min;
	  }
	}
      } while(status==STATUS_NON_SPLIT);
      if(location==0)
      {
	old_status=status;
      }
      if(status!=old_status && old_status_location < location)
      {
	fprintf(log,"%08llX - %08llX %c\n",
	    (unsigned long long)(old_status_location/sector_size),
	    (unsigned long long)((location-1)/sector_size),
	    old_status);
	fflush(log);
	old_status_location=location;
	old_status=status;
      }
      if(status==STATUS_DONE)
      {
	gap=-1;
	first_disk=current_disk;
	location+=readsize;
	if(readsize<readsize_max)
	  readsize*=2;
      }
      else
      {
	char buf[100];
	printf("Sector %llu", (unsigned long long) (location/sector_size));
	printf(" (%s)", size_to_unit(location, buf));
	printf(" - Recovered %s\r", size_to_unit(readok, buf));
	fflush(stdout);
	current_disk=(current_disk+1)%nbr_disk;
	readsize=readsize_min;
	if(current_disk==first_disk)
	{
	  location+=readsize;
	  /* Introduire les gaps */
	  fprintf(log,"%08llX - %08llX %c\n",
	      (unsigned long long)(old_status_location/sector_size),
	      (unsigned long long)((location-1)/sector_size),
	      old_status);
	  fflush(log);
	  old_status_location=location;
	  old_status=STATUS_NON_TRIED;
	  if(gap<0)
	    gap=2;
	  location+=readsize_min<<gap;
	  if(gap<16)
	    gap++;
	}
      }
    }
    printf("\n");
    fprintf(log,"%08llX - %08llX %c\n",
	(unsigned long long)(old_status_location/sector_size),
	(unsigned long long)((disk_size-1)/sector_size),
	old_status);
    fclose(log);
  }
  /* Pass 2: read until a read error occurs */
  {
    FILE *oldlog;
    if((oldlog=fopen("diskcp.log","r"))==NULL)
    {
      printf("Can't read diskcp.log file\n");
      close(disk_dst);
      return 1;
    }
    if((log=fopen("diskcp2.log","w"))==NULL)
    {
      printf("Can't create diskcp2.log file\n");
      fclose(oldlog);
      close(disk_dst);
      return 1;
    }
    {
      long long unsigned start[3];
      long long unsigned end[3];
      char status[3];
      int nbr=0;
      while(fscanf(oldlog,"%20llu - %20llu %c", &start[nbr], &end[nbr], &status[nbr])==3)
      {
	printf("%llu - %llu %c\n", start[nbr], end[nbr], status[nbr]);
	if(nbr==3 && status[1]==STATUS_NON_TRIED && status[2]==STATUS_DONE)
	{
	  for(location=end[nbr];location>=start[nbr];location-=readsize_min)
	  {

	  }
	}
      }
    }
    fclose(log);
    fclose(oldlog);
  }

  /* Pass 3: read */
  for(i=0;i<nbr_disk;i++)
    close(disk_src[i]);
  close(disk_dst);
  return 0;
}
