/*

    File: fat_unformat.c

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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include "types.h"
#include "common.h"
#include "intrf.h"
#ifdef HAVE_NCURSES
#include "intrfn.h"
#else
#include <stdio.h>
#endif
#include "dir.h"
#include "fat_dir.h"
#include "list.h"
#include "filegen.h"
#include "photorec.h"
#include "log.h"
#include "pblocksize.h"
#include "fat_cluster.h"
#include "fat_unformat.h"
#include "pnext.h"

#define READ_SIZE 1024*512
static int pfind_sectors_per_cluster(disk_t *disk, partition_t *partition, const int verbose, const int interface, unsigned int *sectors_per_cluster, uint64_t *offset_org, alloc_data_t *list_search_space)
{
  uint64_t offset=0;
  unsigned int nbr_subdir=0;
  sector_cluster_t sector_cluster[10];
  int ind_stop=0;
  alloc_data_t *current_search_space;
  unsigned char *buffer_start=(unsigned char *)MALLOC(READ_SIZE);
  unsigned char *buffer=buffer_start;
  current_search_space=td_list_entry(list_search_space->list.next, alloc_data_t, list);
  if(current_search_space!=list_search_space)
    offset=current_search_space->start;
  if(verbose>0)
    info_list_search_space(list_search_space, current_search_space, disk->sector_size, 0, verbose);
#ifdef HAVE_NCURSES
  if(interface)
  {
    wmove(stdscr,22,0);
    wattrset(stdscr, A_REVERSE);
    waddstr(stdscr,"  Stop  ");
    wattroff(stdscr, A_REVERSE);
  }
#endif
  disk->pread(disk, buffer_start, READ_SIZE, offset);
  while(current_search_space!=list_search_space && nbr_subdir<10)
  {
    const uint64_t old_offset=offset;
#ifdef HAVE_NCURSES
    if(interface>0 && ((offset&(1024*disk->sector_size-1))==0))
    {
      wmove(stdscr,9,0);
      wclrtoeol(stdscr);
      wprintw(stdscr,"Search subdirectory %10lu/%lu %u",(unsigned long)(offset/disk->sector_size),(unsigned long)(partition->part_size/disk->sector_size),nbr_subdir);
      wrefresh(stdscr);
      ind_stop|=check_enter_key_or_s(stdscr);
    }
#endif
    get_next_sector(list_search_space, &current_search_space, &offset, 512);
    if(memcmp(buffer,         ".          ", 8+3)==0 &&
	memcmp(&buffer[0x20], "..         ", 8+3)==0)
    {
      unsigned long int cluster=(buffer[0*0x20+0x15]<<24) + (buffer[0*0x20+0x14]<<16) +
	(buffer[0*0x20+0x1B]<<8) + buffer[0*0x20+0x1A];
      log_info("sector %lu, cluster %lu\n",
	  (unsigned long)(offset/disk->sector_size), cluster);
      sector_cluster[nbr_subdir].cluster=cluster;
      sector_cluster[nbr_subdir].sector=offset/disk->sector_size;
      log_flush();
      nbr_subdir++;
    }
    buffer+=512;
    if( old_offset+512!=offset ||
        buffer+512>buffer_start+READ_SIZE)
    {
      buffer=buffer_start;
      if(verbose>1)
      {
        log_verbose("Reading sector %10lu/%lu\n",(unsigned long)((offset-partition->part_offset)/disk->sector_size),(unsigned long)((partition->part_size-1)/disk->sector_size));
      }
      if(disk->pread(disk, buffer_start, READ_SIZE, offset) != READ_SIZE)
      {
      }
    }
  } /* end while(current_search_space!=list_search_space) */
  free(buffer_start);
  return find_sectors_per_cluster_aux(sector_cluster,nbr_subdir,sectors_per_cluster,offset_org,verbose,partition->part_size/disk->sector_size);
}

static int fat_copy_file(disk_t *disk, const partition_t *partition, const unsigned int block_size, const uint64_t start_data, const char *recup_dir, const unsigned int dir_num, const file_data_t *file)
{
  char *new_file;	
  FILE *f_out;
  unsigned char *buffer_file=(unsigned char *)MALLOC(block_size);
  unsigned int cluster;
  unsigned int file_size=file->stat.st_size;
  unsigned long int no_of_cluster;
  cluster = file->stat.st_ino;
  new_file=(char *)MALLOC(1024);
  snprintf(new_file, 1024, "%s.%u/f%u-%s", recup_dir, dir_num,
      (unsigned int)((start_data - partition->part_offset + (uint64_t)(cluster-2)*block_size)/disk->sector_size),
      file->name);
  log_info("fat_copy_file %s\n", new_file);
  f_out=fopen(new_file, "wb");
  if(!f_out)
  {
    log_critical("Can't create file %s: \n",new_file);
    free(new_file);
    free(buffer_file);
    return -1;
  }
  no_of_cluster=(partition->part_size - start_data) / block_size;
  while(cluster>=2 && cluster<=no_of_cluster+2 && file_size>0)
  {
    const uint64_t start=start_data + (uint64_t)(cluster-2)*block_size;
    unsigned int toread = block_size;
    if (toread > file_size)
      toread = file_size;
    if((unsigned)disk->pread(disk, buffer_file, toread, start) != toread)
    {
      log_error("fat_copy_file: Can't read cluster %u.\n", cluster);
    }
    if(fwrite(buffer_file, 1, toread, f_out) != toread)
    {
      log_error("fat_copy_file: no space left on destination.\n");
      fclose(f_out);
      set_date(new_file, file->stat.st_atime, file->stat.st_mtime);
      free(new_file);
      free(buffer_file);
      return -1;
    }
    file_size -= toread;
    cluster++;
  }
  fclose(f_out);
  set_date(new_file, file->stat.st_atime, file->stat.st_mtime);
  free(new_file);
  free(buffer_file);
  return 0;
}

static int fat_unformat_aux(disk_t *disk, partition_t *partition, const int verbose, const char *recup_dir, const int interface, unsigned int *file_nbr, const unsigned int blocksize, const uint64_t start_offset, alloc_data_t *list_search_space, const time_t real_start_time, unsigned int *dir_num)
{
  uint64_t offset=0;
  unsigned char *buffer_start;
  unsigned char *buffer_olddata;
  unsigned char *buffer;
  time_t start_time;
  time_t previous_time;
  unsigned int buffer_size;
  const unsigned int read_size=(blocksize>65536?blocksize:65536);
  alloc_data_t *current_search_space;
  file_recovery_t file_recovery;
  buffer_size=blocksize+READ_SIZE;
  buffer_start=(unsigned char *)MALLOC(buffer_size);
  buffer_olddata=buffer_start;
  buffer=buffer_olddata+blocksize;
  reset_file_recovery(&file_recovery);
  start_time=time(NULL);
  previous_time=start_time;
  memset(buffer_olddata,0,blocksize);
  current_search_space=td_list_entry(list_search_space->list.next, alloc_data_t, list);
  if(current_search_space!=list_search_space)
    offset=current_search_space->start;
  if(verbose>0)
    info_list_search_space(list_search_space, current_search_space, disk->sector_size, 0, verbose);
  disk->pread(disk, buffer, READ_SIZE, offset);
  while(current_search_space!=list_search_space)
  {
    const uint64_t old_offset=offset;
    get_next_sector(list_search_space, &current_search_space,&offset,blocksize);
    if(memcmp(buffer,         ".          ", 8+3)==0 &&
	memcmp(&buffer[0x20], "..         ", 8+3)==0)
    {
      file_data_t *dir_list;
      dir_list=dir_fat_aux(buffer,read_size,0,0);
      if(dir_list!=NULL)
      {
	const file_data_t *current_file;
	del_search_space(list_search_space, old_offset, old_offset + blocksize -1);
	current_file=dir_list;
	while(current_file!=NULL)
	{
	  if(strcmp(current_file->name,".")==0 &&
	      LINUX_S_ISDIR(current_file->stat.st_mode)!=0 &&
	      current_file!=dir_list)
	    current_file=NULL;
	  else if(current_file->stat.st_ino>2 &&
	      LINUX_S_ISREG(current_file->stat.st_mode)!=0)
	  {
	    const uint64_t file_start=start_offset + (uint64_t)(current_file->stat.st_ino - 2) * blocksize;
	    const uint64_t file_end=file_start+(current_file->stat.st_size+blocksize-1)/blocksize*blocksize - 1;
	    if(file_end < partition->part_offset + partition->part_size)
	    {
	      if(fat_copy_file(disk, partition, blocksize, start_offset, recup_dir, *dir_num, current_file)==0)
	      {
		del_search_space(list_search_space, file_start, file_end);
	      }
	      current_file=current_file->next;
	    }
	    else
	      current_file=NULL;
	  }
	  else
	    current_file=current_file->next;
	}
	delete_list_file(dir_list);
	(*file_nbr)++;
      }
    }
    if(current_search_space==list_search_space)
    {
      /* End of disk found => EOF */
      reset_file_recovery(&file_recovery);
    }
    buffer_olddata+=blocksize;
    buffer+=blocksize;
    if( old_offset+blocksize!=offset ||
        buffer+read_size>buffer_start+buffer_size)
    {
      memcpy(buffer_start,buffer_olddata,blocksize);
      buffer_olddata=buffer_start;
      buffer=buffer_olddata+blocksize;
      if(verbose>1)
      {
        log_verbose("Reading sector %10lu/%lu\n",(unsigned long)((offset-partition->part_offset)/disk->sector_size),(unsigned long)((partition->part_size-1)/disk->sector_size));
      }
      if(disk->pread(disk, buffer, READ_SIZE, offset) != READ_SIZE)
      {
#ifdef HAVE_NCURSES
        if(interface!=0)
        {
          wmove(stdscr,11,0);
          wclrtoeol(stdscr);
          wprintw(stdscr,"Error reading sector %10lu\n",
              (unsigned long)((offset-partition->part_offset)/disk->sector_size));
        }
#endif
      }
#ifdef HAVE_NCURSES
      if(interface!=0)
      {
        time_t current_time;
        current_time=time(NULL);
        if(current_time>previous_time)
        {
	  const time_t elapsed_time=current_time-real_start_time;
          previous_time=current_time;
	  wmove(stdscr,9,0);
	  wclrtoeol(stdscr);
	  wprintw(stdscr,"Reading sector %10lu/%lu, %u files found\n",
	      (unsigned long)((offset-partition->part_offset)/disk->sector_size),
	      (unsigned long)(partition->part_size/disk->sector_size), file_nbr);
	  wmove(stdscr,10,0);
	  wclrtoeol(stdscr);
	  wprintw(stdscr,"Elapsed time %uh%02um%02us",
	      (unsigned)(elapsed_time/60/60),
	      (unsigned)(elapsed_time/60%60),
	      (unsigned)(elapsed_time%60));
	  if(offset-partition->part_offset!=0)
	  {
	    wprintw(stdscr," - Estimated time for achievement %uh%02um%02u\n",
		(unsigned)((partition->part_offset+partition->part_size-1-offset)*elapsed_time/(offset-partition->part_offset)/3600),
		(unsigned)(((partition->part_offset+partition->part_size-1-offset)*elapsed_time/(offset-partition->part_offset)/60)%60),
		(unsigned)((partition->part_offset+partition->part_size-1-offset)*elapsed_time/(offset-partition->part_offset))%60);
	  }
	  wrefresh(stdscr);
	  if(check_enter_key_or_s(stdscr))
	  {
	    log_info("PhotoRec has been stopped\n");
	    current_search_space=list_search_space;
	  }
	}
      }
#endif
    }
  } /* end while(current_search_space!=list_search_space) */
  free(buffer_start);
  return 0;
}

int fat_unformat(disk_t *disk, partition_t *partition, const int verbose, const char *recup_dir, const int interface, unsigned int *file_nbr, unsigned int *blocksize, alloc_data_t *list_search_space, const time_t real_start_time, unsigned int *dir_num, const unsigned int expert)
{
  unsigned int sectors_per_cluster=0;
  uint64_t start_data=0;
  *blocksize=0;
//  if(find_sectors_per_cluster(disk, partition, verbose, 0, interface, &sectors_per_cluster, &start_data)==0)
  if(pfind_sectors_per_cluster(disk, partition, verbose, interface, &sectors_per_cluster, &start_data, list_search_space)==0)
  {
    display_message("Can't find FAT cluster size\n");
    return 0;
  }
  del_search_space(list_search_space, partition->part_offset,
      partition->part_offset+(uint64_t)(start_data * disk->sector_size)-1);
  {
    uint64_t start_offset;
    *blocksize=sectors_per_cluster * disk->sector_size;
    start_offset=start_data * disk->sector_size + partition->part_offset;
#ifdef HAVE_NCURSES
    if(expert>0)
      *blocksize=menu_choose_blocksize(*blocksize, disk->sector_size, &start_offset);
#endif
    update_blocksize(*blocksize,list_search_space, start_offset);
    fat_unformat_aux(disk, partition, verbose, recup_dir, interface, file_nbr, *blocksize, start_offset, list_search_space, real_start_time, dir_num);
  }
  return 0;
}

