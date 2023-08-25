/*

    File: fat_unformat.c

    Copyright (C) 2009-2012 Christophe GRENIER <grenier@cgsecurity.org>

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
#include <stdio.h>
#include "types.h"
#include "common.h"
#include "intrf.h"
#include "intrfn.h"
#include "dir.h"
#include "fat.h"
#include "fat_dir.h"
#include "list.h"
#include "filegen.h"
#include "photorec.h"
#include "log.h"
#include "pblocksize.h"
#include "fat_cluster.h"
#include "fat_unformat.h"
#include "pnext.h"
#include "setdate.h"
#include "fat_common.h"
#include <assert.h>

#ifndef DISABLED_FOR_FRAMAC
extern int need_to_stop;

#define READ_SIZE 4*1024*1024
static int pfind_sectors_per_cluster(disk_t *disk, const partition_t *partition, const int verbose, unsigned int *sectors_per_cluster, uint64_t *offset_org, alloc_data_t *list_search_space)
{
  uint64_t offset=0;
  uint64_t next_offset=0;
  uint64_t diff_offset=0;
  time_t previous_time=0;
  unsigned int nbr_subdir=0;
  sector_cluster_t sector_cluster[10];
  alloc_data_t *current_search_space;
  unsigned char *buffer_start=(unsigned char *)MALLOC(READ_SIZE);
  unsigned char *buffer=buffer_start;
  assert(disk->sector_size!=0);
  current_search_space=td_list_first_entry(&list_search_space->list, alloc_data_t, list);
  if(current_search_space!=list_search_space)
    offset=current_search_space->start;
  if(verbose>0)
    info_list_search_space(list_search_space, current_search_space, disk->sector_size, 0, verbose);
#ifdef HAVE_NCURSES
  wmove(stdscr,22,0);
  wattrset(stdscr, A_REVERSE);
  waddstr(stdscr,"  Stop  ");
  wattroff(stdscr, A_REVERSE);
#endif
  disk->pread(disk, buffer_start, READ_SIZE, offset);
  while(current_search_space!=list_search_space && nbr_subdir<10)
  {
    const uint64_t old_offset=offset;
    if(buffer[0]=='.' && is_fat_directory(buffer))
    {
      const unsigned long int cluster=fat_get_cluster_from_entry((const struct msdos_dir_entry *)buffer);
      log_info("sector %lu, cluster %lu\n",
	  (unsigned long)(offset/disk->sector_size), cluster);
      sector_cluster[nbr_subdir].cluster=cluster;
      sector_cluster[nbr_subdir].sector=offset/disk->sector_size;
      log_flush();
      nbr_subdir++;
    }
    get_next_sector(list_search_space, &current_search_space, &offset, 512);
    buffer+=512;
    if( old_offset+512!=offset ||
        buffer+512>buffer_start+READ_SIZE)
    {
      buffer=buffer_start;
#ifdef HAVE_NCURSES
      if(offset > next_offset)
      {
	const time_t current_time=time(NULL);
	if(current_time==previous_time)
	  diff_offset<<=1;
	else
	  diff_offset>>=1;
	if(diff_offset < disk->sector_size)
	  diff_offset=disk->sector_size;
	next_offset=offset+diff_offset;
	previous_time=current_time;
	wmove(stdscr,9,0);
	wclrtoeol(stdscr);
	wprintw(stdscr,"Search subdirectory %10lu/%lu %u",(unsigned long)(offset/disk->sector_size),(unsigned long)(partition->part_size/disk->sector_size),nbr_subdir);
	wrefresh(stdscr);
      }
#endif
      if(verbose>1)
      {
        log_verbose("Reading sector %10llu/%llu\n",
	    (unsigned long long)((offset-partition->part_offset)/disk->sector_size),
	    (unsigned long long)((partition->part_size-1)/disk->sector_size));
      }
      if(disk->pread(disk, buffer_start, READ_SIZE, offset) != READ_SIZE)
      {
#ifdef HAVE_NCURSES
	wmove(stdscr,11,0);
	wclrtoeol(stdscr);
	wprintw(stdscr,"Error reading sector %10lu\n",
	    (unsigned long)((offset - partition->part_offset) / disk->sector_size));
#endif
      }
    }
  } /* end while(current_search_space!=list_search_space) */
  free(buffer_start);
  return find_sectors_per_cluster_aux(sector_cluster,nbr_subdir,sectors_per_cluster,offset_org,verbose,partition->part_size/disk->sector_size, UP_UNK);
}

static void strip_fn(char *fn)
{
  unsigned int i;
  for(i=0; fn[i]!='\0'; i++);
  while(i>0 && (fn[i-1]==' ' || fn[i-1]=='.'))
    i--;
  if(i==0 && (fn[0]==' ' || fn[0]=='.'))
    fn[i++]='_';
  fn[i]='\0';
}

static copy_file_t fat_copy_file(disk_t *disk, const partition_t *partition, const unsigned int cluster_size, const uint64_t start_data, const char *recup_dir, const unsigned int dir_num, const unsigned int inode_num, const file_info_t *file)
{
  char *new_file;	
  FILE *f_out;
  unsigned int cluster;
  unsigned int file_size=file->st_size;
  const unsigned long int no_of_cluster=(partition->part_size - start_data) / cluster_size;
  unsigned char *buffer_file=(unsigned char *)MALLOC(cluster_size);
  cluster = file->st_ino;
  new_file=(char *)MALLOC(1024);
#ifdef HAVE_MKDIR
  snprintf(new_file, 1024, "%s.%u/inode_%u", recup_dir, dir_num, inode_num);
#ifdef __MINGW32__
  mkdir(new_file);
#else
  (void)mkdir(new_file, 0775);
#endif
#endif
  snprintf(new_file, 1024, "%s.%u/inode_%u/%s", recup_dir, dir_num, inode_num,
      file->name);
  strip_fn(new_file);
  if((f_out=fopen(new_file, "rb"))!=NULL)
  {
    fclose(f_out);
    snprintf(new_file, 1024, "%s.%u/inode_%u/f%07u-%s", recup_dir, dir_num, inode_num,
	(unsigned int)((start_data - partition->part_offset + (uint64_t)(cluster-2)*cluster_size)/disk->sector_size),
	file->name);
    strip_fn(new_file);
  }
  log_info("fat_copy_file %s\n", new_file);
  f_out=fopen(new_file, "wb");
  if(!f_out)
  {
    log_critical("Can't create file %s: \n",new_file);
    free(new_file);
    free(buffer_file);
    return CP_CREATE_FAILED;
  }
  while(cluster>=2 && cluster<=no_of_cluster+2 && file_size>0)
  {
    const uint64_t start=start_data + (uint64_t)(cluster-2)*cluster_size;
    unsigned int toread = cluster_size;
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
      set_date(new_file, file->td_atime, file->td_mtime);
      free(new_file);
      free(buffer_file);
      return CP_NOSPACE;
    }
    file_size -= toread;
    cluster++;
  }
  fclose(f_out);
  set_date(new_file, file->td_atime, file->td_mtime);
  free(new_file);
  free(buffer_file);
  return CP_OK;
}

static pstatus_t fat_unformat_aux(struct ph_param *params, const struct ph_options *options, const uint64_t start_data, alloc_data_t *list_search_space)
{
  pstatus_t ind_stop=PSTATUS_OK;
  uint64_t offset;
  uint64_t offset_end;
  unsigned char *buffer_start;
  unsigned char *buffer;
  time_t start_time;
  time_t previous_time;
  const unsigned int cluster_size=params->blocksize;
  const unsigned int read_size=(cluster_size>65536?cluster_size:65536);
  alloc_data_t *current_search_space;
  disk_t *disk=params->disk;
  const partition_t *partition=params->partition;
  const unsigned long int no_of_cluster=(partition->part_size - start_data) / cluster_size;
  log_info("fat_unformat_aux: no_of_cluster=%lu\n", no_of_cluster);

#ifdef HAVE_NCURSES
  aff_copy(stdscr);
#endif
  start_time=time(NULL);
  previous_time=start_time;
  current_search_space=td_list_last_entry(&list_search_space->list, alloc_data_t, list);
  if(current_search_space==list_search_space)
  {
    return PSTATUS_OK;
  }
  offset_end=current_search_space->end;
  current_search_space=td_list_first_entry(&list_search_space->list, alloc_data_t, list);
  offset=set_search_start(params, &current_search_space, list_search_space);
  if(options->verbose>0)
    info_list_search_space(list_search_space, current_search_space, disk->sector_size, 0, options->verbose);
  buffer_start=(unsigned char *)MALLOC(READ_SIZE);
  buffer=buffer_start;
  disk->pread(disk, buffer_start, READ_SIZE, offset);
  for(;offset < offset_end; offset+=cluster_size)
  {
    if(buffer[0]=='.' && is_fat_directory(buffer))
    {
      file_info_t dir_list;
      TD_INIT_LIST_HEAD(&dir_list.list);
      dir_fat_aux(buffer, read_size, 0, &dir_list);
      if(!td_list_empty(&dir_list.list))
      {
	struct td_list_head *file_walker = NULL;
	unsigned int dir_inode=0;
	unsigned int nbr;
	int stop=0;
	log_info("Sector %llu\n", (long long unsigned)offset/disk->sector_size);
	dir_aff_log(NULL, &dir_list);
	del_search_space(list_search_space, offset, offset + cluster_size -1);
	for(file_walker=dir_list.list.next, nbr=0;
	    stop==0 && file_walker!=&dir_list.list;
	    file_walker=file_walker->next, nbr++)
	{
	  const file_info_t *current_file=td_list_entry_const(file_walker, const file_info_t, list);
	  if(current_file->st_ino==1 ||
	      current_file->st_ino >= no_of_cluster+2)
	    stop=1;
	  else if(LINUX_S_ISDIR(current_file->st_mode)!=0)
	  {
	    if(strcmp(current_file->name,"..")==0)
	    {
	      if(nbr!=1)
		stop=1;
	    }
	    else if(current_file->st_ino==0)
	      stop=1;
	    else if(strcmp(current_file->name,".")==0)
	    {
	      if(nbr==0)
		dir_inode=current_file->st_ino;
	      else
		stop=1;
	    }
	    else
	    {
#ifdef HAVE_MKDIR
	      char *new_file=(char *)MALLOC(1024);
	      snprintf(new_file, 1024, "%s.%u/inode_%u/inode_%u_%s",
		  params->recup_dir, params->dir_num, dir_inode,
		  (unsigned int)current_file->st_ino, current_file->name);
#ifdef __MINGW32__
	      mkdir(new_file);
#else
	      mkdir(new_file, 0775);
#endif
	      free(new_file);
#endif
	    }
	  }
	  else if(LINUX_S_ISREG(current_file->st_mode)!=0)
	  {
	    const uint64_t file_start=start_data + (uint64_t)(current_file->st_ino - 2) * cluster_size;
	    const uint64_t file_end=file_start+(current_file->st_size+cluster_size-1)/cluster_size*cluster_size - 1;
	    if(file_end < partition->part_offset + partition->part_size && current_file->st_ino>0)
	    {
	      if(fat_copy_file(disk, partition, cluster_size, start_data, params->recup_dir, params->dir_num, dir_inode, current_file)==0)
	      {
		params->file_nbr++;
		del_search_space(list_search_space, file_start, file_end);
	      }
	    }
	    else
	      stop=1;
	  }
	}
	delete_list_file(&dir_list);
      }
    }
    buffer+=cluster_size;
    if(buffer+read_size>buffer_start+READ_SIZE)
    {
      buffer=buffer_start;
      if(options->verbose>1)
      {
        log_verbose("Reading sector %10llu/%llu\n",
	    (unsigned long long)((offset-partition->part_offset)/disk->sector_size),
	    (unsigned long long)((partition->part_size-1)/disk->sector_size));
      }
      if(disk->pread(disk, buffer_start, READ_SIZE, offset) != READ_SIZE)
      {
#ifdef HAVE_NCURSES
	wmove(stdscr,11,0);
	wclrtoeol(stdscr);
	wprintw(stdscr,"Error reading sector %10lu\n",
	    (unsigned long)((offset-partition->part_offset)/disk->sector_size));
#endif
      }
#ifdef HAVE_NCURSES
      {
        time_t current_time;
        current_time=time(NULL);
        if(current_time>previous_time)
        {
          previous_time=current_time;
	  wmove(stdscr,9,0);
	  wclrtoeol(stdscr);
	  wprintw(stdscr,"Reading sector %10llu/%llu, %u files found\n",
	      (unsigned long long)((offset-partition->part_offset)/disk->sector_size),
	      (unsigned long long)(partition->part_size/disk->sector_size), params->file_nbr);
	  wmove(stdscr,10,0);
	  wclrtoeol(stdscr);
	  if(current_time > params->real_start_time)
	  {
	    const time_t elapsed_time=current_time - params->real_start_time;
	    wprintw(stdscr,"Elapsed time %uh%02um%02us",
		(unsigned)(elapsed_time/60/60),
		(unsigned)((elapsed_time/60)%60),
		(unsigned)(elapsed_time%60));
	    if(offset > partition->part_offset)
	    {
	      const time_t eta=(partition->part_offset+partition->part_size-1-offset)*elapsed_time/(offset-partition->part_offset);
	      wprintw(stdscr," - Estimated time to completion %uh%02um%02u\n",
		  (unsigned)(eta/3600),
		  (unsigned)((eta/60)%60),
		  (unsigned)(eta%60));
	    }
	  }
	  wrefresh(stdscr);
	  if(check_enter_key_or_s(stdscr))
	  {
	    log_info("PhotoRec has been stopped\n");
	    params->offset=offset;
	    offset = offset_end;
	    ind_stop=PSTATUS_STOP;
	  }
	}
      }
#endif
      if(need_to_stop!=0)
      {
	log_info("PhotoRec has been stopped\n");
	params->offset=offset;
	offset = offset_end;
	ind_stop=PSTATUS_STOP;
      }
    }
  }
  free(buffer_start);
  return ind_stop;
}

/* fat_unformat()
 * @param struct ph_param *params
 * @param const struct ph_options *options
 * @param alloc_data_t *list_search_space
 *
 * @returns:
 * 0: Completed or not possible
 * 1: Stop by user request
 *    params->offset is set
 */
pstatus_t fat_unformat(struct ph_param *params, const struct ph_options *options, alloc_data_t *list_search_space)
{
  unsigned int sectors_per_cluster=0;
  uint64_t start_data=0;
  params->blocksize=0;
  if(pfind_sectors_per_cluster(params->disk, params->partition, options->verbose, &sectors_per_cluster, &start_data, list_search_space)==0)
  {
    display_message("Can't find FAT cluster size\n");
    return PSTATUS_OK;
  }
  if(start_data <= params->partition->part_offset)
  {
    display_message("FAT filesystem was beginning before the actual partition.");
    return PSTATUS_OK;
  }
  start_data *= params->disk->sector_size;
  del_search_space(list_search_space, params->partition->part_offset, start_data - 1);
  {
    uint64_t offset=start_data;
    params->blocksize=sectors_per_cluster * params->disk->sector_size;
#ifdef HAVE_NCURSES
    if(options->expert>0)
      menu_choose_blocksize(&params->blocksize, &offset, params->disk->sector_size);
#endif
    update_blocksize(params->blocksize, list_search_space, offset);
  }
  /* start_data is relative to the disk */
  return fat_unformat_aux(params, options, start_data, list_search_space);
}
#endif
