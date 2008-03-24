/*

    File: phrecn.c

    Copyright (C) 1998-2008 Christophe GRENIER <grenier@cgsecurity.org>

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
#ifdef HAVE_UNISTD_H
#include <unistd.h>	/* unlink, ftruncate */
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
#include <ctype.h>      /* tolower */
#include "types.h"
#include "common.h"
#include "intrf.h"
#ifdef HAVE_NCURSES
#include "intrfn.h"
#else
#include <stdio.h>
#endif
#include "fnctdsk.h"
#include "dir.h"
#include "fat_dir.h"
#include "list.h"
#include "chgtype.h"
#include "lang.h"
#include "filegen.h"
#include "photorec.h"
#include "sessionp.h"
#include "phrecn.h"
#include "partauto.h"
#include "log.h"
#include "hdaccess.h"
#include "file_tar.h"
#include "phcfg.h"

/* #define DEBUG */
/* #define DEBUG_GET_NEXT_SECTOR */
/* #define DEBUG_BF */
#define READ_SIZE 256*512
#define INTER_MENU_DISK 10

extern const file_hint_t file_hint_tar;
extern const file_hint_t file_hint_dir;
extern file_check_t *file_check_list;

#ifdef HAVE_NCURSES
static int photorec_progressbar(WINDOW *window, const unsigned int pass, const photorec_status_t status, const uint64_t offset, disk_t *disk_car, partition_t *partition, const unsigned int file_nbr, const time_t elapsed_time, const file_stat_t *file_stats);
static void recovery_finished(const unsigned int file_nbr, const char *recup_dir, const int ind_stop, char **current_cmd);
static int ask_mode_ext2(const disk_t *disk_car, const partition_t *partition, unsigned int *mode_ext2, unsigned int *carve_free_space_only);
#endif

static int photorec_bf(disk_t *disk_car, partition_t *partition, const int verbose, const int paranoid, const char *recup_dir, const int interface, file_stat_t *file_stats, unsigned int *file_nbr, unsigned int *blocksize, alloc_data_t *list_search_space, const time_t real_start_time, unsigned int *dir_num, const photorec_status_t status, const unsigned int pass, const unsigned int expert, const unsigned int lowmem);
static int photorec_aux(disk_t *disk_car, partition_t *partition, const int verbose, const int paranoid, const char *recup_dir, const int interface, file_stat_t *file_stats, unsigned int *file_nbr, unsigned int *blocksize, alloc_data_t *list_search_space, const time_t real_start_time, unsigned int *dir_num, const photorec_status_t status, const unsigned int pass, const unsigned int expert, const unsigned int lowmem);
static int photorec(disk_t *disk_car, partition_t *partition, const int verbose, const int paranoid, char *recup_dir, const int keep_corrupted_file, const int interface, file_enable_t *file_enable, const unsigned int mode_ext2, char **current_cmd, alloc_data_t *list_search_space, unsigned int blocksize, const unsigned int expert, const unsigned int lowmem, const unsigned int carve_free_space_only);
static void interface_options_photorec(int *paranoid, int *allow_partial_last_cylinder, int *keep_corrupted_file, unsigned int *mode_ext2, unsigned int *expert, unsigned int *lowmem, char**current_cmd);
static int photorec_bf_aux(disk_t *disk_car, partition_t *partition, const int paranoid, const char *recup_dir, const int interface, file_stat_t *file_stats, unsigned int *file_nbr, file_recovery_t *file_recovery, unsigned int blocksize, alloc_data_t *list_search_space, alloc_data_t *current_search_space, const time_t real_start_time, unsigned int *dir_num, const photorec_status_t status, const unsigned int pass);
static void interface_file_select(file_enable_t *files_enable, char**current_cmd);

/* ==================== INLINE FUNCTIONS ========================= */
/* Check if the block looks like an indirect/double-indirect block */
static inline int ind_block(const unsigned char *buffer, const unsigned int blocksize)
{
  const uint32_t *p32=(const uint32_t *)buffer;
  unsigned int i;
  unsigned int diff=1;	/* IND: Indirect block */
  if(le32(p32[0])==0)
    return 0;
  if(le32(p32[1])==le32(p32[0])+blocksize/4+1)
    diff=blocksize/4+1;	/* DIND: Double Indirect block */
  for(i=0;i<blocksize/4-1 && le32(p32[i+1])!=0;i++)
  {
    if(le32(p32[i+1])!=le32(p32[i])+diff)
    {
      return 0;
    }
  }
  i++;
  for(;i<blocksize/4 && le32(p32[i])==0;i++);
  if(i<blocksize/4)
  {
    return 0;
  }
  return 1;	/* Ok: ind_block points to non-fragmented block */
}

static
#ifndef DEBUG_GET_NEXT_SECTOR
inline
#endif
void get_next_header(alloc_data_t *list_search_space, alloc_data_t **current_search_space, uint64_t *offset)
{
#ifdef DEBUG_GET_NEXT_SECTOR
  log_trace(" get_next_header %llu (%llu-%llu)\n",
      (unsigned long long)((*offset)/512),
      (unsigned long long)((*current_search_space)->start/512),
      (unsigned long long)((*current_search_space)->end)/512);
#endif
  if((*current_search_space) != list_search_space)
    *current_search_space=td_list_entry((*current_search_space)->list.next, alloc_data_t, list);
  *offset=(*current_search_space)->start;
}

static
#ifndef DEBUG_GET_NEXT_SECTOR
inline
#endif
void get_next_sector(alloc_data_t *list_search_space, alloc_data_t **current_search_space, uint64_t *offset, const unsigned int blocksize)
{
#ifdef DEBUG_GET_NEXT_SECTOR
  log_debug(" get_next_sector %llu (%llu-%llu)\n",
      (unsigned long long)((*offset)/512),
      (unsigned long long)((*current_search_space)->start/512),
      (unsigned long long)((*current_search_space)->end)/512);
#endif
  if((*current_search_space) == list_search_space)
  {
    return ;
  }
  if(! ((*current_search_space)->start <= *offset && (*offset)<=(*current_search_space)->end))
  {
    log_critical("BUG: get_next_sector stop everything %llu (%llu-%llu)\n",
        (unsigned long long)((*offset)/512),
        (unsigned long long)((*current_search_space)->start/512),
        (unsigned long long)((*current_search_space)->end/512));
    log_flush();
#ifdef DEBUG_GET_NEXT_SECTOR
    bug();
#endif
    exit(1);
  }
  if((*offset)+blocksize <= (*current_search_space)->end)
    *offset+=blocksize;
  else
    get_next_header(list_search_space, current_search_space, offset);
}
/* ==================== INLINE FUNCTIONS ========================= */

#ifdef HAVE_NCURSES
static void photorec_info(WINDOW *window, const file_stat_t *file_stats)
{
  unsigned int i;
  unsigned int nbr;
  unsigned int others=0;
  file_stat_t *new_file_stats;
  for(i=0;file_stats[i].file_hint!=NULL;i++);
  nbr=i;
  if(nbr==0)
    return ;
  new_file_stats=(file_stat_t*)MALLOC(nbr*sizeof(file_stat_t));
  memcpy(new_file_stats, file_stats, nbr*sizeof(file_stat_t));
  qsort(new_file_stats, nbr, sizeof(file_stat_t), sorfile_stat_ts);
  for(i=0;i<nbr && new_file_stats[i].recovered>0;i++)
  {
    if(i<10)
    {
      wmove(window,11+i,0);
      wclrtoeol(window);
      wprintw(window, "%s: %u recovered\n",
          (new_file_stats[i].file_hint->extension!=NULL?
           new_file_stats[i].file_hint->extension:""),
          new_file_stats[i].recovered);
    }
    else
      others+=new_file_stats[i].recovered;
  }
  if(others>0)
  {
    wmove(window,11+10,0);
    wclrtoeol(window);
    wprintw(window, "others: %u recovered\n", others);
  }
  free(new_file_stats);
}

static int photorec_progressbar(WINDOW *window, const unsigned int pass, const photorec_status_t status, const uint64_t offset, disk_t *disk_car, partition_t *partition, const unsigned int file_nbr, const time_t elapsed_time, const file_stat_t *file_stats)
{
  wmove(window,9,0);
  wclrtoeol(window);
  if(status==STATUS_EXT2_ON_BF || status==STATUS_EXT2_OFF_BF)
  {
    wprintw(window,"Bruteforce %10lu sectors remaining (test %u), %u files found\n",
        (unsigned long)((offset-partition->part_offset)/disk_car->sector_size), pass, file_nbr);
  }
  else
  {
    wprintw(window, "Pass %u - ", pass);
    if(status==STATUS_FIND_OFFSET)
      wprintw(window,"Reading sector %10lu/%lu, %u/10 headers found\n",
          (unsigned long)((offset-partition->part_offset)/disk_car->sector_size),
          (unsigned long)(partition->part_size/disk_car->sector_size), file_nbr);
    else
      wprintw(window,"Reading sector %10lu/%lu, %u files found\n",
          (unsigned long)((offset-partition->part_offset)/disk_car->sector_size),
          (unsigned long)(partition->part_size/disk_car->sector_size), file_nbr);
  }
  wmove(window,10,0);
  wclrtoeol(window);
  wprintw(window,"Elapsed time %uh%02um%02us",
      (unsigned)(elapsed_time/60/60),
      (unsigned)(elapsed_time/60%60),
      (unsigned)(elapsed_time%60));
  if(offset-partition->part_offset!=0 && (status!=STATUS_EXT2_ON_BF && status!=STATUS_EXT2_OFF_BF))
  {
    wprintw(window," - Estimated time for achievement %uh%02um%02u\n",
        (unsigned)((partition->part_offset+partition->part_size-1-offset)*elapsed_time/(offset-partition->part_offset)/3600),
        (unsigned)(((partition->part_offset+partition->part_size-1-offset)*elapsed_time/(offset-partition->part_offset)/60)%60),
        (unsigned)((partition->part_offset+partition->part_size-1-offset)*elapsed_time/(offset-partition->part_offset))%60);
  }
  photorec_info(window, file_stats);
  wrefresh(window);
  return check_enter_key_or_s(window);
}

void aff_copy(WINDOW *window)
{
  wclear(window);
  keypad(window, TRUE); /* Need it to get arrow key */
  wmove(window,0,0);
  wprintw(window, "PhotoRec %s, Data Recovery Utility, %s\n",VERSION,TESTDISKDATE);
  wmove(window,1,0);
  wprintw(window, "Christophe GRENIER <grenier@cgsecurity.org>");
  wmove(window,2,0);
  wprintw(window, "http://www.cgsecurity.org");
}

static int ask_mode_ext2(const disk_t *disk_car, const partition_t *partition, unsigned int *mode_ext2, unsigned int *carve_free_space_only)
{
  static struct MenuItem menuMode[]=
    {
      {'E',"EXT2/EXT3","EXT2/EXT3 filesystem"},
      {'O',"Other","FAT/NTFS/HFS+/ReiserFS/..."},
      {0,NULL,NULL}
    };
  static struct MenuItem menuFAT16[]=
  {
    {'F',"Free", "Scan for files from FAT16 unallocated space only"},
    {'W',"Whole","Extract files from whole partition"},
    {0,NULL,NULL}
  };
  static struct MenuItem menuFAT32[]=
  {
    {'F',"Free", "Scan for file from FAT32 unallocated space only"},
    {'W',"Whole","Extract files from whole partition"},
    {0,NULL,NULL}
  };
#ifdef HAVE_LIBNTFS
  static struct MenuItem menuNTFS[]=
  {
    {'F',"Free", "Scan for file from NTFS unallocated space only"},
    {'W',"Whole","Extract files from whole partition"},
    {0,NULL,NULL}
  };
#endif
#ifdef HAVE_LIBEXT2FS
  static struct MenuItem menuEXT2[]=
  {
    {'F',"Free", "Scan for file from ext2/ext3 unallocated space only"},
    {'W',"Whole","Extract files from whole partition"},
    {0,NULL,NULL}
  };
#endif
  const char *options="EO";
  WINDOW *window;
  unsigned int menu;
  int command;
  if(partition->upart_type==UP_EXT2 ||
      partition->upart_type==UP_EXT3)
    menu=0;
  else
    menu=1;
  window=newwin(0,0,0,0);	/* full screen */
  aff_copy(window);
  wmove(window,4,0);
  aff_part(window, AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition);
  wmove(window,6,0);
  waddstr(window,"To recover lost files, PhotoRec need to know the filesystem type where the");
  wmove(window,7,0);
  waddstr(window,"file were stored:");
  command = wmenuSelect_ext(window,8, 0, menuMode, 11,
      options, MENU_VERT | MENU_VERT_WARN | MENU_BUTTON, &menu,NULL);
  *mode_ext2=(command=='E' || command=='e');
  if(*mode_ext2>0)
  {
    log_info("EXT2/EXT3 mode activated.\n");
  }
  *carve_free_space_only=0;
  /*
  if((*mode_ext2)!=0)
    return 0;
   */
  {
    menu=0;
    options="FW";
    wmove(window,6,0);
    wclrtoeol(window);
    wmove(window,7,0);
    wclrtoeol(window);
    waddstr(window,"Please choose if all space need to be analysed:");
    if(partition->upart_type==UP_FAT16)
      command = wmenuSelect_ext(window,8, 0, menuFAT16, 11,
	  options, MENU_VERT | MENU_VERT_WARN | MENU_BUTTON, &menu,NULL);
    else if(partition->upart_type==UP_FAT32)
      command = wmenuSelect_ext(window,8, 0, menuFAT32, 11,
	  options, MENU_VERT | MENU_VERT_WARN | MENU_BUTTON, &menu,NULL);
#ifdef HAVE_LIBNTFS
    else if(partition->upart_type==UP_NTFS)
      command = wmenuSelect_ext(window,8, 0, menuNTFS, 11,
	  options, MENU_VERT | MENU_VERT_WARN | MENU_BUTTON, &menu,NULL);
#endif
#ifdef HAVE_LIBEXT2FS
    else if(partition->upart_type==UP_EXT2 || partition->upart_type==UP_EXT3)
      command = wmenuSelect_ext(window,8, 0, menuEXT2, 11,
	  options, MENU_VERT | MENU_VERT_WARN | MENU_BUTTON, &menu,NULL);
#endif
    else
      command='W';
    if(command=='F' || command=='f')
      *carve_free_space_only=1;
    if(*carve_free_space_only>0)
    {
      log_info("Carve free space only.\n");
    }
  }
  delwin(window);
  return 0;
}

static unsigned int menu_choose_blocksize(unsigned int blocksize, const unsigned int sector_size, uint64_t *offset)
{
  int command;
  unsigned int menu=0;
  const char *optionsBlocksize="51248736";
  static struct MenuItem menuBlocksize[]=
  {
	{'5',"512",""},
	{'1',"1024",""},
	{'2',"2048",""},
	{'4',"4096",""},
	{'8',"8192",""},
	{'7',"16384",""},
	{'3',"32768",""},
	{'6',"65536",""},
	{0,NULL,NULL}
  };
  switch(sector_size)
  {
    case 1024: optionsBlocksize+=1; break;
    case 2048: optionsBlocksize+=2; break;
    case 4096: optionsBlocksize+=3; break;
    case 8192: optionsBlocksize+=4; break;
    case 16384: optionsBlocksize+=5;break;
    case 32768: optionsBlocksize+=6; break;
    case 65536: optionsBlocksize+=7; break;
  }
  switch(blocksize)
  {
    case 512: menu=0; break;
    case 1024: menu=1; break;
    case 2048: menu=2; break;
    case 4096: menu=3; break;
    case 8192: menu=4; break;
    case 16384: menu=5; break;
    case 32768: menu=6; break;
    case 65536: menu=7; break;
  }
  aff_copy(stdscr);
  wmove(stdscr,INTER_PARTITION_Y-1,0);
  wprintw(stdscr,"Please select the block size, press Enter when done.");
  command = wmenuSelect_ext(stdscr,INTER_PARTITION_Y, INTER_PARTITION_X, menuBlocksize, 7,
      optionsBlocksize, MENU_VERT| MENU_BUTTON|MENU_VERT_WARN, &menu,NULL);
  switch(command)
  {
    case '5': blocksize=512; break;
    case '1': blocksize=1024; break;
    case '2': blocksize=2048; break;
    case '4': blocksize=4096; break;
    case '8': blocksize=8192; break;
    case '7': blocksize=16384; break;
    case '3': blocksize=32768; break;
    case '6': blocksize=65536; break;
  }
  if(*offset%sector_size!=0 || *offset>=blocksize)
    *offset=0;
  if(sector_size < blocksize)
  {
    unsigned int quit=0;
    aff_copy(stdscr);
    wmove(stdscr,INTER_PARTITION_Y-2,0);
    wprintw(stdscr,"Please select the offset (0 - %u). Press Up/Down to increase/decrease it,",blocksize-sector_size);
    wmove(stdscr,INTER_PARTITION_Y-1,0);
    wprintw(stdscr,"Enter when done.");
    do
    {
      wmove(stdscr,INTER_PARTITION_Y,0);
      wclrtoeol(stdscr);
      wprintw(stdscr,"Offset %u",(unsigned int)(*offset));
      switch(wgetch(stdscr))
      {
	case KEY_ENTER:
#ifdef PADENTER
	case PADENTER:
#endif
	case '\n':
	case '\r':
	  quit=1;
	  break;
	case KEY_PPAGE:
	case KEY_UP:
	case KEY_RIGHT:
	case '+':
	  if(*offset + sector_size < blocksize)
	    *offset+=sector_size;
	  break;
	case KEY_NPAGE:
	case KEY_DOWN:
	case KEY_LEFT:
	case '-':
	  if(*offset >= sector_size)
	    *offset-=sector_size;
	  break;
      }
    } while(quit==0);
  }
  log_info("blocksize=%u,offset=%u\n",blocksize,(unsigned int)*offset);
  return blocksize;
}
#endif

static int photorec_bf(disk_t *disk_car, partition_t *partition, const int verbose, const int paranoid, const char *recup_dir, const int interface, file_stat_t *file_stats, unsigned int *file_nbr, unsigned int *blocksize, alloc_data_t *list_search_space, const time_t real_start_time, unsigned int *dir_num, const photorec_status_t status, const unsigned int pass, const unsigned int expert, const unsigned int lowmem)
{
  struct td_list_head *search_walker = NULL;
  struct td_list_head *n= NULL;
  unsigned char *buffer_start;
  unsigned int read_size;
  unsigned int buffer_size;
  int ind_stop=0;
  int pass2=pass;
  read_size=((*blocksize)>8192?(*blocksize):8192);
  buffer_size=(*blocksize)+READ_SIZE;
  buffer_start=MALLOC(buffer_size);
  for(search_walker=list_search_space->list.prev, n=search_walker->prev;
      search_walker!=&list_search_space->list && ind_stop==0;
      search_walker=n,n=search_walker->prev)
  {
    alloc_data_t *current_search_space;
    unsigned char *buffer;
    unsigned char *buffer_olddata;
    uint64_t offset;
    int need_to_check_file;
    file_recovery_t file_recovery;
    current_search_space=td_list_entry(search_walker, alloc_data_t, list);
    offset=current_search_space->start;
    buffer_olddata=buffer_start;
    buffer=buffer_olddata+(*blocksize);
    reset_file_recovery(&file_recovery);
    memset(buffer_olddata,0,(*blocksize));
    disk_car->read(disk_car,READ_SIZE, buffer, offset);
#ifdef DEBUG_BF
    info_list_search_space(list_search_space, current_search_space, disk_car->sector_size, 0, verbose);
#endif
    log_flush();

    do
    {
      uint64_t old_offset=offset;
      need_to_check_file=0;
      if(offset==current_search_space->start)
      {
        file_recovery_t file_recovery_new;
        file_check_t *file_check;
        for(file_check=file_check_list;
            file_check!=NULL &&
            !((file_check->length==0 || memcmp(buffer + file_check->offset, file_check->value, file_check->length)==0) &&
              file_check->header_check(buffer, read_size, 0, &file_recovery, &file_recovery_new)!=0);
            file_check=file_check->next);
        file_recovery_new.file_stat=(file_check==NULL?NULL:file_check->file_stat);
        file_recovery_new.location.start=offset;
        if(file_recovery_new.file_stat!=NULL)
        {
          if(verbose>0)
          {
            log_info("%s header found at sector %lu\n",
                ((file_recovery_new.extension!=NULL && file_recovery_new.extension[0]!='\0')?
                 file_recovery_new.extension:file_recovery_new.file_stat->file_hint->description),
                (unsigned long)((offset-partition->part_offset)/disk_car->sector_size));
          }
          if(file_recovery.file_stat==NULL)
          { /* Header found => file found */
            memcpy(&file_recovery, &file_recovery_new, sizeof(file_recovery));
          }
          else if(file_recovery_new.file_stat->file_hint!=NULL)
          {
            if(verbose>0)
              log_verbose("New file found => stop the recovery of current file\n");
            need_to_check_file=1;
          }
        }
        else if(file_recovery.file_stat==NULL)
          need_to_check_file=1;	/* No header found => no file => stop */
      }
      if(file_recovery.file_stat!=NULL && file_recovery.handle==NULL)
      { /* Create new file */
        if(file_recovery.extension==NULL || file_recovery.extension[0]=='\0')
        {
          snprintf(file_recovery.filename,sizeof(file_recovery.filename)-1,"%s.%u/%c%u",recup_dir,
              *dir_num,(status==STATUS_EXT2_ON_SAVE_EVERYTHING||status==STATUS_EXT2_OFF_SAVE_EVERYTHING?'b':'f'),
              (unsigned int)((file_recovery.location.start-partition->part_offset)/disk_car->sector_size));
        }
        else
        {
          snprintf(file_recovery.filename,sizeof(file_recovery.filename)-1,"%s.%u/%c%u.%s",recup_dir,
              *dir_num,(status==STATUS_EXT2_ON_SAVE_EVERYTHING||status==STATUS_EXT2_OFF_SAVE_EVERYTHING?'b':'f'),
              (unsigned int)((file_recovery.location.start-partition->part_offset)/disk_car->sector_size), file_recovery.extension);
        }
        if(file_recovery.file_stat->file_hint->recover==1)
        {
          if(!(file_recovery.handle=fopen(file_recovery.filename,"w+b")))
          { 
            log_critical("Cannot create file %s\n", file_recovery.filename);
            ind_stop=2;
          }
        }
      }
      if(file_recovery.handle!=NULL)
      {
        if((status==STATUS_EXT2_ON || status==STATUS_EXT2_ON_SAVE_EVERYTHING) &&
            file_recovery.file_stat!=NULL && file_recovery.file_size_on_disk>=12*(*blocksize) &&
            ind_block(buffer,*blocksize)!=0)
        {
          list_append_block(&file_recovery.location,offset,*blocksize,0);
          file_recovery.file_size_on_disk+=*blocksize;
          if(verbose>1)
          {
            log_verbose("Skipping sector %10lu/%lu\n",(unsigned long)((offset-partition->part_offset)/disk_car->sector_size),(unsigned long)(partition->part_size/disk_car->sector_size));
          }
          memcpy(buffer,buffer_olddata,(*blocksize));
        }
        else
        {
          if(file_recovery.handle!=NULL)
          {
            if(fwrite(buffer,*blocksize,1,file_recovery.handle)<1)
            { 
              log_critical("Cannot write to file %s\n", file_recovery.filename);
              ind_stop=3;
            }
          }
          if(file_recovery.file_stat!=NULL)
          {
            int res=1;
            list_append_block(&file_recovery.location,offset,*blocksize,1);
            if(file_recovery.data_check!=NULL)
              res=file_recovery.data_check(buffer_olddata,2*(*blocksize),&file_recovery);
            file_recovery.file_size+=*blocksize;
            file_recovery.file_size_on_disk+=*blocksize;
            if(res==2)
            { /* EOF found */
              need_to_check_file=1;
            }
          }
        }
        if(file_recovery.file_stat!=NULL && file_recovery.file_stat->file_hint->max_filesize>0 && file_recovery.file_size>=file_recovery.file_stat->file_hint->max_filesize)
        {
          log_verbose("File should not be bigger than %llu, stop adding data\n",
              (long long unsigned)file_recovery.file_stat->file_hint->max_filesize);
          need_to_check_file=1;
        }
      }
      get_next_sector(list_search_space, &current_search_space, &offset, *blocksize);
      if(current_search_space==list_search_space)
        need_to_check_file=1;
      if(need_to_check_file==0)
      {
        buffer_olddata+=*blocksize;
        buffer+=*blocksize;
        if(old_offset+*blocksize!=offset || buffer+read_size>buffer_start+buffer_size)
        {
          memcpy(buffer_start,buffer_olddata,*blocksize);
          buffer_olddata=buffer_start;
          buffer=buffer_olddata+*blocksize;
          if(verbose>1)
          {
            log_verbose("Reading sector %10lu/%lu\n",
                (unsigned long)((offset-partition->part_offset)/disk_car->sector_size),
                (unsigned long)((partition->part_size-1)/disk_car->sector_size));
          }
          disk_car->read(disk_car,READ_SIZE, buffer, offset);
        }
      }
    } while(need_to_check_file==0);
    if(need_to_check_file==1)
    {
      if(file_finish(&file_recovery,recup_dir,paranoid,file_nbr, *blocksize, list_search_space, &current_search_space, &offset, dir_num,status,disk_car->sector_size,disk_car)<0)
      { /* BF */
        current_search_space=td_list_entry(search_walker, alloc_data_t, list);
        ind_stop=photorec_bf_aux(disk_car, partition, paranoid, recup_dir, interface, file_stats, file_nbr, &file_recovery, *blocksize, list_search_space, current_search_space, real_start_time, dir_num, status, pass2);
        pass2++;
      }
    }
  }
#ifdef HAVE_NCURSES
  photorec_info(stdscr, file_stats);
#endif
  return ind_stop;
}

static int photorec_bf_aux(disk_t *disk_car, partition_t *partition, const int paranoid, const char *recup_dir, const int interface, file_stat_t *file_stats, unsigned int *file_nbr, file_recovery_t *file_recovery, unsigned int blocksize, alloc_data_t *list_search_space, alloc_data_t *start_search_space, const time_t real_start_time, unsigned int *dir_num, const photorec_status_t status, const unsigned int pass)
{
  uint64_t offset;
  uint64_t original_offset_error, file_offset;
  long int save_seek;
  unsigned char *block_buffer;
  int blocs_to_skip,i;
  int ind_stop;
  int testbf=0;
  time_t previous_time=0;
  alloc_data_t *current_search_space;
  //Init. of the brute force
#ifdef DEBUG_BF
  log_trace("photorec_bf_aux location.start=%lu\n",
      (long unsigned)(file_recovery->location.start/disk_car->sector_size));
#endif
  original_offset_error=file_recovery->offset_error;

  file_recovery->handle=fopen(file_recovery->filename, "w+b");
  if(file_recovery->handle==NULL)
  {
    log_critical("Brute Force : Cannot create file %s\n", file_recovery->filename);
    return 2;
  }
  block_buffer=(unsigned char *) malloc(sizeof(unsigned char)*blocksize);

  current_search_space=start_search_space;
  /* We have offset==start_search_space->start==file_recovery->location.start */
  offset=start_search_space->start;;

  // Writing the file until the error location
#ifdef DEBUG_BF
  log_debug("Writing the file until the error location %llu\n", (long long unsigned)original_offset_error);
#endif
  //FIXME: Handle ext2/ext3, handle fwrite return value
  file_recovery->file_size=0;
  for(i=0; i<(original_offset_error+blocksize-1)/blocksize; i++)
  {
    disk_car->read(disk_car,blocksize, block_buffer, offset);
    fwrite(block_buffer, blocksize, 1, file_recovery->handle);
    list_append_block(&file_recovery->location, offset, blocksize, 1);
    file_recovery->file_size+=blocksize;
    get_next_sector(list_search_space, &current_search_space, &offset, blocksize);
  }
#ifdef DEBUG_BF
  log_trace("BF Amorce ");
  list_space_used(file_recovery, blocksize);
  log_trace("\n");
#endif
  //Main Loop
  do
  {
    ind_stop=0;
    for(file_offset=(original_offset_error+blocksize-1)/blocksize*blocksize;
        file_offset >= blocksize && (original_offset_error+blocksize-1)/blocksize*blocksize<file_offset+8*512 && ind_stop==0;
        file_offset -= blocksize)
    {
      alloc_data_t *extractblock_search_space;
      uint64_t extrablock_offset;
      /* Set extractblock_search_space & extrablock_offset to the begining of the potential extra block */
#ifdef DEBUG_BF
      log_debug("Set extractblock_search_space & extrablock_offset to the begining of the potential extra block\n");
#endif
      /* Get the last block added to the file */
      extrablock_offset=0;
      {
        const alloc_list_t *element;
        for(element=&file_recovery->location;element!=NULL;element=element->next)
          extrablock_offset=element->end/blocksize*blocksize;
      }
      /* Get the corresponding search_place */
      extractblock_search_space=td_list_entry(list_search_space->list.next, alloc_data_t, list);
      while(extractblock_search_space != list_search_space &&
          !(extractblock_search_space->start <= extrablock_offset &&
            extrablock_offset <= extractblock_search_space->end))
        extractblock_search_space=td_list_entry(extractblock_search_space->list.next, alloc_data_t, list);
      /* Update extractblock_search_space & extrablock_offset */
      get_next_sector(list_search_space, &extractblock_search_space, &extrablock_offset, blocksize);
      /* */
      for(blocs_to_skip=1; blocs_to_skip<=250 && ind_stop==0; blocs_to_skip++)
      {
        offset=extrablock_offset;
        current_search_space=extractblock_search_space;
        testbf++;
        if(interface!=0)
        {
          time_t current_time;
          current_time=time(NULL);
          if(current_time>previous_time)
          {
            previous_time=current_time;
#ifdef HAVE_NCURSES
            ind_stop=photorec_progressbar(stdscr, testbf, status, file_recovery->location.start, disk_car, partition, *file_nbr, current_time-real_start_time, file_stats);
#endif
            if(ind_stop!=0)
            {
              file_finish(file_recovery,recup_dir,paranoid,file_nbr,blocksize,list_search_space,&current_search_space, &offset, dir_num,status,disk_car->sector_size,disk_car);
              free(block_buffer);
              return ind_stop;
            }
          }
        }
        fseek(file_recovery->handle,file_offset,SEEK_SET);
        list_truncate(&file_recovery->location,file_offset);
        file_recovery->file_size=file_offset;
        /* Skip extra blocs */
#ifdef DEBUG_BF
        log_debug("Skip %u extra blocs\n", blocs_to_skip);
#endif
        for(i=0; i<blocs_to_skip;i++)
        {
          get_next_sector(list_search_space, &current_search_space, &offset, blocksize);
        }
        { /* Add remaining data blocs */
          uint64_t offset_error_tmp;
          file_recovery->offset_error=original_offset_error;
          do
          {
            offset_error_tmp=file_recovery->offset_error;
            file_recovery->file_size=file_offset;

            for (;file_recovery->file_size < file_recovery->offset_error+100*blocksize &&
                current_search_space != list_search_space;
                file_recovery->file_size+=blocksize)
            {
              /* FIXME: handle fwrite return value */
              disk_car->read(disk_car, blocksize, block_buffer, offset);
              fwrite(block_buffer, blocksize, 1, file_recovery->handle);
              list_append_block(&file_recovery->location, offset, blocksize, 1);
              get_next_sector(list_search_space, &current_search_space, &offset, blocksize);
            }
            save_seek=ftell(file_recovery->handle);
#ifdef DEBUG_BF
            log_trace("BF ");
            list_space_used(file_recovery, blocksize);
#endif
            file_recovery->file_check(file_recovery);
#ifdef DEBUG_BF
            log_trace("offset_error %llu %llu\n",
                (long long unsigned) file_recovery->offset_error,
                (long long unsigned) offset_error_tmp);
#endif
            log_flush();
            fseek(file_recovery->handle, save_seek, SEEK_SET);
          } while(file_recovery->offset_error/blocksize*blocksize > offset_error_tmp/blocksize*blocksize);
        }
        if(file_recovery->offset_error==0)
        { /* Recover the file */
          file_finish(file_recovery,recup_dir,paranoid,file_nbr,blocksize,list_search_space,&current_search_space, &offset, dir_num,status,disk_car->sector_size,disk_car);
          free(block_buffer);
          return ind_stop;
        }
        else if(file_recovery->offset_error/blocksize*blocksize >= original_offset_error+4096)
        { /* Try to recover file composed of multiple fragments */
          log_info("%s multiple fragment %llu -> %llu\n", file_recovery->filename,
              (unsigned long long)original_offset_error,
              (unsigned long long)file_recovery->offset_error);
          log_flush();
          original_offset_error=file_recovery->offset_error;
          ind_stop=2;
        }
      }
    }
  } while(ind_stop==2);
  /* Cleanup */
  file_finish(file_recovery,recup_dir,paranoid,file_nbr,blocksize,list_search_space,&current_search_space, &offset, dir_num,status,disk_car->sector_size,disk_car);
  free(block_buffer);
  return ind_stop;
}

static int photorec_aux(disk_t *disk_car, partition_t *partition, const int verbose, const int paranoid, const char *recup_dir, const int interface, file_stat_t *file_stats, unsigned int *file_nbr, unsigned int *blocksize, alloc_data_t *list_search_space, const time_t real_start_time, unsigned int *dir_num, const photorec_status_t status, const unsigned int pass, const unsigned int expert, const unsigned int lowmem)
{
  uint64_t offset=0;
  unsigned char *buffer_start;
  unsigned char *buffer_olddata;
  unsigned char *buffer;
  time_t start_time;
  time_t previous_time;
  int ind_stop=0;
  unsigned int buffer_size;
  unsigned int read_size;
  alloc_data_t *current_search_space;
  file_recovery_t file_recovery;
  static alloc_data_t list_file={
    .list = TD_LIST_HEAD_INIT(list_file.list)
  };
  static list_cluster_t list_cluster= {
    .list = TD_LIST_HEAD_INIT(list_cluster.list)
  };
#define READ_SIZE 256*512
  read_size=((*blocksize)>8192?(*blocksize):8192);
  buffer_size=(*blocksize)+READ_SIZE;
  buffer_start=MALLOC(buffer_size);
  buffer_olddata=buffer_start;
  buffer=buffer_olddata+(*blocksize);
  reset_file_recovery(&file_recovery);
  start_time=time(NULL);
  previous_time=start_time;
  memset(buffer_olddata,0,(*blocksize));
  current_search_space=td_list_entry(list_search_space->list.next, alloc_data_t, list);
  if(current_search_space!=list_search_space)
    offset=current_search_space->start;
  if(verbose>0)
    info_list_search_space(list_search_space, current_search_space, disk_car->sector_size, 0, verbose);
  disk_car->read(disk_car,READ_SIZE, buffer, offset);
  while(current_search_space!=list_search_space)
  {
    int move_next=1;
    uint64_t old_offset=offset;
#ifdef DEBUG
    log_debug("sector %llu\n",
        (unsigned long long)((offset-partition->part_offset)/disk_car->sector_size));
#endif
    if(!(current_search_space->start<=offset && offset<=current_search_space->end))
    {
      log_critical("BUG: offset=%llu not in [%llu-%llu]\n",
          (unsigned long long)(offset/disk_car->sector_size),
          (unsigned long long)(current_search_space->start/disk_car->sector_size),
          (unsigned long long)(current_search_space->end/disk_car->sector_size));
      log_flush();
      exit(1);
    }
    {
      file_recovery_t file_recovery_new;
      if(file_recovery.file_stat!=NULL &&
          file_recovery.file_stat->file_hint->min_header_distance > 0 &&
          file_recovery.file_size<=file_recovery.file_stat->file_hint->min_header_distance)
      {
      }
      else if(file_recovery.file_stat!=NULL && file_recovery.file_stat->file_hint==&file_hint_tar &&
          header_check_tar(buffer-0x200,0x200,0,&file_recovery,&file_recovery_new))
      { /* Currently saving a tar, do not check the data for know header */
        if(verbose>1)
        {
          log_verbose("Currently saving a tar file, sector %lu.\n",
              (unsigned long)((offset-partition->part_offset)/disk_car->sector_size));
        }
      }
      else
      {
        {
          file_check_t *file_check;
          for(file_check=file_check_list;file_check!=NULL &&
              !((file_check->length==0 || memcmp(buffer + file_check->offset, file_check->value, file_check->length)==0) &&
                file_check->header_check(buffer, read_size, (status==STATUS_FIND_OFFSET), &file_recovery, &file_recovery_new)!=0); file_check=file_check->next);
          file_recovery_new.file_stat=(file_check==NULL?NULL:file_check->file_stat);
          file_recovery_new.location.start=offset;
        }

        if(file_recovery_new.file_stat!=NULL && file_recovery_new.file_stat->file_hint!=NULL)
        {
          if(verbose>1)
            log_trace("A known header has been found, recovery of the previous file is finished\n");
          if(file_finish(&file_recovery,recup_dir,paranoid,file_nbr,*blocksize,list_search_space,&current_search_space, &offset, dir_num,status,disk_car->sector_size,disk_car)>0)
            move_next=0;
          reset_file_recovery(&file_recovery);
          if(lowmem>0)
            forget(list_search_space,current_search_space);
          if(move_next!=0)
          {
            memcpy(&file_recovery, &file_recovery_new, sizeof(file_recovery));
            if(verbose>1)
            {
              log_info("%s header found at sector %lu\n",
                  ((file_recovery.extension!=NULL && file_recovery.extension[0]!='\0')?
                   file_recovery.extension:file_recovery.file_stat->file_hint->description),
                  (unsigned long)((file_recovery.location.start-partition->part_offset)/disk_car->sector_size));
              log_info("file_recovery.location.start=%lu\n",
                  (unsigned long)(file_recovery.location.start/disk_car->sector_size));
            }

            if(status==STATUS_FIND_OFFSET)
            { /* Backup file offset */
              alloc_data_t *new_file_alloc;
              new_file_alloc=(alloc_data_t*)MALLOC(sizeof(*new_file_alloc));
              new_file_alloc->start=file_recovery.location.start;
              new_file_alloc->end=0;
              td_list_add_tail(&new_file_alloc->list,&list_file.list);
              (*file_nbr)++;
            }
            if(file_recovery.file_stat->file_hint==&file_hint_dir)
            {
              file_data_t *dir_list;
              dir_list=dir_fat_aux(buffer,read_size,0,0);
              if(dir_list!=NULL)
              {
                if(verbose>0)
                {
                  dir_aff_log(disk_car, partition, NULL, dir_list);
                }
                delete_list_file(dir_list);
              }
            }
          }
        }
      }
      if(file_recovery.file_stat!=NULL && file_recovery.handle==NULL)
      {
        if(file_recovery.extension==NULL || file_recovery.extension[0]=='\0')
        {
          snprintf(file_recovery.filename,sizeof(file_recovery.filename)-1,"%s.%u/%c%u",recup_dir,
              *dir_num,(status==STATUS_EXT2_ON_SAVE_EVERYTHING||status==STATUS_EXT2_OFF_SAVE_EVERYTHING?'b':'f'),
              (unsigned int)((file_recovery.location.start-partition->part_offset)/disk_car->sector_size));
        }
        else
        {
          snprintf(file_recovery.filename,sizeof(file_recovery.filename)-1,"%s.%u/%c%u.%s",recup_dir,
              *dir_num,(status==STATUS_EXT2_ON_SAVE_EVERYTHING||status==STATUS_EXT2_OFF_SAVE_EVERYTHING?'b':'f'),
              (unsigned int)((file_recovery.location.start-partition->part_offset)/disk_car->sector_size), file_recovery.extension);
        }
        if(file_recovery.file_stat->file_hint->recover==1 && status!=STATUS_FIND_OFFSET)
        {
          if(!(file_recovery.handle=fopen(file_recovery.filename,"w+b")))
          { 
            log_critical("Cannot create file %s\n", file_recovery.filename);
            ind_stop=2;
          }
        }
      }
    }
    /* try to skip ext2/ext3 indirect block */
#ifdef OLD
    /* EXT2_NDIR_BLOCKS=12 */
    if((status==STATUS_EXT2_ON || status==STATUS_EXT2_ON_SAVE_EVERYTHING) &&
        file_recovery.file_stat!=NULL &&
        ((file_recovery.file_size_on_disk==12*(*blocksize)) ||
         (file_recovery.file_size_on_disk==(12+1+(*blocksize)/4)*(*blocksize)) ||
         (file_recovery.file_size_on_disk%(*blocksize)==0 && file_recovery.file_size_on_disk>(12+1+(*blocksize)/4)*(*blocksize) && ((file_recovery.file_size_on_disk/(*blocksize))-(12+1))%((*blocksize)/4+1)==0)) &&
        (file_recovery.location.start>=current_search_space->start)
      )
#else
      if((status==STATUS_EXT2_ON || status==STATUS_EXT2_ON_SAVE_EVERYTHING) &&
          file_recovery.file_stat!=NULL && file_recovery.file_size_on_disk>=12*(*blocksize) &&
          ind_block(buffer,*blocksize)!=0)
#endif
      {
        list_append_block(&file_recovery.location,offset,*blocksize,0);
        file_recovery.file_size_on_disk+=*blocksize;
        if(verbose>1)
        {
          log_verbose("Skipping sector %10lu/%lu\n",
              (unsigned long)((offset-partition->part_offset)/disk_car->sector_size),
              (unsigned long)(partition->part_size/disk_car->sector_size));
        }
        memcpy(buffer,buffer_olddata,(*blocksize));
      }
      else
      {
        if(file_recovery.handle!=NULL)
        {
          if(fwrite(buffer,*blocksize,1,file_recovery.handle)<1)
          { 
            log_critical("Cannot write file %s\n", file_recovery.filename);
            ind_stop=3;
          }
        }
        if(file_recovery.file_stat!=NULL)
        {
          int res=1;
          list_append_block(&file_recovery.location,offset,*blocksize,1);
          if(file_recovery.data_check!=NULL)
            res=file_recovery.data_check(buffer_olddata,2*(*blocksize),&file_recovery);
          file_recovery.file_size+=*blocksize;
          file_recovery.file_size_on_disk+=*blocksize;
          if(res==2)
          {
            if(verbose>1)
              log_trace("EOF found\n");
            if(file_finish(&file_recovery,recup_dir,paranoid,file_nbr, *blocksize, list_search_space, &current_search_space, &offset, dir_num,status,disk_car->sector_size,disk_car)>0)
              move_next=0;
            reset_file_recovery(&file_recovery);
            if(lowmem>0)
              forget(list_search_space,current_search_space);
          }
        }
      }
    if(file_recovery.file_stat!=NULL && file_recovery.file_stat->file_hint->max_filesize>0 && file_recovery.file_size>=file_recovery.file_stat->file_hint->max_filesize)
    {
      log_verbose("File should not be bigger than %llu, stop adding data\n",
          (long long unsigned)file_recovery.file_stat->file_hint->max_filesize);
      if(file_finish(&file_recovery,recup_dir,paranoid,file_nbr,*blocksize, list_search_space, &current_search_space, &offset, dir_num,status,disk_car->sector_size,disk_car)>0)
        move_next=0;
      reset_file_recovery(&file_recovery);
      if(lowmem>0)
        forget(list_search_space,current_search_space);
    }

    if(ind_stop>0)
    {
      log_info("PhotoRec has been stopped\n");
      current_search_space=list_search_space;
    }
    else if(*file_nbr>=10 && status==STATUS_FIND_OFFSET)
    {
      current_search_space=list_search_space;
    }
    else if(move_next!=0)
    {
      get_next_sector(list_search_space, &current_search_space,&offset,*blocksize);
    }
    else // if(move_next==0)
    {
      /* try to recover the previous file, otherwise stay at the current location */
      get_prev_file_header(list_search_space, &current_search_space, &offset);
    }
    if(current_search_space==list_search_space)
    {
#ifdef DEBUG_GET_NEXT_SECTOR
      log_trace("current_search_space==list_search_space=%p (prev=%p,next=%p)\n",
          current_search_space, current_search_space->list.prev, current_search_space->list.next);
      log_trace("End of media\n");
#endif
      if(file_finish(&file_recovery,recup_dir,paranoid,file_nbr,*blocksize,list_search_space, &current_search_space, &offset, dir_num,status,disk_car->sector_size,disk_car)>0)
      {
        move_next=0;
        get_prev_file_header(list_search_space, &current_search_space, &offset);
      }
      reset_file_recovery(&file_recovery);
      if(lowmem>0)
        forget(list_search_space,current_search_space);
    }
    buffer_olddata+=*blocksize;
    buffer+=*blocksize;
    if(move_next==0 ||
        old_offset+*blocksize!=offset ||
        buffer+read_size>buffer_start+buffer_size)
    {
      if(move_next==0)
        memset(buffer_start,0,(*blocksize));
      else
        memcpy(buffer_start,buffer_olddata,*blocksize);
      buffer_olddata=buffer_start;
      buffer=buffer_olddata+*blocksize;
      if(verbose>1)
      {
        log_verbose("Reading sector %10lu/%lu\n",(unsigned long)((offset-partition->part_offset)/disk_car->sector_size),(unsigned long)((partition->part_size-1)/disk_car->sector_size));
      }
      if(disk_car->read(disk_car,READ_SIZE, buffer, offset)<0)
      {
#ifdef HAVE_NCURSES
        if(interface!=0)
        {
          wmove(stdscr,11,0);
          wclrtoeol(stdscr);
          wprintw(stdscr,"Error reading sector %10lu\n",
              (unsigned long)((offset-partition->part_offset)/disk_car->sector_size));
        }
#endif
      }
      if(interface!=0)
      {
        time_t current_time;
        current_time=time(NULL);
        if(current_time>previous_time)
        {
          previous_time=current_time;
#ifdef HAVE_NCURSES
          ind_stop=photorec_progressbar(stdscr, pass, status, offset, disk_car, partition, *file_nbr, current_time-real_start_time, file_stats);
#endif
        }
      }
    }
  } /* end while(current_search_space!=list_search_space) */
  if(status==STATUS_FIND_OFFSET)
  {
    uint64_t start_offset;
    *blocksize=find_blocksize(&list_file,disk_car->sector_size, &start_offset);
#ifdef HAVE_NCURSES
    if(expert>0)
      *blocksize=menu_choose_blocksize(*blocksize, disk_car->sector_size, &start_offset);
#endif
    update_blocksize(*blocksize,list_search_space, start_offset);
    free_list_search_space(&list_file);
    /* An expert can stop and manually set the blocksize without stopping the recovery */
    ind_stop=0;
  }
  free(buffer_start);
#ifdef HAVE_NCURSES
  photorec_info(stdscr, file_stats);
#endif
  return ind_stop;
}

#ifdef HAVE_NCURSES
static void recovery_finished(const unsigned int file_nbr, const char *recup_dir, const int ind_stop, char **current_cmd)
{
  wmove(stdscr,9,0);
  wclrtoeol(stdscr);
  wprintw(stdscr,"%u files saved in %s directory.\n",file_nbr,recup_dir);
  wmove(stdscr,10,0);
  wclrtoeol(stdscr);
  switch(ind_stop)
  {
    case 0:
      wprintw(stdscr,"Recovery completed.");
      break;
    case 1:
      wprintw(stdscr,"Recovery aborted by the user.");
      break;
    case 2:
      wprintw(stdscr,"Cannot create file in current directory.");
      break;
    case 3:
      wprintw(stdscr,"Cannot write file, no space left.");
      break;
  }
  wmove(stdscr,22,0);
  wclrtoeol(stdscr);
  wattrset(stdscr, A_REVERSE);
  wprintw(stdscr,"[ Quit ]");
  wattroff(stdscr, A_REVERSE);
  wrefresh(stdscr);
  while(1)
  {
    switch(wgetch(stdscr))
    {
      case KEY_ENTER:
#ifdef PADENTER
      case PADENTER:
#endif
      case '\n':
      case '\r':
      case 'q':
      case 'Q':
	return;
    }
  }
}
#endif


static void free_search_space(alloc_data_t *list_search_space)
{
  struct td_list_head *search_walker = NULL;
  struct td_list_head *search_walker_next = NULL;
  td_list_for_each_safe(search_walker,search_walker_next,&list_search_space->list)
  {
    alloc_data_t *current_search_space;
    current_search_space=td_list_entry(search_walker, alloc_data_t, list);
    td_list_del(search_walker);
    free(current_search_space);
  }
}

static int photorec(disk_t *disk_car, partition_t *partition, const int verbose, const int paranoid, char *recup_dir, const int keep_corrupted_file, const int interface, file_enable_t *files_enable, unsigned int mode_ext2, char **current_cmd, alloc_data_t *list_search_space, unsigned int blocksize, const unsigned int expert, const unsigned int lowmem, const unsigned int carve_free_space_only)
{
  char *new_recup_dir=NULL;
  file_stat_t *file_stats=NULL;
  time_t real_start_time;
  unsigned int file_nbr=0;
  unsigned int dir_num=1;
  int ind_stop=0;
  unsigned int pass;
  unsigned int blocksize_is_known=0;
  photorec_status_t status;
  aff_buffer(BUFFER_RESET,"Q");
  log_info("\nAnalyse\n");
  log_partition(disk_car,partition);
  if(blocksize==0 || td_list_empty(&list_search_space->list))
  {
    blocksize=disk_car->sector_size;
    blocksize_is_known=0;
  }
  else
    blocksize_is_known=1;

  if(td_list_empty(&list_search_space->list))
  {
    alloc_data_t *tmp=init_search_space(partition,disk_car);
    td_list_add_tail(&tmp->list, &list_search_space->list);
    if(carve_free_space_only>0)
    {
      blocksize=remove_used_space(disk_car, partition, list_search_space);
      if(blocksize==0)
        blocksize=disk_car->sector_size;
      else
        blocksize_is_known=1;
    }
  }
  else
  { /* Correct the values */
    struct td_list_head *search_walker = NULL;
    td_list_for_each(search_walker, &list_search_space->list)
    {
      alloc_data_t *current_search_space;
      current_search_space=td_list_entry(search_walker, alloc_data_t, list);
      current_search_space->start=current_search_space->start*disk_car->sector_size;
      current_search_space->end=current_search_space->end*disk_car->sector_size+disk_car->sector_size-1;
    }
  }
  {
    file_enable_t *file_enable;
    unsigned int enable_count=1;	/* Lists are terminated by NULL */
    for(file_enable=files_enable;file_enable->file_hint!=NULL;file_enable++)
    {
      if(file_enable->enable>0)
      {
        enable_count++;
      }
    }
    file_stats=MALLOC(enable_count * sizeof(file_stat_t));
    enable_count=0;
    for(file_enable=files_enable;file_enable->file_hint!=NULL;file_enable++)
    {
      if(file_enable->enable>0)
      {
        file_stats[enable_count].file_hint=file_enable->file_hint;
        file_stats[enable_count].not_recovered=0;
        file_stats[enable_count].recovered=0;
        if(file_enable->file_hint->register_header_check!=NULL)
          file_enable->file_hint->register_header_check(&file_stats[enable_count]);
        enable_count++;
      }
    }
    file_stats[enable_count].file_hint=NULL;
  }

  real_start_time=time(NULL);
  dir_num=photorec_mkdir(recup_dir,dir_num);
  status=STATUS_FIND_OFFSET;
  for(pass=0;status!=STATUS_QUIT;pass++)
  {
    unsigned int old_file_nbr=file_nbr;
    log_info("Pass %u (blocksize=%u) ",pass,blocksize);
    switch(status)
    {
      case STATUS_FIND_OFFSET:			log_info("STATUS_FIND_OFFSET\n");	break;
      case STATUS_EXT2_ON:			log_info("STATUS_EXT2_ON\n");	break;
      case STATUS_EXT2_ON_BF:			log_info("STATUS_EXT2_ON_BF\n");	break;
      case STATUS_EXT2_OFF:			log_info("STATUS_EXT2_OFF\n");	break;
      case STATUS_EXT2_OFF_BF:			log_info("STATUS_EXT2_OFF_BF\n");	break;
      case STATUS_EXT2_ON_SAVE_EVERYTHING:	log_info("STATUS_EXT2_ON_SAVE_EVERYTHING\n");	break;
      case STATUS_EXT2_OFF_SAVE_EVERYTHING:	log_info("STATUS_EXT2_OFF_SAVE_EVERYTHING\n");	break;
      case STATUS_QUIT :			log_info("STATUS_QUIT\n");			break;
    }
#ifdef HAVE_NCURSES
    if(interface)
    {
      aff_copy(stdscr);
      wmove(stdscr,4,0);
      wprintw(stdscr,"%s",disk_car->description_short(disk_car));
      mvwaddstr(stdscr,5,0,msg_PART_HEADER_LONG);
      wmove(stdscr,6,0);
      aff_part(stdscr,AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition);
      wmove(stdscr,22,0);
      wattrset(stdscr, A_REVERSE);
      waddstr(stdscr,"  Stop  ");
      wattroff(stdscr, A_REVERSE);
      wrefresh(stdscr);
    }
#endif
    if(status==STATUS_FIND_OFFSET && blocksize_is_known>0)
      ind_stop=0;
    else if(status==STATUS_EXT2_ON_BF || status==STATUS_EXT2_OFF_BF)
    {
      ind_stop=photorec_bf(disk_car, partition, verbose, paranoid, recup_dir, interface, file_stats, &file_nbr, &blocksize, list_search_space, real_start_time, &dir_num, status, pass,expert, lowmem);
      session_save(list_search_space, disk_car, partition, files_enable, blocksize, verbose);
    }
    else
    {
      ind_stop=photorec_aux(disk_car, partition, verbose, paranoid, recup_dir, interface, file_stats, &file_nbr, &blocksize, list_search_space, real_start_time, &dir_num, status, pass,expert, lowmem);
      session_save(list_search_space, disk_car, partition, files_enable, blocksize, verbose);
    }
    if(ind_stop==3)
    { /* no more space */
#ifdef HAVE_NCURSES
      char *res;
      res=ask_location("Warning: no free space available. Do you want to save recovered files in %s%s ? [Y/N]\nDo not choose to write the files to the same partition they were stored on.","");
      if(res==NULL)
        status=STATUS_QUIT;
      else
      {
        free(new_recup_dir);
        new_recup_dir=MALLOC(strlen(res)+1+strlen(DEFAULT_RECUP_DIR)+1);
        strcpy(new_recup_dir,res);
        strcat(new_recup_dir,"/");
        strcat(new_recup_dir,DEFAULT_RECUP_DIR);
        recup_dir=new_recup_dir;
        free(res);
        /* Create the directory */
        dir_num=photorec_mkdir(recup_dir,dir_num);
      }
#else
      status=STATUS_QUIT;
#endif
    }
    else if(ind_stop>0)
    {
      status=STATUS_QUIT;
    }
    else if(paranoid>0)
    {
      switch(status)
      {
        case STATUS_FIND_OFFSET:
          status=(mode_ext2>0?STATUS_EXT2_ON:STATUS_EXT2_OFF);
          file_nbr=0;
          break;
        case STATUS_EXT2_ON:
          status=(paranoid>1?STATUS_EXT2_ON_BF:STATUS_EXT2_OFF);
          break;
        case STATUS_EXT2_ON_BF:
          status=STATUS_EXT2_OFF;
          break;
        case STATUS_EXT2_OFF:
          if(paranoid>1)
          {
            status=STATUS_EXT2_OFF_BF;
          }
          else
          {
            if(keep_corrupted_file>0)
              status=(mode_ext2>0?STATUS_EXT2_ON_SAVE_EVERYTHING:STATUS_EXT2_OFF_SAVE_EVERYTHING);
            else
            {
              status=STATUS_QUIT;
              unlink("photorec.ses");
            }
          }
          break;
        case STATUS_EXT2_OFF_BF:
          if(keep_corrupted_file>0)
            status=(mode_ext2>0?STATUS_EXT2_ON_SAVE_EVERYTHING:STATUS_EXT2_OFF_SAVE_EVERYTHING);
          else
          {
            status=STATUS_QUIT;
            unlink("photorec.ses");
          }
          break;
        case STATUS_EXT2_ON_SAVE_EVERYTHING:
          status=STATUS_EXT2_OFF_SAVE_EVERYTHING;
          break;
        default:
          status=STATUS_QUIT;
          unlink("photorec.ses");
          break;
      }
    }
    else
    {
      switch(status)
      {
        case STATUS_FIND_OFFSET:
          status=(mode_ext2>0?STATUS_EXT2_ON_SAVE_EVERYTHING:STATUS_EXT2_OFF_SAVE_EVERYTHING);
          file_nbr=0;
          break;
        default:
          status=STATUS_QUIT;
          unlink("photorec.ses");
          break;
      }
    }
    {
      time_t current_time;
      current_time=time(NULL);
      log_info("Elapsed time %uh%02um%02us\n",
          (unsigned)((current_time-real_start_time)/60/60),
          (unsigned)((current_time-real_start_time)/60%60),
          (unsigned)((current_time-real_start_time)%60));
    }
    update_stats(file_stats,list_search_space);
    log_info("Pass %u +%u file%s\n",pass,file_nbr-old_file_nbr,(file_nbr-old_file_nbr<=1?"":"s"));
    write_stats_log(file_stats);
    if(interface==0)
    {
      printf("Pass %u +%u file%s\n",pass,file_nbr-old_file_nbr,(file_nbr-old_file_nbr<=1?"":"s"));
      write_stats_stdout(file_stats);
      fflush(stdout);
    }
  }
  info_list_search_space(list_search_space, NULL, disk_car->sector_size, keep_corrupted_file, verbose);
  /* Free memory */
  free_search_space(list_search_space);
#ifdef HAVE_NCURSES
  if(interface && *current_cmd==NULL)
    recovery_finished(file_nbr, recup_dir, ind_stop, current_cmd);
#endif
  free(file_stats);
  free_header_check();
  free(new_recup_dir);
  return 0;
}



static void menu_photorec(disk_t *disk_car, const int verbose, const char *recup_dir, file_enable_t *file_enable, char **current_cmd, alloc_data_t*list_search_space)
{
  int insert_error=0;
  list_part_t *list_part;
  list_part_t *element;
  partition_t *partition_wd;
  list_part_t *current_element;
  int allow_partial_last_cylinder=0;
  int paranoid=1;
  int keep_corrupted_file=0;
  int current_element_num;
  unsigned int mode_ext2=0;
  unsigned int blocksize=0;
  unsigned int expert=0;
  unsigned int lowmem=0;
  unsigned int carve_free_space_only=0;
  int done=0;
#ifdef HAVE_NCURSES
  int command;
  int offset=0;
  unsigned int menu=0;
  static struct MenuItem menuMain[]=
  {
	{'S',"Search","Start file recovery"},
	{'O',"Options","Modify options"},
	{'F',"File Opt","Modify file options"},
	{'G',"Geometry", "Change disk geometry" },
	{'Q',"Quit","Return to disk selection"},
	{0,NULL,NULL}
  };
#endif
  list_part=disk_car->arch->read_part(disk_car,verbose,0);
  partition_wd=new_whole_disk(disk_car);
  list_part=insert_new_partition(list_part, partition_wd, 0, &insert_error);
  if(insert_error>0)
  {
    free(partition_wd);
  }
  for(element=list_part;element!=NULL;element=element->next)
  {
    log_partition(disk_car,element->part);
  }
  if(list_part!=NULL && list_part->next!=NULL)
  {
    current_element_num=1;
    current_element=list_part->next;
  }
  else
  {
    current_element_num=0;
    current_element=list_part;
  }
  while(done==0)
  {
    if(*current_cmd!=NULL)
    {
      while(*current_cmd[0]==',')
	(*current_cmd)++;
      if(*current_cmd[0]=='\0')
      {
	part_free_list(list_part);
	return;
      }
      if(strncmp(*current_cmd,"search",6)==0)
      {
	char *res;
	(*current_cmd)+=6;
	if(recup_dir!=NULL)
	  res=recup_dir;
	else
	{
	  res=ask_location("Do you want to save recovered files in %s%s ? [Y/N]\nDo not choose to write the files to the same partition they were stored on.","");
	  if(res!=NULL)
	  {
	    char *new_recup_dir=MALLOC(strlen(res)+1+strlen(DEFAULT_RECUP_DIR)+1);
	    strcpy(new_recup_dir,res);
	    strcat(new_recup_dir,"/");
	    strcat(new_recup_dir,DEFAULT_RECUP_DIR);
	    if(res!=recup_dir)
	      free(res);
	    res=new_recup_dir;
	  }
	}
	if(res!=NULL)
	  photorec(disk_car, current_element->part, verbose, paranoid, res, keep_corrupted_file,1,file_enable,mode_ext2,current_cmd,list_search_space,blocksize,expert, lowmem, carve_free_space_only);
	if(res!=recup_dir)
	  free(res);
      }
      else if(strncmp(*current_cmd,"options",7)==0)
      {
	int old_allow_partial_last_cylinder=allow_partial_last_cylinder;
	(*current_cmd)+=7;
	interface_options_photorec(&paranoid, &allow_partial_last_cylinder,
	    &keep_corrupted_file, &mode_ext2, &expert, &lowmem, current_cmd);
	if(old_allow_partial_last_cylinder!=allow_partial_last_cylinder)
	  hd_update_geometry(disk_car,allow_partial_last_cylinder,verbose);
      }
      else if(strncmp(*current_cmd,"fileopt",7)==0)
      {
	(*current_cmd)+=7;
	interface_file_select(file_enable,current_cmd);
      }
      else if(strncmp(*current_cmd,"blocksize,",10)==0)
      {
	(*current_cmd)+=10;
	blocksize=atoi(*current_cmd);
	while(*current_cmd[0]!=',' && *current_cmd[0]!='\0')
	  (*current_cmd)++;
      }
      else if(strncmp(*current_cmd,"geometry,",9)==0)
      {
	(*current_cmd)+=9;
	change_geometry(disk_car,current_cmd);
      }
      else if(strncmp(*current_cmd,"inter",5)==0)
      {	/* Start interactive mode */
	*current_cmd=NULL;
      }
      else if(isdigit(*current_cmd[0]))
      {
	unsigned int order;
	order= atoi(*current_cmd);
	while(*current_cmd[0]!=',' && *current_cmd[0]!='\0')
	  (*current_cmd)++;
	for(element=list_part;element!=NULL && element->part->order!=order;element=element->next);
	if(element!=NULL)
	  current_element=element;
      }
      else
      {
	log_critical("error >%s<\n",*current_cmd);
	while(*current_cmd[0]!='\0')
	  (*current_cmd)++;
	part_free_list(list_part);
	return;
      }
    }
#ifdef HAVE_NCURSES
    else
    { /* ncurses interface */
      unsigned int i;
      aff_copy(stdscr);
      wmove(stdscr,4,0);
      wprintw(stdscr,"%s",disk_car->description_short(disk_car));
      mvwaddstr(stdscr,6,0,msg_PART_HEADER_LONG);
      for(i=0,element=list_part;(element!=NULL) && (i<offset);element=element->next,i++);
      for(i=offset;(element!=NULL) && ((i-offset)<INTER_SELECT);i++,element=element->next)
      {
	wmove(stdscr,5+2+i-offset,0);
	wclrtoeol(stdscr);	/* before addstr for BSD compatibility */
	if(element==current_element)
	{
	  wattrset(stdscr, A_REVERSE);
	  aff_part(stdscr,AFF_PART_ORDER|AFF_PART_STATUS,disk_car,element->part);
	  wattroff(stdscr, A_REVERSE);
	} else
	{
	  aff_part(stdscr,AFF_PART_ORDER|AFF_PART_STATUS,disk_car,element->part);
	}
      }
      command = wmenuSelect(stdscr,INTER_SELECT_Y, INTER_SELECT_X, menuMain, 8,
	  (expert==0?"SOFQ":"SOFGQ"), MENU_HORIZ | MENU_BUTTON | MENU_ACCEPT_OTHERS, menu);
      switch(command)
      {
	case KEY_UP:
	  if(current_element!=NULL)
	  {
	    if(current_element->prev!=NULL)
	    {
	      current_element=current_element->prev;
	      current_element_num--;
	    }
	    if(current_element_num<offset)
	      offset--;
	  }
	  break;
	case KEY_DOWN:
	  if(current_element!=NULL)
	  {
	    if(current_element->next!=NULL)
	    {
	      current_element=current_element->next;
	      current_element_num++;
	    }
	    if(current_element_num>=offset+INTER_SELECT)
	      offset++;
	  }
	  break;
	case 's':
	case 'S':
	  ask_mode_ext2(disk_car, current_element->part, &mode_ext2, &carve_free_space_only);
	  {
	    char *res;
	    menu=0;
	    if(recup_dir!=NULL)
	      res=recup_dir;
	    else
	    {
	      res=ask_location("Do you want to save recovered files in %s%s ? [Y/N]\nDo not choose to write the files to the same partition they were stored on.","");
	      if(res!=NULL)
	      {
		char *new_recup_dir=MALLOC(strlen(res)+1+strlen(DEFAULT_RECUP_DIR)+1);
		strcpy(new_recup_dir,res);
		strcat(new_recup_dir,"/");
		strcat(new_recup_dir,DEFAULT_RECUP_DIR);
		if(res!=recup_dir)
		  free(res);
		res=new_recup_dir;
	      }
	    }
	    if(res!=NULL)
	      photorec(disk_car, current_element->part, verbose, paranoid, res, keep_corrupted_file,1,file_enable,mode_ext2, current_cmd, list_search_space,blocksize,expert, lowmem, carve_free_space_only);
	    if(res!=recup_dir)
	      free(res);
	  }
	  break;
	case 'o':
	case 'O':
	  {
	    int old_allow_partial_last_cylinder=allow_partial_last_cylinder;
	    interface_options_photorec(&paranoid, &allow_partial_last_cylinder,
		&keep_corrupted_file, &mode_ext2, &expert, &lowmem, current_cmd);
	    if(old_allow_partial_last_cylinder!=allow_partial_last_cylinder)
	      hd_update_geometry(disk_car,allow_partial_last_cylinder,verbose);
	    menu=1;
	  }
	  break;
	case 'f':
	case 'F':
	  interface_file_select(file_enable, current_cmd);
	  menu=2;
	  break;
	case 'g':
	case 'G':
	  if(expert!=0)
	    change_geometry(disk_car, current_cmd);
	  break;
	case 'q':
	case 'Q':
	  done = 1;
	  break;
      }
    }
#endif
  }
  log_info("\n");
  part_free_list(list_part);
}

#ifdef HAVE_NCURSES
static void photorec_disk_selection_ncurses(int verbose, const char *recup_dir, const list_disk_t *list_disk, file_enable_t *file_enable)
{
  char * current_cmd=NULL;
  int command;
  int real_key;
  int done=0;
  unsigned int menu=0;
  int offset=0;
  int pos_num=0;
  const list_disk_t *element_disk;
  const list_disk_t *current_disk=list_disk;
  static struct MenuItem menuMain[]=
  {
    { 'P', "Previous",""},
    { 'N', "Next","" },
    { 'O',"Proceed",""},
    { 'Q',"Quit","Quit program"},
    { 0,NULL,NULL}
  };
  static alloc_data_t list_search_space={
    .list = TD_LIST_HEAD_INIT(list_search_space.list)
  };
  /* ncurses interface */
  while(done==0)
  {
    const char *options;
    int i;
    aff_copy(stdscr);
    wmove(stdscr,4,0);
    wprintw(stdscr,"  PhotoRec is free software, and");
    wmove(stdscr,5,0);
    wprintw(stdscr,"comes with ABSOLUTELY NO WARRANTY.");
    wmove(stdscr,7,0);
    wprintw(stdscr,"Select a media (use Arrow keys, then press Enter):");
    for(i=0,element_disk=list_disk;(element_disk!=NULL) && (i<offset);element_disk=element_disk->next,i++);
    for(;element_disk!=NULL && (i-offset)<10;i++,element_disk=element_disk->next)
    {
      wmove(stdscr,8+i-offset,0);
      if(element_disk!=current_disk)
	wprintw(stdscr,"%s\n",element_disk->disk->description_short(element_disk->disk));
      else
      {
	wattrset(stdscr, A_REVERSE);
	wprintw(stdscr,"%s\n",element_disk->disk->description_short(element_disk->disk));
	wattroff(stdscr, A_REVERSE);
      }
    }
    if(i<=10 && element_disk==NULL)
      options="OQ";
    else
      options="PNOQ";
    {
      int line=20;
#if defined(__CYGWIN__) || defined(__MINGW32__)
#else
#ifndef DJGPP
#ifdef HAVE_GETEUID
      if(geteuid()!=0)
      {
	wmove(stdscr,line++,0);
	wprintw(stdscr,"Note: Some disks won't appear unless you're root user.");
      }
#endif
#endif
#endif
      wmove(stdscr,line++,0);
      if(line==22)
	wprintw(stdscr,"Disk capacity must be correctly detected for a successful recovery.");
      else
	wprintw(stdscr,"Note: Disk capacity must be correctly detected for a successful recovery.");
      wmove(stdscr,line++,0);
      wprintw(stdscr,"If a disk listed above has incorrect size, check HD jumper settings, BIOS");
      wmove(stdscr,line++,0);
      wprintw(stdscr,"detection, and install the latest OS patches and disk drivers."); 
    }
    command = wmenuSelect_ext(stdscr,INTER_MAIN_Y, INTER_MAIN_X, menuMain, 8,
	options, MENU_HORIZ | MENU_BUTTON | MENU_ACCEPT_OTHERS, &menu,&real_key);
    switch(command)
    {
      case KEY_UP:
      case 'P':
	if(current_disk->prev!=NULL)
	{
	  current_disk=current_disk->prev;
	  pos_num--;
	}
	if(pos_num<offset)
	  offset--;
	break;
      case KEY_DOWN:
      case 'N':
	if(current_disk->next!=NULL)
	{
	  current_disk=current_disk->next;
	  pos_num++;
	}
	if(pos_num>=offset+INTER_MENU_DISK)
	  offset++;
	break;
      case KEY_PPAGE:
	for(i=0;i<INTER_MENU_DISK && current_disk->prev!=NULL;i++)
	{
	  current_disk=current_disk->prev;
	  pos_num--;
	  if(pos_num<offset)
	    offset--;
	}
	break;
      case KEY_NPAGE:
	for(i=0;i<INTER_MENU_DISK && current_disk->next!=NULL;i++)
	{
	  current_disk=current_disk->next;
	  pos_num++;
	  if(pos_num>=offset+INTER_MENU_DISK)
	    offset++;
	}
	break;
      case 'o':
      case 'O':
	{
	  disk_t *disk=current_disk->disk;
	  autodetect_arch(disk);
	  if(interface_partition_type(disk, verbose, &current_cmd)==0)
	    menu_photorec(disk, verbose, recup_dir, file_enable, &current_cmd, &list_search_space);
	}
	break;
      case 'q':
      case 'Q':
	done=1;
	break;
    }
  }
}
#endif

int do_curses_photorec(int verbose, const char *recup_dir, const list_disk_t *list_disk, file_enable_t *file_enable, char *cmd_device, char **current_cmd)
{
  const list_disk_t *current_disk=list_disk;
  static alloc_data_t list_search_space={
    .list = TD_LIST_HEAD_INIT(list_search_space.list)
  };
  if(cmd_device==NULL)
  {
    char *saved_device=NULL;
    char *saved_cmd=NULL;
    session_load(&saved_device, &saved_cmd,&list_search_space);
    if(saved_device!=NULL && saved_cmd!=NULL && !td_list_empty(&list_search_space.list) && ask_confirmation("Continue previous session ? (Y/N)")!=0)
    {
      /* yes */
      *current_cmd=saved_cmd;
      cmd_device=saved_device;
    }
    else
    {
      free(saved_device);
      free(saved_cmd);
      free_list_search_space(&list_search_space);
    }
  }
  if(cmd_device!=NULL)
  {
    const list_disk_t *element_disk;
    for(element_disk=list_disk;element_disk!=NULL;element_disk=element_disk->next)
    {
      if(strcmp(element_disk->disk->device,cmd_device)==0)
	current_disk=element_disk;
    }
  }
  if(current_disk==NULL)
  {
    return intrf_no_disk("PhotoRec");
  }
  if(*current_cmd!=NULL)
  {
    disk_t *disk=current_disk->disk;
    autodetect_arch(disk);
    if(interface_partition_type(disk, verbose, current_cmd)==0)
      menu_photorec(disk, verbose, recup_dir, file_enable, current_cmd, &list_search_space);
  }
  else
  {
#ifdef HAVE_NCURSES
    photorec_disk_selection_ncurses(verbose, recup_dir, list_disk, file_enable);
#endif
  }
  log_info("\n");
  return 0;
}

#ifdef HAVE_NCURSES
static void interface_options_photorec_ncurses(int *paranoid, int *allow_partial_last_cylinder, int *keep_corrupted_file, unsigned int *mode_ext2, unsigned int *expert, unsigned int *lowmem)
{
  unsigned int menu = 6;
  struct MenuItem menuOptions[]=
  {
    { 'P', NULL, "Check JPG files" },
    { 'A',NULL,"" },
    { 'K',NULL,"Keep corrupted files"},
    { 'S',NULL,"Try to skip indirect block"},
    { 'E',NULL,"Provide additional controls"},
    { 'L',NULL,"Low memory"},
    { 'Q',"Quit","Return to main menu"},
    { 0, NULL, NULL }
  };
  while (1)
  {
    int car;
    int real_key;
    switch(*paranoid)
    {
      case 0:
	menuOptions[0].name="Paranoid : No";
	break;
      case 1:
	menuOptions[0].name="Paranoid : Yes (Brute force disabled)";
	break;
      default:
	menuOptions[0].name="Paranoid : Yes (Brute force enabled)";
	break;
    }
    menuOptions[1].name=*allow_partial_last_cylinder?"Allow partial last cylinder : Yes":"Allow partial last cylinder : No";
    menuOptions[2].name=*keep_corrupted_file?"Keep corrupted files : Yes":"Keep corrupted files : No";
    menuOptions[3].name=*mode_ext2?"ext2/ext3 mode: Yes":"ext2/ext3 mode : No";
    menuOptions[4].name=*expert?"Expert mode : Yes":"Expert mode : No";
    menuOptions[5].name=*lowmem?"Low memory: Yes":"Low memory: No";
    /* Jpg
       Mov
       Mpg
       Minolta MRW
       Canon CRW
       Signa/Foveon X3F
       Fuji RAF
       Rollei RDC
       MP3

     */
    aff_copy(stdscr);
    car=wmenuSelect_ext(stdscr,INTER_OPTION_Y, INTER_OPTION_X, menuOptions, 0, "PAKELQ", MENU_VERT|MENU_VERT_ARROW2VALID, &menu,&real_key);
    switch(car)
    {
      case 'p':
      case 'P':
	if(*paranoid<2)
	  (*paranoid)++;
	else
	  *paranoid=0;
	break;
      case 'a':
      case 'A':
	*allow_partial_last_cylinder=!*allow_partial_last_cylinder;
	break;
      case 'k':
      case 'K':
	*keep_corrupted_file=!*keep_corrupted_file;
	break;
      case 's':
      case 'S':
	*mode_ext2=!*mode_ext2;
	break;
      case 'e':
      case 'E':
	*expert=!*expert;
	break;
      case 'l':
      case 'L':
	*lowmem=!*lowmem;
	break;
      case key_ESC:
      case 'q':
      case 'Q':
	return;
    }
  }
}
#endif

static void interface_options_photorec(int *paranoid, int *allow_partial_last_cylinder, int *keep_corrupted_file, unsigned int *mode_ext2, unsigned int *expert, unsigned int *lowmem, char **current_cmd)
{
  if(*current_cmd!=NULL)
  {
    int keep_asking=1;
    do
    {
      while(*current_cmd[0]==',')
	(*current_cmd)++;
      if(strncmp(*current_cmd,"mode_ext2",9)==0)
      {
	(*current_cmd)+=9;
	*mode_ext2=1;
      }
      else if(strncmp(*current_cmd,"expert",6)==0)
      {
	(*current_cmd)+=6;
	*expert=1;
      }
      else if(strncmp(*current_cmd,"lowmem",6)==0)
      {
	(*current_cmd)+=6;
	*lowmem=1;
      }
      else if(strncmp(*current_cmd,"keep_corrupted_file",19)==0)
      {
	(*current_cmd)+=19;
	*keep_corrupted_file=1;
      }
      else
	keep_asking=0;
    } while(keep_asking>0);
  }
  else
  {
#ifdef HAVE_NCURSES
    interface_options_photorec_ncurses(paranoid, allow_partial_last_cylinder, keep_corrupted_file, mode_ext2, expert, lowmem);
#endif
  }
  /* write new options to log file */
  log_info("New options :\n Paranoid : %s\n", *paranoid?"Yes":"No");
  log_info(" Brute force : %s\n", ((*paranoid)>1?"Yes":"No"));
  log_info(" Allow partial last cylinder : %s\n Keep corrupted files : %s\n ext2/ext3 mode : %s\n Expert mode : %s\n Low memory : %s\n",
      *allow_partial_last_cylinder?"Yes":"No",
      *keep_corrupted_file?"Yes":"No",
      *mode_ext2?"Yes":"No",
      *expert?"Yes":"No",
      *lowmem?"Yes":"No");
}

#ifdef HAVE_NCURSES
static void interface_file_select_ncurses(file_enable_t *files_enable)
{
  int current_element_num=0;
  int offset=0;
  int rewrite=1;
  unsigned int menu=0;
  int enable_status=files_enable[0].enable;
  static struct MenuItem menuAdv[]=
  {
    {'q',"Quit","Return to main menu"},
    {0,NULL,NULL}
  };
  while(1)
  {
    int i;
    int command;
    if(rewrite!=0)
    {
      aff_copy(stdscr);
      wmove(stdscr,4,0);
      wprintw(stdscr,"PhotoRec will try to locate the following files");
      rewrite=0;
    }
    wmove(stdscr,5,4);
    wclrtoeol(stdscr);
    if(offset>0)
      wprintw(stdscr,"Previous");
    for(i=offset;files_enable[i].file_hint!=NULL && ((i-offset)<INTER_SELECT);i++)
    {
      wmove(stdscr,6+i-offset,0);
      wclrtoeol(stdscr);	/* before addstr for BSD compatibility */
      if(i==current_element_num)
      {
	wattrset(stdscr, A_REVERSE);
	wprintw(stdscr,"[%c] %-4s %s", (files_enable[i].enable==0?' ':'X'),
	    (files_enable[i].file_hint->extension!=NULL?
	     files_enable[i].file_hint->extension:""),
	    files_enable[i].file_hint->description);
	wattroff(stdscr, A_REVERSE);
      } else
      {
	wprintw(stdscr,"[%c] %-4s %s", (files_enable[i].enable==0?' ':'X'),
	    (files_enable[i].file_hint->extension!=NULL?
	     files_enable[i].file_hint->extension:""),
	    files_enable[i].file_hint->description);
      }
    }
    wmove(stdscr,6+INTER_SELECT,4);
    wclrtoeol(stdscr);	/* before addstr for BSD compatibility */
    if(files_enable[i].file_hint!=NULL)
      wprintw(stdscr,"Next");
    wmove(stdscr,6+INTER_SELECT+1,0);
    wclrtoeol(stdscr);
    wprintw(stdscr,"Press ");
    if(has_colors())
      wbkgdset(stdscr,' ' | A_BOLD | COLOR_PAIR(0));
    wprintw(stdscr,"s");
    if(has_colors())
      wbkgdset(stdscr,' ' | COLOR_PAIR(0));
    if(enable_status==0)
      wprintw(stdscr," for default selection, ");
    else
      wprintw(stdscr," to disable all file famillies, ");
    if(has_colors())
      wbkgdset(stdscr,' ' | A_BOLD | COLOR_PAIR(0));
    wprintw(stdscr,"b");
    if(has_colors())
      wbkgdset(stdscr,' ' | COLOR_PAIR(0));
    wprintw(stdscr," to save the settings");
    command = wmenuSelect(stdscr,INTER_SELECT_Y, INTER_SELECT_X, menuAdv, 8,
	"q", MENU_BUTTON | MENU_ACCEPT_OTHERS, menu);
    switch(command)
    {
      case KEY_UP:
	if(current_element_num>0)
	{
	  current_element_num--;
	  if(current_element_num<offset)
	    offset--;
	}
	break;
      case KEY_PPAGE:
	for(i=0;(i<INTER_SELECT) && (current_element_num>0);i++)
	{
	  current_element_num--;
	  if(current_element_num<offset)
	    offset--;
	}
	break;
      case KEY_DOWN:
	if(files_enable[current_element_num+1].file_hint!=NULL)
	{
	  current_element_num++;
	  if(current_element_num>=offset+INTER_SELECT)
	    offset++;
	}
	break;
      case KEY_NPAGE:
	for(i=0;(i<INTER_SELECT) && (files_enable[current_element_num+1].file_hint!=NULL);i++)
	{
	  current_element_num++;
	  if(current_element_num>=offset+INTER_SELECT)
	    offset++;
	}
	break;
      case KEY_RIGHT:
      case '+':
      case ' ':
      case KEY_LEFT:
      case '-':
      case 'x':
      case 'X':
	files_enable[current_element_num].enable=1-files_enable[current_element_num].enable;
	break;
      case 's':
      case 'S':
	{
	  enable_status=1-enable_status;
	  if(enable_status==0)
	  {
	    file_enable_t *file_enable;
	    for(file_enable=&files_enable[0];file_enable->file_hint!=NULL;file_enable++)
	      file_enable->enable=0;
	  }
	  else
	    reset_list_file_enable(files_enable);
	}
	break;
      case 'b':
      case 'B':
	if(file_options_save(files_enable)<0)
	{
	  display_message("Failed to save the settings.");
	}
	else
	{
	  display_message("Settings recorded successfully.");
	}
	break;
      case 'q':
      case 'Q':
	return;
    }
  }
}
#endif

static void interface_file_select(file_enable_t *files_enable, char**current_cmd)
{
  log_info("\nInterface File Select\n");
  if(*current_cmd!=NULL)
  {
    int keep_asking;
    do
    {
      file_enable_t *file_enable;
      keep_asking=0;
      while(*current_cmd[0]==',')
	(*current_cmd)++;
      if(strncmp(*current_cmd,"everything",10)==0)
      {
	int enable_status;
	keep_asking=1;
	(*current_cmd)+=10;
	while(*current_cmd[0]==',')
	  (*current_cmd)++;
	if(strncmp(*current_cmd,"enable",6)==0)
	{
	  (*current_cmd)+=6;
	  enable_status=1;
	}
	else if(strncmp(*current_cmd,"disable",7)==0)
	{
	  (*current_cmd)+=7;
	  enable_status=0;
	}
	else
	{
	  log_critical("Syntax error %s\n",*current_cmd);
	  return;
	}
	for(file_enable=&files_enable[0];file_enable->file_hint!=NULL;file_enable++)
	  file_enable->enable=enable_status;
      }
      else
      {
	unsigned int cmd_length=0;
	while((*current_cmd)[cmd_length]!='\0' && (*current_cmd)[cmd_length]!=',')
	  cmd_length++;
	for(file_enable=&files_enable[0];file_enable->file_hint!=NULL;file_enable++)
	{
	  if(file_enable->file_hint->extension!=NULL &&
	      strlen(file_enable->file_hint->extension)==cmd_length &&
	      memcmp(file_enable->file_hint->extension,*current_cmd,cmd_length)==0)
	  {
	    keep_asking=1;
	    (*current_cmd)+=cmd_length;
	    while(*current_cmd[0]==',')
	      (*current_cmd)++;
	    if(strncmp(*current_cmd,"enable",6)==0)
	    {
	      (*current_cmd)+=6;
	      file_enable->enable=1;
	    }
	    else if(strncmp(*current_cmd,"disable",7)==0)
	    {
	      (*current_cmd)+=7;
	      file_enable->enable=0;
	    }
	    else
	    {
	      log_critical("Syntax error %s\n",*current_cmd);
	      return;
	    }
	  }
	}
      }
    } while(keep_asking>0);
    return;
  }
#ifdef HAVE_NCURSES
  interface_file_select_ncurses(files_enable);
#endif
}

#ifdef DEBUG_GET_NEXT_SECTOR
void bug(void)
{
  log_critical("bug\n");
}
#endif


