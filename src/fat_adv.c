/*

    File: fat_adv.c

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
#include <ctype.h>
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#include "types.h"
#include "common.h"
#include "fat.h"
#include "fat_common.h"
#include "lang.h"
#include "fnctdsk.h"
#include "intrf.h"
#include "intrfn.h"
#include "dir.h"
#include "dirpart.h"
#include "fat_dir.h"
#include "io_redir.h"
#include "log.h"
#include "log_part.h"
#include "fat_adv.h"
#include "fat_cluster.h"
#ifdef HAVE_NCURSES
#include "fatn.h"
#endif

#define INTER_FAT_ASK_X 0
#define INTER_FAT_ASK_Y	23
#define INTER_FATBS_X		0
#define INTER_FATBS_Y		22

typedef struct info_offset_struct info_offset_t;

struct info_offset_struct
{
  unsigned long int offset;
  unsigned int  nbr;
  unsigned int  fat_type;
};

static upart_type_t fat_find_info(disk_t *disk_car,unsigned int*reserved, unsigned int*fat_length, const partition_t *partition, const uint64_t max_offset, const int p_fat12, const int p_fat16, const int p_fat32, const int verbose, const int dump_ind, const unsigned int expert, unsigned int *fats);
static int fat_find_type(disk_t *disk_car, const partition_t *partition, const uint64_t max_offset, const int p_fat12, const int p_fat16, const int p_fat32, const int verbose, const int dump_ind, unsigned int *nbr_offset, info_offset_t *info_offset, const unsigned int max_nbr_offset);

static unsigned int fat_find_fat_start(const unsigned char *buffer,const int p_fat12, const int p_fat16, const int p_fat32,unsigned long int*fat_offset, const unsigned int sector_size);

static void create_fat_boot_sector(disk_t *disk_car, partition_t *partition, const unsigned int reserved, const int verbose, const unsigned int dir_entries, const unsigned long int root_cluster, const unsigned int sectors_per_cluster, const unsigned int fat_length, const upart_type_t upart_type, const unsigned int fats, char **current_cmd);
static unsigned int fat32_find_root_cluster(disk_t *disk_car,const partition_t *partition,const unsigned int sectors_per_cluster, const unsigned long int no_of_cluster, const unsigned int reserved, const unsigned int fat_length, const int verbose, const unsigned int expert, const unsigned int first_free_cluster, const unsigned int fats);
static int write_FAT_boot_code_aux(unsigned char *buffer);
static int find_dir_entries(disk_t *disk_car,const partition_t *partition, const unsigned int offset,const int verbose);
static int analyse_dir_entries(disk_t *disk_car,const partition_t *partition, const unsigned int offset, const int verbose);
static int analyse_dir_entries2(disk_t *disk_car,const partition_t *partition, const unsigned int reserved, const unsigned int fat_length,const int verbose, unsigned int root_size_max,const upart_type_t upart_type, const unsigned int fats);
static int calcul_sectors_per_cluster(const upart_type_t upart_type, const unsigned long int data_size, const unsigned int fat_length, const unsigned int sector_size);
static int check_FAT_dir_entry(const unsigned char *entry, const unsigned int entry_nr);
static unsigned long int get_subdirectory(disk_t *disk_car,const uint64_t hd_offset, const unsigned long int i);

#ifdef HAVE_NCURSES
static int fat32_create_rootdir(disk_t *disk_car,const partition_t *partition, const unsigned int reserved, const unsigned int fat_length, const unsigned int root_cluster, const unsigned int sectors_per_cluster, const int verbose, file_info_t *rootdir_list, const unsigned int fats);
static upart_type_t select_fat_info(const info_offset_t *info_offset, const unsigned int nbr_offset,unsigned int*reserved, unsigned int*fat_length, const unsigned long int max_sector_offset, unsigned int *fats);
#endif

/*
 * 0 entry is free
 * 1 entry is used
 * 2 not an entry
 * */
static int check_FAT_dir_entry(const unsigned char *entry, const unsigned int entry_nr)
{
  int i;
  if((entry[0xB]&ATTR_EXT_MASK)==ATTR_EXT)
    return 1;
/* log_trace("check_FAT_dir_entry %02x\n",*(entry+0)); */
  if(entry[0]==0)
  {
    for(i=0;i<0x20;i++)
      if(entry[i]!='\0')
        return 2;
    return 0;
  }
  if(entry[0]==0x20)
    return 2;
  if(entry[0]==0xE5)
    return 1;
  if(entry_nr<10 && (entry[0xB]&ATTR_VOLUME)==ATTR_VOLUME)
    return 1;
  for(i=0;i<8+3;i++)
  {
    const unsigned char car=entry[i];
    if((car>=0x06 && car<=0x1f)||
      (car>=0x3a && car<=0x3f)||
      (car>='a' && car<='z'))
      return 2;
    switch(car)
    {
      case 0x1:
      case 0x2:
      case 0x3:
      case 0x4:
      case '"':
      case '*':
      case '+':
      case ',':
      case '.':
      case '/':
      case '[':
      case '\\':
      case ']':
      case '|':
/*log_trace("check_FAT_dir_entry bad  %c (%02x)\n",car,car); */
	return 2;
      default:
/*log_trace("check_FAT_dir_entry good %c (%02x)\n",car,car); */
	break;
    }
  }
  return 1;
}

/* */


static unsigned long int get_subdirectory(disk_t *disk_car,const uint64_t hd_offset,const unsigned long int i)
{
  unsigned char buffer[DEFAULT_SECTOR_SIZE];
  const struct msdos_dir_entry *entry1=(const struct msdos_dir_entry *)&buffer[0];
  const struct msdos_dir_entry *entry2=(const struct msdos_dir_entry *)&buffer[0x20];
  if(disk_car->pread(disk_car, &buffer, sizeof(buffer), hd_offset) != sizeof(buffer))
  {
    log_error("fat_dir, get_subdirectory(), can't read directory\n");
    return 1;
  }
  if(!is_fat_directory(buffer))
    return 1;
  if(fat_get_cluster_from_entry(entry1) != i)
    return 1;
  return fat_get_cluster_from_entry(entry2);
}

#ifdef HAVE_NCURSES
#define INTER_DIR 16

static int ask_root_directory(const disk_t *disk_car, const partition_t *partition, const file_info_t*dir_list, const unsigned long int cluster)
{
  /* Return value
   * -1: quit
   *  1: back
   *  other: new cluster
   * */
  int car;
  int quit=0;
  int offset=0;
  int pos_num=0;
  struct td_list_head *pos=dir_list->list.next;
  WINDOW *window;
  window=newwin(LINES, COLS, 0, 0);	/* full screen */
  aff_copy(window);
  wmove(window,4,0);
  aff_part(window,AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition);
  wmove(window,6,0);
  wprintw(window,"Answer Y(es), N(o), Q(uit) or A(bort interactive mode). N or A if not sure.");
  curs_set(1);
  do
  {
    int i;
    struct td_list_head *file_walker = NULL;
    for(i=0, file_walker=dir_list->list.next;
	file_walker!=&dir_list->list && i<offset;
	file_walker=file_walker->next,i++);
    for(i=offset;
	file_walker!=&dir_list->list && (i-offset)<INTER_DIR;
	file_walker=file_walker->next,i++)
    {
      const file_info_t *current_file=td_list_entry_const(file_walker, const file_info_t, list);
      char str[11];
      char		datestr[80];
      wmove(window,8+i-offset,0);
      wclrtoeol(window);	/* before addstr for BSD compatibility */
      if(&current_file->list==pos)
      {
	wattrset(window, A_REVERSE);
	waddstr(window, ">");
      }
      else
	waddstr(window, " ");
      set_datestr((char *)&datestr, sizeof(datestr), current_file->td_mtime);
      mode_string(current_file->st_mode, str);
      wprintw(window, "%s %3u %3u ", 
	  str, (unsigned int)current_file->st_uid, (unsigned int)current_file->st_gid);
      wprintw(window, "%9llu", (long long unsigned int)current_file->st_size);
      /* FIXME: screen overlaps due to long filename */
      wprintw(window, " %s %s\n", datestr, current_file->name);
      if(&current_file->list==pos)
	wattroff(window, A_REVERSE);
    }
    /* Clear the last line, useful if overlapping */
    wmove(window,8+i-offset,0);
    wclrtoeol(window);	/* before addstr for BSD compatibility */
    /* print the cluster in the loop, so */
    /* the visible cursor will be at the end */
    wmove(window,5,0);
    wprintw(window,"Cluster %lu, Directory / found ? ", cluster);
    wrefresh(window);
    car=wgetch(window);
    switch(car)
    {
      case 'a':
      case 'A':
      case 'y':
      case 'Y':
      case 'n':
      case 'N':
      case 'Q':
      case 'q':
	quit=1;
	break;
    }
    if(!td_list_empty(&dir_list->list))
    {
      switch(car)
      {
	case KEY_UP:
	  if(pos->prev!=&dir_list->list)
	  {
	    pos=pos->prev;
	    pos_num--;
	  }
	  break;
	case KEY_DOWN:
	  if(pos->next!=&dir_list->list)
	  {
	    pos=pos->next;
	    pos_num++;
	  }
	  break;
	case KEY_PPAGE:
	  for(i=0; i<INTER_DIR-1 && pos->prev!=&dir_list->list; i++)
	  {
	    pos=pos->prev;
	    pos_num--;
	  }
	  break;
	case KEY_NPAGE:
	  for(i=0; i<INTER_DIR-1 && pos->next!=&dir_list->list; i++)
	  {
	    pos=pos->next;
	    pos_num++;
	  }
	  break;
      }
      if(pos_num<offset)
	offset=pos_num;
      if(pos_num>=offset+INTER_DIR)
	offset=pos_num-INTER_DIR+1;
    }
  } while(quit==0);
  curs_set(0);
  wprintw(window,"%c\n",car);
  delwin(window);
  (void) clearok(stdscr, TRUE);
#ifdef HAVE_TOUCHWIN
  touchwin(stdscr);
#endif
  return toupper(car);
}
#endif

static int is_root_cluster_candidat(const file_info_t *dir_list)
{
  const file_info_t *file1=td_list_first_entry(&dir_list->list, const file_info_t, list);
  const file_info_t *file2=td_list_next_entry(file1, list);
  return (!td_list_empty(&dir_list->list) && (&file2->list==&dir_list->list || file1->st_ino!=file2->st_ino));
}

static unsigned int fat32_find_root_cluster(disk_t *disk_car,const partition_t *partition,const unsigned int sectors_per_cluster, const unsigned long int no_of_cluster,const unsigned int reserved, const unsigned int fat_length, const int verbose, const unsigned int expert, const unsigned int first_free_cluster, const unsigned int fats)
{
  unsigned long int root_cluster=0;
  const uint64_t start_data=reserved+fats*fat_length;
  const unsigned int cluster_size=sectors_per_cluster*disk_car->sector_size;
  if(verbose>0)
    log_trace("fat32_find_root_cluster(sectors_per_cluster=%u,no_of_cluster=%lu,reserved=%u,fat_length=%u,expert=%u,first_free_cluster=%u)\n",sectors_per_cluster,no_of_cluster,reserved,fat_length,expert,first_free_cluster);
  if(sectors_per_cluster==0)
    return 0;
  {
    unsigned int dir_nbr=0;
#ifdef HAVE_NCURSES
    int interactive=1;
#endif
    unsigned char *buffer;
    int ind_stop=0;
    file_info_t rootdir_list;
    TD_INIT_LIST_HEAD(&rootdir_list.list);
    buffer=(unsigned char *)MALLOC(cluster_size);
#ifdef HAVE_NCURSES
    wmove(stdscr,22,0);
    wattrset(stdscr, A_REVERSE);
    waddstr(stdscr,"  Stop  ");
    wattroff(stdscr, A_REVERSE);
#endif
    for(root_cluster=2;(root_cluster<2+no_of_cluster)&&(ind_stop==0);root_cluster++)
    {
#ifdef HAVE_NCURSES
      const unsigned long int percent=root_cluster*100/(2+no_of_cluster);
      if((root_cluster&0xfff)==0)
      {
        wmove(stdscr,9,0);
        wclrtoeol(stdscr);
        wprintw(stdscr,"Search root cluster %10lu/%lu %lu%%",root_cluster,2+no_of_cluster,percent);
        wrefresh(stdscr);
        ind_stop|=check_enter_key_or_s(stdscr);
      }
#endif
      if((unsigned)disk_car->pread(disk_car, buffer, cluster_size,
	    partition->part_offset + (start_data + (uint64_t)(root_cluster - 2) * sectors_per_cluster) *
	    disk_car->sector_size) == cluster_size)
      {
	const struct msdos_dir_entry *entry1=(const struct msdos_dir_entry *)&buffer[0];
	const struct msdos_dir_entry *entry2=(const struct msdos_dir_entry *)&buffer[0x20];
        if(verbose>1)
        {
          log_verbose("fat32_find_root_cluster test cluster=%lu\n",root_cluster);
          /*
             dump_ncurses(buffer,cluster_size);
           */
        }
        if(buffer[0]=='.' && is_fat_directory(buffer))
        { /* Directory found */
          if(fat_get_cluster_from_entry(entry2)==0 &&
	      buffer[0x40]!=0) /* First-level directory with files */
          {
	    file_info_t dir_list;
	    TD_INIT_LIST_HEAD(&dir_list.list);
            log_info("First-level directory found at cluster %lu\n",root_cluster);
            dir_fat_aux(buffer, cluster_size, 0, &dir_list);
            if(verbose>0)
            {
              dir_aff_log(NULL, &dir_list);
            }
            {
	      const file_info_t *first_entry=td_list_first_entry(&dir_list.list, const file_info_t, list);
              file_info_t *new_file=(file_info_t *)MALLOC(sizeof(*new_file));
              memcpy(new_file, first_entry, sizeof(*new_file));
	      new_file->name=(char*)MALLOC(32);
              snprintf(new_file->name, 32,"DIR%05u",++dir_nbr);
	      td_list_add_tail(&new_file->list, &rootdir_list.list);
            }
            delete_list_file(&dir_list);
          }
        }
        else if(memcmp(entry1, entry2, 0x20)!=0)
        {	/* Potential root directory */
          unsigned int i,found=1;
          int etat=0,nb_subdir=0,nb_subdir_ok=0;
          for(i=0; found && i<cluster_size/0x20; i++)
          {
            int res=check_FAT_dir_entry(&buffer[i*0x20],i);
            if(verbose>2)
              log_verbose("fat32_find_root_cluster root_cluster=%lu i=%u etat=%d res=%d\n",root_cluster,i,etat,res);
            switch(res)
            {
              case 0:
                if(etat==0)
                  etat=1;
                break;
              case 1:
                if(etat==1)
                {
                  etat=2;
                  found=0;
                }
                break;
              case 2:
                found=0;
                break;
            }
            if((buffer[i*0x20]!=DELETED_FLAG) && (buffer[i*0x20+0xB]!= ATTR_EXT && (buffer[i*0x20+0xB]&ATTR_DIR)!=0)) /* Test directory */
            {
              nb_subdir++;
            }
          }
          for(i=0;found && (i<cluster_size/32);i++)
          {
	    const struct msdos_dir_entry *entry=(const struct msdos_dir_entry *)&buffer[i*0x20];
            if((buffer[i*0x20]!=DELETED_FLAG) && (buffer[i*0x20+0xB]!= ATTR_EXT && (buffer[i*0x20+0xB]&ATTR_DIR)!=0)) /* Test directory */
            {
              const unsigned int cluster=fat_get_cluster_from_entry(entry);
              /*	  log_debug("cluster %u\n",cluster); */
              if(cluster>2+no_of_cluster ||
                  get_subdirectory(disk_car,
                    partition->part_offset+(start_data+(uint64_t)(cluster-2)*sectors_per_cluster) * disk_car->sector_size,
                    cluster)!=0)
              {
                /*	    if(verbose) */
                /*	      log_debug("failed with %s\n",&buffer[i*0x20]); */
              }
              else
                nb_subdir_ok++;
            }
          }
          if(found)
          {
            if((nb_subdir_ok>nb_subdir*0.90)&&(nb_subdir>=3))
            {
              unsigned long int new_root_cluster;
              unsigned long int tmp=root_cluster;
              int back;	/* To avoid an endless loop... */
              /* Il faut ajouter un parcours arriere de la FAT 
               * car on localise le dernier cluster du root_cluster */
              if(verbose>0)
                log_verbose("cluster %lu, etat=%d, found=%u,nb_subdir=%d,nb_subdir_ok=%d\n",
		    root_cluster, etat, found, nb_subdir, nb_subdir_ok);
	      for(back=0; back<10; back++)
	      {
		new_root_cluster=tmp;
		tmp=fat32_get_prev_cluster(disk_car,partition,reserved,new_root_cluster,no_of_cluster);
		if(verbose>0)
		  log_verbose("prev cluster(%lu)=>%lu\n",new_root_cluster,tmp);
		if(tmp==0)
		{
		  free(buffer);
		  return new_root_cluster;
		}
		/* Check cluster number */
		if((tmp<2) || (tmp>=2+no_of_cluster))
		{
		  log_error("bad cluster number\n");
		  free(buffer);
		  return new_root_cluster;
		}
		/* Read the cluster */
		if((unsigned)disk_car->pread(disk_car, buffer, cluster_size,
		      partition->part_offset + (start_data + (uint64_t)(tmp - 2) * sectors_per_cluster) * disk_car->sector_size) != cluster_size)
		{
		  log_critical("cluster can't be read\n");
		  free(buffer);
		  return new_root_cluster;
		}
		/* Check if this cluster is a directory structure. FAT can be damaged */
		for(i=0;i<cluster_size/32;i++)
		{
		  if(check_FAT_dir_entry(&buffer[i*0x20],i)!=1)
		  {
		    log_error("cluster data is not a directory structure\n");
		    free(buffer);
		    return new_root_cluster;
		  }
		}
	      }
              free(buffer);
              return new_root_cluster;
            }
            else
            {
              if(verbose>1)
              {
                log_verbose("cluster %lu, etat=%d, found=%u, nb_subdir=%d, nb_subdir_ok=%d\n",
                    root_cluster, etat, found, nb_subdir, nb_subdir_ok);
              }
            }
            {
	      file_info_t dir_list;
	      TD_INIT_LIST_HEAD(&dir_list.list);
              dir_fat_aux(buffer, cluster_size, 0, &dir_list);
              if(is_root_cluster_candidat(&dir_list))
              {
                int test_date=1;
                if(verbose>0)
                {
                  log_verbose("Potential root_cluster %lu\n",root_cluster);
                  test_date=dir_aff_log(NULL, &dir_list);
                }
#ifdef HAVE_NCURSES
                if(interactive>0 && test_date>0)
                {
                  switch(ask_root_directory(disk_car, partition, &dir_list, root_cluster))
                  {
                    case c_YES:
                      delete_list_file(&dir_list);
                      free(buffer);
                      return root_cluster;
                    case 'A':
                      interactive=0;
                      break;
		    case 'Q':
                      delete_list_file(&dir_list);
                      free(buffer);
                      return 0;
                    default:
                      break;
                  }
                }
#endif
              }
              delete_list_file(&dir_list);
            }
          }
        }

      }
    }
    if(ind_stop!=0)
      log_info("Search root cluster stopped: %10lu (2..%lu)\n",root_cluster,no_of_cluster+1);
    else
      log_error("Search root cluster failed\n");
    root_cluster=0;
    if(td_list_empty(&rootdir_list.list))
    {
      log_warning("No first-level directory found.\n");
    }
    else
    {
      dir_aff_log(NULL, &rootdir_list);
#ifdef HAVE_NCURSES
      if(expert>0)
      {
        if(ask_confirmation("Create a new root cluster with %u first-level directories (Expert only) (Y/N)",dir_nbr)!=0 && ask_confirmation("Write root cluster, confirm ? (Y/N)")!=0)
        {
          root_cluster=first_free_cluster;
          fat32_create_rootdir(disk_car, partition, reserved, fat_length, root_cluster, sectors_per_cluster, verbose, &rootdir_list, fats);
        }
      }
#endif
      delete_list_file(&rootdir_list);
    }
    free(buffer);
  }
  return root_cluster;
}

#ifdef HAVE_NCURSES

static void fat_date_unix2dos(time_t unix_date,unsigned short *mstime, unsigned short *msdate)
{
  static const int day_n[] = { 0,31,59,90,120,151,181,212,243,273,304,334,0,0,0,0 };
                          /* JanFebMarApr May Jun Jul Aug Sep Oct Nov Dec */
  int day,year,nl_day,month;

/*  unix_date -= sys_tz.tz_minuteswest*60; */

  /* Jan 1 GMT 00:00:00 1980. But what about another time zone? */
  if (unix_date < 315532800)
    unix_date = 315532800;

  *mstime = le16((unix_date % 60)/2+(((unix_date/60) % 60) << 5)+
      (((unix_date/3600) % 24) << 11));
  day = unix_date/86400-3652;
  year = day/365;
  if ((year+3)/4+365*year > day)
    year--;
  day -= (year+3)/4+365*year;
  if (day == 59 && !(year & 3)) {
    nl_day = day;
    month = 2;
  }
  else {
    nl_day = (year & 3) || day <= 59 ? day : day-1;
    for (month = 1; month < 12; month++)
      if (day_n[month] > nl_day)
	break;
  }
  *msdate = le16(nl_day-day_n[month-1]+1+(month << 5)+(year << 9));
}

static int file2entry(struct msdos_dir_entry *de, const file_info_t *current_file)
{
  unsigned int i,j;
  /* Name */
  for(i=0;
      i<8 && current_file->name[i]!='.' && current_file->name[i]!='\0';
      i++)
  {
    de->name[i]=current_file->name[i];
  }
  for(j=i;j<8;j++)
  {
    de->name[j]=' ';
  }
  /* Extension */
  for(;
      current_file->name[i]!='.' && current_file->name[i]!='\0';
      i++);
  for(j=0;
      j<3 && current_file->name[i]!='\0';
      j++)
  {
    de->ext[j]=current_file->name[i];
  }
  for(;j<3;j++)
  {
    de->ext[j]=' ';
  }
  de->attr=(LINUX_S_ISDIR(current_file->st_mode)!=0?ATTR_DIR:ATTR_NONE);
  fat_date_unix2dos(current_file->td_mtime,&de->time,&de->date);
  de->start=le16(current_file->st_ino);
  de->starthi=le16(current_file->st_ino>>16);
  de->size=le32(current_file->st_size);
  return 0;
}

static int fat32_create_rootdir(disk_t *disk_car,const partition_t *partition, const unsigned int reserved, const unsigned int fat_length, const unsigned int root_cluster, const unsigned int sectors_per_cluster, const int verbose, file_info_t *rootdir_list, const unsigned int fats)
{
  const uint64_t start_data=reserved+fats*fat_length;
  const unsigned int cluster_size=disk_car->sector_size*sectors_per_cluster;
  unsigned int current_entry=0;
  unsigned int cluster;
  unsigned char *buffer;
  struct td_list_head *file_walker = NULL;
  if(verbose>0)
  {
    log_trace("fat32_create_rootdir(reserved=%u,fat_length=%u,root_cluster=%u,sectors_per_cluster=%u)\n",reserved,fat_length,root_cluster,sectors_per_cluster);
  }
  cluster=root_cluster;
  buffer=(unsigned char *)MALLOC(cluster_size);
  memset(buffer,0,cluster_size);
  td_list_for_each(file_walker, &rootdir_list->list)
  {
    const file_info_t *current_file=td_list_entry_const(file_walker, const file_info_t, list);
    file2entry((struct msdos_dir_entry*)buffer+current_entry,current_file);
    if(++current_entry==(cluster_size/sizeof(struct msdos_dir_entry)))
    {
      unsigned int next_cluster;
      if((unsigned)disk_car->pwrite(disk_car, buffer, cluster_size,
	    partition->part_offset + (start_data + (uint64_t)(cluster - 2) * sectors_per_cluster) * disk_car->sector_size) != cluster_size)
      {
	display_message("Write error: Can't create FAT32 root cluster.\n");
      }
      current_entry=0;
      memset(buffer,0,cluster_size);
      /* FIXME need to write fat32_get_next_free_cluster */
      next_cluster=cluster++;
      if(set_next_cluster(disk_car,partition,UP_FAT32,reserved,cluster,next_cluster))
      {
	display_message("Can't modify the FAT entries.\n");
      }
      if(set_next_cluster(disk_car,partition,UP_FAT32,reserved+fat_length,cluster,next_cluster))
      {
	display_message("Can't modify the FAT entries.\n");
      }
      cluster=next_cluster;
    }
  }
  if((unsigned)disk_car->pwrite(disk_car, buffer, cluster_size, partition->part_offset + (start_data + (uint64_t)(cluster - 2) * sectors_per_cluster) * disk_car->sector_size) != cluster_size)
  {
    display_message("Write error: Can't create FAT32 root cluster.\n");
  }
  if(set_next_cluster(disk_car,partition,UP_FAT32,reserved,cluster,FAT32_EOC))
  {
    display_message("Can't modify the FAT entries.\n");
  }
  if(set_next_cluster(disk_car,partition,UP_FAT32,reserved+fat_length,cluster,FAT32_EOC))
  {
    display_message("Can't modify the FAT entries.\n");
  }
#ifdef DEBUG
  {
    file_info_t dir_list;
    TD_INIT_LIST_HEAD(&dir_list.list);
    dir_fat_aux(buffer, cluster_size, 0, &dir_list);
    dir_aff_log(NULL, dir_list);
    delete_list_file(&dir_list);
  }
#endif
  free(buffer);
  return 0;
}
#endif

static int find_dir_entries(disk_t *disk_car,const partition_t *partition, const unsigned int offset,const int verbose)
{
  uint64_t hd_offset;
  unsigned int i;
  int dir_entry_found=0;
  unsigned char *buffer=(unsigned char *)MALLOC(disk_car->sector_size);
  for(i=0, hd_offset=partition->part_offset+(uint64_t)offset*disk_car->sector_size;
      i<200 && i<offset;
      i++, hd_offset-=disk_car->sector_size)
  {
    if((unsigned)disk_car->pread(disk_car, buffer, disk_car->sector_size, hd_offset) != disk_car->sector_size)
    {
      log_error("dir_entries: read error, dir_entries>=%u (%u sectors)\n",i*(disk_car->sector_size/32),i);
    }
    else
    {
      unsigned int j;
      /* A directory entry is 32 bytes long 	*
       * Entries has allocated by whole sector 	*/
      for(j=disk_car->sector_size/32-1;j>0;j--)
      {
        if(verbose>1)
        {
          log_verbose("find_dir_entries sector=%u entry=%u dir_entry_found=%d\n",
	      offset-i, j, dir_entry_found);
        }
        if(dir_entry_found==0)
        { /* Should be between the last directory entries and the first cluster */
          switch(check_FAT_dir_entry(&buffer[j*32],j))
          {
            case 0:	/* Empty entry */
              break;
            case 1:	/* Non empty entry */
              dir_entry_found=1;
              break;
            case 2:	/* Failed */
              free(buffer);
              return 0;
          }
        }
        else
        {
          if(check_FAT_dir_entry(&buffer[j*32],j)!=1)
          { /* Must be in the FAT table */
            free(buffer);
            return (i-1)*(disk_car->sector_size/32);
          }
        }
      }
    }
  }
  free(buffer);
  return 0;
}

static int analyse_dir_entries(disk_t *disk_car,const partition_t *partition, const unsigned int offset,const int verbose)
{
  unsigned int i,j;
  int etat=0;
  unsigned int sector_etat1=0;
  uint64_t hd_offset;
  unsigned char *buffer=(unsigned char *)MALLOC(disk_car->sector_size);
  hd_offset=partition->part_offset+(uint64_t)offset*disk_car->sector_size;
  for(i=0;i<200;i++)
  {
    if((unsigned)disk_car->pread(disk_car, buffer, disk_car->sector_size, hd_offset) != disk_car->sector_size)
    {
      log_error("dir_entries: read error, dir_entries>=%u (%u sectors)\n",i*(disk_car->sector_size/32),i);
    }
    else
    {
      for(j=0;j<(disk_car->sector_size/32);j++)
      {
        if(check_FAT_dir_entry(&buffer[j*0x20],j)==0)
        { /* Empty entry */
          if(etat==0)
          {
            if(i==0 && j==0)
            { /* The first entry must not be empty, otherwise there is no file */
              free(buffer);
              return 0;
            }
            etat=1;
            sector_etat1=i;
            if(verbose>0)
              log_verbose("dir_entries 0->1 %u\n", i*(disk_car->sector_size/32)+j);
          }
        }
        else
        { /* Not an entry or non empty entry */
          if(etat==1)
          {
            free(buffer);
            if(i==sector_etat1)
            { /* In the same sector, empty entry must not be followed by non-empty entry */
              return 0;
            }
            /* Data found */
            if(verbose>0)
              log_verbose("dir_entries 1->2 %u\n", i*(disk_car->sector_size/32)+j);
            return i*(disk_car->sector_size/32);
          }
        }
      }
    }
    hd_offset+=disk_car->sector_size;
  }
  free(buffer);
  return 0;
}

static int analyse_dir_entries2(disk_t *disk_car,const partition_t *partition, const unsigned int reserved, const unsigned int fat_length,const int verbose, unsigned int root_size_max,const upart_type_t upart_type, const unsigned int fats)
{
  unsigned char *buffer_dir;
  unsigned int root_dir_size;
  file_info_t dir_list;
  struct td_list_head *file_walker = NULL;
  TD_INIT_LIST_HEAD(&dir_list.list);
  if(root_size_max==0)
  {
    root_size_max=4096;
  }
  root_dir_size=(root_size_max*32+disk_car->sector_size-1)/disk_car->sector_size*disk_car->sector_size;
  buffer_dir=(unsigned char *)MALLOC(root_dir_size);
  if((unsigned)disk_car->pread(disk_car, buffer_dir, root_dir_size,
	partition->part_offset + (uint64_t)(reserved + fats * fat_length) * disk_car->sector_size) != root_dir_size)
  {
    log_error("FAT 1x can't read root directory\n");
    free(buffer_dir);
    return 0;
  }
  dir_fat_aux(buffer_dir, root_dir_size,
      (partition->upart_type==UP_FAT12?FLAG_LIST_MASK12:FLAG_LIST_MASK16), &dir_list);
  if(verbose>1)
  {
    dir_aff_log(NULL, &dir_list);
  }
  td_list_for_each(file_walker, &dir_list.list)
  {
    const file_info_t *current_file=td_list_entry_const(file_walker, const file_info_t, list);
    if(LINUX_S_ISDIR(current_file->st_mode) && (current_file->status&FILE_STATUS_DELETED)==0)
    {
      const unsigned long int new_inode=current_file->st_ino;
      unsigned int dir_entries;
      if(verbose>1)
      {
	log_verbose("Directory %s used inode=%lu\n",current_file->name,new_inode);
      }
      for(dir_entries=disk_car->sector_size/32;
	  dir_entries <= root_size_max;
	  dir_entries+=disk_car->sector_size/32)
      {
	const uint64_t start_data=reserved+fats*fat_length+(dir_entries+(disk_car->sector_size/32)-1)/(disk_car->sector_size/32);
	const unsigned int sectors_per_cluster=calcul_sectors_per_cluster(upart_type,partition->part_size/disk_car->sector_size-start_data,fat_length,disk_car->sector_size);
	if(verbose>1)
	{
	  log_verbose("dir_entries %u, sectors_per_cluster %u\n",dir_entries,sectors_per_cluster);
	}
	if((unsigned)disk_car->pread(disk_car, buffer_dir, disk_car->sector_size,
	      partition->part_offset + (start_data + (uint64_t)(new_inode - 2) * sectors_per_cluster) * disk_car->sector_size) == disk_car->sector_size)
	{
	  if(buffer_dir[0]=='.' && is_fat_directory(buffer_dir))
	  {
	    const unsigned long int cluster=fat_get_cluster_from_entry((const struct msdos_dir_entry *)&buffer_dir[0]);
	    const unsigned long int cluster_prev=fat_get_cluster_from_entry((const struct msdos_dir_entry *)&buffer_dir[0x20]);
	    if(verbose>1)
	    {
	      log_verbose("Cluster %lu, directory .. found link to %lu\n", cluster, cluster_prev);
	    }
	    if(cluster_prev==0 && cluster==new_inode)
	    {
	      free(buffer_dir);
	      delete_list_file(&dir_list);
	      return ((dir_entries+(disk_car->sector_size/32)-1)/(disk_car->sector_size/32))*(disk_car->sector_size/32);
	    }
	  }
	}
      }
    }
  }
  log_warning("No directory found\n");
  free(buffer_dir);
  delete_list_file(&dir_list);
  return root_size_max;
}

#ifdef HAVE_NCURSES
static void fat32_dump_ncurses(disk_t *disk_car, const partition_t *partition, const upart_type_t upart_type, const unsigned char *orgboot, const unsigned char *newboot)
{
  WINDOW *window=newwin(LINES, COLS, 0, 0);	/* full screen */
  keypad(window, TRUE); /* Need it to get arrow key */
  aff_copy(window);
  wmove(window,4,0);
  wprintw(window,"%s",disk_car->description(disk_car));
  wmove(window,5,0);
  aff_part(window,AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition);
  mvwaddstr(window,6,0, "     Rebuild Boot sector           Boot sector");
  dump2(window, newboot,orgboot, (unsigned int)(upart_type==UP_FAT32?3*disk_car->sector_size:DEFAULT_SECTOR_SIZE));
  delwin(window);
  (void) clearok(stdscr, TRUE);
#ifdef HAVE_TOUCHWIN
  touchwin(stdscr);
#endif
}
#endif

static void fat32_dump(disk_t *disk_car, const partition_t *partition, const upart_type_t upart_type, const unsigned char *orgboot, const unsigned char *newboot, char **current_cmd)
{
  log_info("     Rebuild Boot sector           Boot sector\n");
  dump2_log(newboot,orgboot, (unsigned int)(upart_type==UP_FAT32?3*disk_car->sector_size:DEFAULT_SECTOR_SIZE));
  if(*current_cmd==NULL)
  {
#ifdef HAVE_NCURSES
    fat32_dump_ncurses(disk_car, partition, upart_type, orgboot, newboot);
#endif
  }
}

static void menu_write_fat_boot_sector(disk_t *disk_car, partition_t *partition, const int verbose, const upart_type_t upart_type, const unsigned char *orgboot, const unsigned char*newboot, const int error, char **current_cmd)
{
  const struct fat_boot_sector *fat_header=(const struct fat_boot_sector *)newboot;
#ifdef HAVE_NCURSES
  const struct MenuItem menuSaveBoot[]=
  {
    { 'D', "Dump", "Dump sector" },
    { 'L', "List", "List directories and files" },
    { 'W', "Write","Write boot"},
    { 'Q',"Quit","Quit this section"},
    { 0, NULL, NULL }
  };
#endif
  const char *options="DLQ";
  int do_write=0;
  int do_exit=0;
  int no_confirm=0;
  do
  {
    int command;
    do_exit=0;
#ifdef HAVE_NCURSES
    aff_copy(stdscr);
    wmove(stdscr,4,0);
    wprintw(stdscr,"%s",disk_car->description(disk_car));
    mvwaddstr(stdscr,5,0,msg_PART_HEADER_LONG);
    wmove(stdscr,6,0);
    aff_part(stdscr,AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition);
    wmove(stdscr,8,0);
#endif
    if(memcmp(newboot,orgboot,DEFAULT_SECTOR_SIZE))	/* Only compare the first sector */
    {
#ifdef HAVE_NCURSES
      const struct fat_boot_sector *org_fat_header=(const struct fat_boot_sector *)orgboot;
      dump_2fat_info_ncurses(fat_header, org_fat_header, upart_type,disk_car->sector_size);
      wprintw(stdscr,"Extrapolated boot sector and current boot sector are different.\n");
      if(error)
	wprintw(stdscr,"Warning: Extrapolated boot sector have incorrect values.\n");
#endif
      if(error)
	log_error("Warning: Extrapolated boot sector have incorrect values.\n");
      options="DLWQ";
    }
    else
    {
#ifdef HAVE_NCURSES
      dump_fat_info_ncurses(fat_header, upart_type,disk_car->sector_size);
      wprintw(stdscr,"Extrapolated boot sector and current boot sector are identical.\n");
#endif
    }
    if(*current_cmd!=NULL)
    {
      command='Q';
      skip_comma_in_command(current_cmd);
      if(check_command(current_cmd,"list",4)==0)
      {
	command='L';
      }
      else if(check_command(current_cmd,"dump",4)==0)
      {
	command='D';
      }
      else if(check_command(current_cmd,"noconfirm",9)==0)
      {
	command=0;	/* do nothing */
	no_confirm=1;
      }
      else if(check_command(current_cmd,"write",5)==0)
      {
	command='W';
      }
    }
    else
    {
#ifdef HAVE_NCURSES
      command=wmenuSelect(stdscr, INTER_FATBS_Y+1, INTER_FATBS_Y, INTER_FATBS_X, menuSaveBoot,8,options,MENU_HORIZ|MENU_BUTTON, 1);
#else
      command=0;
#endif
    }
    switch(command)
    {
      case 'w':
      case 'W':
	if(strchr(options,'W')!=NULL)
	  do_write=1;
	break;
      case 'd':
      case 'D':
	if(strchr(options,'D')!=NULL)
	  fat32_dump(disk_car, partition, upart_type, orgboot, newboot, current_cmd);
	break;
      case 'l':
      case 'L':
	{
	  const upart_type_t old_upart_type=upart_type;
	  partition->upart_type=upart_type;
	  io_redir_add_redir(disk_car,partition->part_offset,3*disk_car->sector_size,0,newboot);
	  dir_partition(disk_car, partition, verbose, 0, current_cmd);
	  io_redir_del_redir(disk_car,partition->part_offset);
	  partition->upart_type=old_upart_type;
	}
	break;
      case 'q':
      case 'Q':
	do_exit=1;
	break;
    }
  } while(do_write==0 && do_exit==0);
  if(do_write!=0 && (no_confirm!=0
#ifdef HAVE_NCURSES
    || ask_confirmation("Write FAT boot sector, confirm ? (Y/N)")!=0
#endif
    ))
  {
    int err=0;
    log_info("Write new boot!\n");
    /* Reset information about backup boot sector */
    partition->sb_offset=0;
    /* Write boot sector and backup boot sector */
    if(upart_type==UP_FAT32)
    {
      if((unsigned)disk_car->pwrite(disk_car, newboot, 3 * disk_car->sector_size, partition->part_offset) !=
	  3 * disk_car->sector_size ||
	  (unsigned)disk_car->pwrite(disk_car, newboot, 3 * disk_car->sector_size, partition->part_offset + (uint64_t)le16(fat_header->backup_boot) * disk_car->sector_size) !=
	  3 * disk_car->sector_size)
	err=1;
    }
    else
    {
      if(disk_car->pwrite(disk_car, newboot, DEFAULT_SECTOR_SIZE, partition->part_offset) != DEFAULT_SECTOR_SIZE)
	err=1;
    }
    disk_car->sync(disk_car);
    if(err==1)
    {
      display_message("Write error: Can't write new FAT boot sector\n");
    }
    /* Note that TestDisk doesn't repair the filesystem itself, use another utility for that */
  }
  else
    log_info("Don't write new boot!\n");
}

static void create_fat_boot_sector(disk_t *disk_car, partition_t *partition, const unsigned int reserved, const int verbose, const unsigned int dir_entries, const unsigned long int root_cluster, const unsigned int sectors_per_cluster, const unsigned int fat_length, const upart_type_t upart_type, const unsigned int fats, char **current_cmd)
{
  unsigned char *orgboot;
  unsigned char *newboot;
  const struct fat_boot_sector *org_fat_header;
  struct fat_boot_sector *fat_header;
  int error=0;
  unsigned long int part_size=0;
  orgboot=(unsigned char *)MALLOC(3*disk_car->sector_size);
  newboot=(unsigned char *)MALLOC(3*disk_car->sector_size);
  org_fat_header=(const struct fat_boot_sector *)orgboot;
  fat_header=(struct fat_boot_sector *)newboot;
  if((unsigned)disk_car->pread(disk_car, orgboot, 3 * disk_car->sector_size, partition->part_offset) != 3 * disk_car->sector_size)
  {
    log_error("create_fat_boot_sector: Can't read old boot sector\n");
    memset(orgboot,0,3*disk_car->sector_size);
  }
  memcpy(newboot,orgboot,3*disk_car->sector_size);
  if(3*disk_car->sector_size >= DEFAULT_SECTOR_SIZE &&
      (le16(fat_header->marker)!=0xAA55 ||
       !((fat_header->ignored[0]==0xeb && fat_header->ignored[2]==0x90)||fat_header->ignored[0]==0xe9)))
  {
    write_FAT_boot_code_aux(newboot);
  }
  fat_header->sector_size[0]=disk_car->sector_size & 0xFF;
  fat_header->sector_size[1]=disk_car->sector_size >>8;
  fat_header->fats=fats;
  fat_header->secs_track=le16(disk_car->geom.sectors_per_head);
  fat_header->heads=le16(disk_car->geom.heads_per_cylinder);
  fat_header->marker=le16(0xAA55);
  if(!((fat_header->ignored[0]==0xeb&&fat_header->ignored[2]==0x90)||fat_header->ignored[0]==0xe9))
  {
    fat_header->ignored[0]=0xeb;
    fat_header->ignored[2]=0x90;
  }

  /* I have seen a FAT32 partition that Win98 2nd edition was unable to read
   * because this name was missing! */
  if(memcmp(fat_header->system_id,"MSDOS5.0",8) &&
      memcmp(fat_header->system_id,"MSWIN4.0",8) &&
      memcmp(fat_header->system_id,"MSWIN4.1",8))
    memcpy(fat_header->system_id,"MSWIN4.1",8);
  /* FIXME, need to know where the extended or logical partition start */
#if 0
  if(partition->status==STATUS_LOG)
    fat_header->hidden=le32(disk_car->geom.sectors_per_head);
  else
#endif
    fat_header->hidden=le32((partition->part_offset/disk_car->sector_size));
  fat_header->sectors_per_cluster=sectors_per_cluster;
  fat_header->reserved=le16(reserved);
  /* The filesystem size can be smaller than the partition size */
  switch(upart_type)
  {
    case UP_FAT12:
      part_size=le16(fat_header->reserved)+fats*fat_length+dir_entries*32/disk_car->sector_size+sectors_per_cluster*(fat_length*disk_car->sector_size*2/3-2);
      break;
    case UP_FAT16:
      part_size=le16(fat_header->reserved)+fats*fat_length+dir_entries*32/disk_car->sector_size+sectors_per_cluster*(fat_length*(disk_car->sector_size/2)-2);
      break;
    case UP_FAT32:
      part_size=le16(fat_header->reserved)+fats*fat_length+sectors_per_cluster*(fat_length*(disk_car->sector_size/4)-2);
      break;
    default:
      log_critical("create_fat_boot_sector: severe error\n");
      log_close();
      exit(1);
  }
  if(part_size>partition->part_size/disk_car->sector_size)
    part_size=partition->part_size/disk_car->sector_size;
  if(part_size>0xFFFF)
  {
    fat_header->sectors[0]=0;
    fat_header->sectors[1]=0;
    fat_header->total_sect=le32(part_size);
  }
  else
  {
    fat_header->sectors[1]=part_size>>8;
    fat_header->sectors[0]=part_size;
    fat_header->total_sect=le32(0);
  }
  switch(upart_type)
  {
    case UP_FAT12:
      fat_header->media=0xF0;				/* Floppy */
      if((fat_length==0) || (dir_entries==0))
	error=1;
      if((newboot[36]<0x80)||(newboot[36]>0x88))
	newboot[36]=0x80; /* BS_DrvNum=0x80 */
      newboot[37]=0;	/* BS_Reserved1=0 */
      newboot[38]=0x29; 	/* Boot sig=0x29 */
      if(memcmp(newboot+FAT_NAME2,"FAT32",5)==0)
	memcpy(newboot+FAT_NAME2, "        ",8);
      memcpy(newboot+FAT_NAME1,"FAT12   ",8);
      fat_header->fat_length=le16(fat_length);
      fat_header->dir_entries[1]=dir_entries>>8;
      fat_header->dir_entries[0]=dir_entries;
      if(check_VFAT_volume_name((const char*)&newboot[FAT1X_PART_NAME],11))
	newboot[FAT1X_PART_NAME]='\0';
      break;
    case UP_FAT16:
      fat_header->media=0xF8;				/* Hard Disk*/
      if((fat_length==0) || (dir_entries==0))
	error=1;
      if((newboot[36]<0x80)||(newboot[36]>0x88))
	newboot[36]=0x80; /* BS_DrvNum */
      newboot[37]=0;	/* BS_Reserved1=0 */
      newboot[38]=0x29; 	/* Boot sig=0x29 */
      if(memcmp(newboot+FAT_NAME2,"FAT32",5)==0)
	memcpy(newboot+FAT_NAME2, "        ",8);
      memcpy(newboot+FAT_NAME1,"FAT16   ",8);
      fat_header->fat_length=le16(fat_length);
      fat_header->dir_entries[1]=dir_entries>>8;
      fat_header->dir_entries[0]=dir_entries;
      if(check_VFAT_volume_name((const char*)&newboot[FAT1X_PART_NAME],11))
	newboot[FAT1X_PART_NAME]='\0';
      break;
    case UP_FAT32:
      fat_header->media=0xF8;				/* Hard Disk*/
      if((fat_length==0) || (root_cluster==0))
	error=1;
      fat_header->fat_length=le16(0);
      fat_header->dir_entries[0]=0;
      fat_header->dir_entries[1]=0;
      fat_header->fat32_length=le32(fat_length);
      /*
	 Bits 0-3 -- Zero-based number of active FAT. Only valid if mirroring
	 is disabled.
	 Bits 4-6 -- Reserved.
	 Bit    7 -- 0 means the FAT is mirrored at runtime into all FATs.
	 -- 1 means only one FAT is active; it is the one referenced
	 in bits 0-3.
	 Bits 8-15 -- Reserved.
       */
      fat_header->flags=le16(0);
      fat_header->version[0]=0;
      fat_header->version[1]=0;
      fat_header->root_cluster=le32(root_cluster);
      /* Sector number of FSINFO structure in the reserved area of the FAT32 volume. */
      fat_header->info_sector=le16(1);
      fat_header->backup_boot=le16(6);
      memset(&fat_header->BPB_Reserved,0,sizeof(fat_header->BPB_Reserved));
      if((fat_header->BS_DrvNum<0x80)||(fat_header->BS_DrvNum>0x87))
	fat_header->BS_DrvNum=0x80;
      fat_header->BS_Reserved1=0;
      fat_header->BS_BootSig=0x29;
      if((memcmp(newboot+FAT_NAME1,"FAT12",5)==0) ||(memcmp(newboot+FAT_NAME1,"FAT16",5)==0))
	memcpy(newboot+FAT_NAME1,"        ",8);
      memcpy(fat_header->BS_FilSysType,  "FAT32   ",8);
      newboot[0x1FC]=0x00;	/* part of the signature */
      newboot[0x1FD]=0x00;
      memset(&newboot[disk_car->sector_size],0,2*disk_car->sector_size);
      newboot[disk_car->sector_size]='R';		/* Signature RRaA */
      newboot[disk_car->sector_size+1]='R';
      newboot[disk_car->sector_size+2]='a';
      newboot[disk_car->sector_size+3]='A';
      newboot[disk_car->sector_size+0x1E4]='r';		/* Signature rrAa */
      newboot[disk_car->sector_size+0x1E5]='r';
      newboot[disk_car->sector_size+0x1E6]='A';
      newboot[disk_car->sector_size+0x1E7]='a';
      /* Don't set the number of free cluster or the next free cluster */
      newboot[disk_car->sector_size+0x1E8]=0xFF;	/* 488: Free clusters on disk */
      newboot[disk_car->sector_size+0x1E9]=0xFF;
      newboot[disk_car->sector_size+0x1EA]=0xFF;
      newboot[disk_car->sector_size+0x1EB]=0xFF;
      newboot[disk_car->sector_size+0x1EC]=0xFF;	/* 492: Next available clusters */
      newboot[disk_car->sector_size+0x1ED]=0xFF;
      newboot[disk_car->sector_size+0x1EE]=0xFF;
      newboot[disk_car->sector_size+0x1EF]=0xFF;
      newboot[disk_car->sector_size+0x1FC]=0x00;	/* End of Sector signature */
      newboot[disk_car->sector_size+0x1FD]=0x00;
      newboot[disk_car->sector_size+0x1FE]=0x55;
      newboot[disk_car->sector_size+0x1FF]=0xAA;
      newboot[2*disk_car->sector_size+0x1FC]=0x00;	/* End of Sector signature */
      newboot[2*disk_car->sector_size+0x1FD]=0x00;
      newboot[2*disk_car->sector_size+0x1FE]=0x55;
      newboot[2*disk_car->sector_size+0x1FF]=0xAA;
      if(check_VFAT_volume_name((const char*)&newboot[FAT32_PART_NAME],11))
	newboot[FAT32_PART_NAME]='\0';
      break;
    default:
      log_critical("create_fat_boot_sector: severe error\n");
      log_close();
      exit(1);
  }
  if(memcmp(newboot,orgboot,1*DEFAULT_SECTOR_SIZE))	/* Only compare the first sector */
  {
    log_warning("             New / Current boot sector");
    log_fat2_info(fat_header,org_fat_header,upart_type,disk_car->sector_size);
    log_warning("Extrapolated boot sector and current boot sector are different.\n");
  }
  else
  {
    log_info("Extrapolated boot sector and current boot sector are identical.\n");
  }
  menu_write_fat_boot_sector(disk_car, partition, verbose, upart_type, orgboot, newboot, error, current_cmd);
  free(orgboot);
  free(newboot);
}

/*@
  @ decreases number;
  @ assigns \nothing;
  @*/
static unsigned int up2power_aux(const unsigned int number)
{
  if(number==0)
	return 0;
  else
	return(1+up2power_aux(number/2));
}

/*@
  @ assigns \nothing;
  @*/
static unsigned int up2power(const unsigned int number)
{
  if(number==0)
    return 1;
  return (1<<up2power_aux(number-1));
}


static int calcul_sectors_per_cluster(const upart_type_t upart_type, const unsigned long int data_size, const unsigned int fat_length, const unsigned int sector_size)
{
  /* log_info("calcul_sectors_per_cluster data_size=%lu, fat_length=%u, sector_size=%u\n",data_size,fat_length,sector_size); */
  if(fat_length==0)
    return 0;
  switch(upart_type)
  {
    case UP_FAT12:
      return up2power(data_size/(fat_length*sector_size*2/3-1));
    case UP_FAT16:
      return up2power(data_size/(fat_length*sector_size/2-1));
    case UP_FAT32:
      return up2power(data_size/(fat_length*sector_size/4-1));
    default:
      log_critical("calcul_sectors_per_cluster: severe error\n");
      return 0;
  }
}

static unsigned int fat_find_fat_start(const unsigned char *buffer,const int p_fat12, const int p_fat16, const int p_fat32,unsigned long int*fat_offset, const unsigned int sector_size)
{
  /* TODO: handle limited size of info_offset */
  info_offset_t *info_offset;
  unsigned int nbr_offset=0;
  int have_fat_signature=0;
  info_offset=(info_offset_t *)MALLOC(sector_size*sizeof(info_offset_t));
  if(p_fat12!=0)
  {
    unsigned int i;
    unsigned int low;
    unsigned int high;
    i=0;
    high=0;
    low=0;
    while(high<(sector_size-1))
    {
      unsigned long int cluster=0;
      if(low==0)
	cluster=((buffer[high+1] & 0x0F) <<8) | buffer[high];
      else
	cluster=(buffer[high+1] <<4) | ((buffer[high]&0xF0)>>4);
      if((cluster!=0) && ((cluster&0x0ff8)!=(unsigned)0x0ff8) && (((cluster-i-1)*3)%(2*sector_size)==0))
      {
	unsigned int j;
	for(j=0;(j<nbr_offset) &&
	    (info_offset[j].offset!=(cluster-i-1)*3/(2*sector_size) || info_offset[j].fat_type!=12);j++);
	if(j<nbr_offset)
	  info_offset[j].nbr++;
	else
	{
	  info_offset[nbr_offset].offset=(cluster-i-1)*3/(2*sector_size);
	  info_offset[nbr_offset].nbr=1;
	  info_offset[nbr_offset].fat_type=12;
	  nbr_offset++;
	}
      }
      if(low==0)
	low=1;
      else
      {
	high++;
	low=0;
      }
      high++;
      i++;
    }
    i=1;
    high=1;
    low=0;
    while(high<(sector_size-1))
    {
      unsigned long int cluster=0;
      if(low==0)
	cluster=((buffer[high+1] & 0x0F) <<8) | buffer[high];
      else
	cluster=(buffer[high+1] <<4) | ((buffer[high]&0xF0)>>4);
      if((cluster!=0) && ((cluster&0x0ff8)!=(unsigned)0x0ff8) && (((cluster-i-1)*3+1)%(2*sector_size)==0))
      {
	unsigned int j;
	for(j=0;(j<nbr_offset) &&
	  (info_offset[j].offset!=((cluster-i-1)*3+1)/(2*sector_size) || info_offset[j].fat_type!=12);j++);
	if(j<nbr_offset)
	  info_offset[j].nbr++;
	else
	{
	  info_offset[nbr_offset].offset=((cluster-i-1)*3+1)/(2*sector_size);
	  info_offset[nbr_offset].nbr=1;
	  info_offset[nbr_offset].fat_type=12;
	  nbr_offset++;
	}
      }
      if(low==0)
	low=1;
      else
      {
	high++;
	low=0;
      }
      high++;
      i++;
    }
    i=1;
    high=0;
    low=1;
    while(high<(sector_size-1))
    {
      unsigned long int cluster=0;
      if(low==0)
	cluster=((buffer[high+1] & 0x0F) <<8) | buffer[high];
      else
	cluster=(buffer[high+1] <<4) | ((buffer[high]&0xF0)>>4);
      if((cluster!=0) && ((cluster&0x0ff8)!=(unsigned)0x0ff8) && (((cluster-i-1)*3+2)%(2*sector_size)==0))
      {
	unsigned int j;
	for(j=0;(j<nbr_offset) &&
	    (info_offset[j].offset!=((cluster-i-1)*3+2)/(2*sector_size) || info_offset[j].fat_type!=12);j++);
	if(j<nbr_offset)
	  info_offset[j].nbr++;
	else
	{
	  info_offset[nbr_offset].offset=((cluster-i-1)*3+2)/(2*sector_size);
	  info_offset[nbr_offset].nbr=1;
	  info_offset[nbr_offset].fat_type=12;
	  nbr_offset++;
	}
      }
      if(low==0)
	low=1;
      else
      {
	high++;
	low=0;
      }
      high++;
      i++;
    }
    if((buffer[0]==0xF0 || buffer[0]>=0xF8) && buffer[1]==0xFF)
    {
      unsigned int j;
      for(j=0;(j<nbr_offset) &&
	  (info_offset[j].offset!=0 || info_offset[j].fat_type!=12);j++);
      if(j<nbr_offset)
	info_offset[j].nbr++;
      else
      {
	info_offset[nbr_offset].offset=0;
	info_offset[nbr_offset].nbr=1;
	info_offset[nbr_offset].fat_type=12;
	nbr_offset++;
      }
      have_fat_signature=1;
    }
  }
  if(p_fat16!=0)
  {
    unsigned int i,j;
    const uint16_t *p16=(const uint16_t*)buffer;
    unsigned int err=0;
    for(i=0; (i<sector_size/2)&&(err==0); i++)
    {
      unsigned long int cluster=le16(p16[i]);
      if(cluster==1)
      {
	err=1;
      }
      if((cluster!=0) && ((cluster&0x0fff8)!=(unsigned)0x0fff8))
      {
	for(j=i+1; (j<sector_size/2)&&(err==0); j++)
	{
	  if(cluster==le16(p16[j]))
	  {
	    err=1;
	  }
	}
      }
    }
    if(err==0)
    {
      for(i=0; i<sector_size/2; i++)
      {
	unsigned long int cluster=le16(p16[i]);
	if((cluster!=0) && ((cluster&0x0fff8)!=(unsigned)0x0fff8)&&((cluster-i-1)%(sector_size/2)==0))
	{
	  for(j=0;(j<nbr_offset) &&
	    (info_offset[j].offset!=(cluster-i-1)/(sector_size/2) || info_offset[j].fat_type!=16);j++);
	  if(j<nbr_offset)
	    info_offset[j].nbr++;
	  else
	  {
	    info_offset[nbr_offset].offset=(cluster-i-1)/(sector_size/2);
	    info_offset[nbr_offset].nbr=1;
	    info_offset[nbr_offset].fat_type=16;
	    nbr_offset++;
	  }
	}
      }
    }
    if((buffer[0]==0xF0 || buffer[0]>=0xF8) && buffer[1]==0xFF
	&& buffer[2]==0xFF && ((buffer[3] & 0xF7)==0xF7))
    {
      for(j=0;(j<nbr_offset)&& (info_offset[j].offset!=0 || info_offset[j].fat_type!=16);j++);
      if(j<nbr_offset)
	info_offset[j].nbr++;
      else
      {
	info_offset[nbr_offset].offset=0;
	info_offset[nbr_offset].nbr=1;
	info_offset[nbr_offset].fat_type=16;
	nbr_offset++;
      }
      have_fat_signature=1;
    }
  }
  if(p_fat32!=0)
  {
    unsigned int i,j;
    const uint32_t *p32=(const uint32_t*)buffer;
    unsigned int err=0;
    for(i=0; (i<sector_size/4)&&(err==0); i++)
    {
      unsigned long int cluster=le32(p32[i])&0x0FFFFFFF;
      if(cluster==1)
      {
	err=1;
      }
      if((cluster!=0) && ((cluster&0x0ffffff8)!=(unsigned)0x0ffffff8))
      {
	for(j=i+1; (j<sector_size/4)&&(err==0); j++)
	{
	  if(cluster==(le32(p32[j])&0x0FFFFFFF))
	  {
	    err=1;
	  }
	}
      }
    }
    if(err==0)
    {
      for(i=0; i<sector_size/4; i++)
      {
	unsigned long int cluster=le32(p32[i])&0x0FFFFFFF;
	if((cluster!=0) && ((cluster&0x0ffffff8)!=(unsigned)0x0ffffff8)&&((cluster-i-1)%(sector_size/4)==0))
	{
	  for(j=0;(j<nbr_offset) &&
	      ((info_offset[j].offset!=(cluster-i-1)/(sector_size/4)) || (info_offset[j].fat_type!=32));j++);
	  if(j<nbr_offset)
	    info_offset[j].nbr++;
	  else
	  {
	    info_offset[nbr_offset].offset=(cluster-i-1)/(sector_size/4);
	    info_offset[nbr_offset].nbr=1;
	    info_offset[nbr_offset].fat_type=32;
	    nbr_offset++;
	  }
	}
      }
    }
    if((buffer[0]==0xF0 || buffer[0]>=0xF8) && buffer[1]==0xFF &&
	buffer[2]==0xFF && ((buffer[3]==0x0F) ||(buffer[3]==0xFF)) &&
	buffer[4]==0xFF && buffer[5]==0xFF && buffer[6]==0xFF)
    {
      for(j=0;(j<nbr_offset)&&(info_offset[j].offset!=0 || info_offset[j].fat_type!=32);j++);
      if(j<nbr_offset)
	info_offset[j].nbr++;
      else
      {
	info_offset[nbr_offset].offset=0;
	info_offset[nbr_offset].nbr=1;
	info_offset[nbr_offset].fat_type=32;
	nbr_offset++;
      }
      have_fat_signature=1;
    }
  }
  if(nbr_offset>0)
  {
    unsigned int j;
    unsigned int best_j=0;
    for(j=0;j<nbr_offset;j++)
    {
      if(info_offset[j].nbr>info_offset[best_j].nbr)
	best_j=j;
    }
    if(info_offset[best_j].nbr>10 || have_fat_signature>0)
    {
      unsigned int res;
      *fat_offset=info_offset[best_j].offset;
      res=info_offset[best_j].fat_type;
      free(info_offset);
      return res;
    }
  }
  free(info_offset);
  return 0;
}

static int fat_find_type(disk_t *disk_car, const partition_t *partition, const uint64_t max_offset, const int p_fat12, const int p_fat16, const int p_fat32, const int verbose, const int dump_ind, unsigned int *nbr_offset, info_offset_t *info_offset, const unsigned int max_nbr_offset)
{
  uint64_t offset;
#ifdef HAVE_NCURSES
  unsigned long int old_percent=0;
#endif
  int ind_stop=0;
  unsigned char *buffer=(unsigned char *)MALLOC(disk_car->sector_size);
  if(verbose>0)
  {
    log_trace("fat_find_type(max_offset=%lu, p_fat12=%d, p_fat16=%d, p_fat32=%d, debug=%d, dump_ind=%d)\n",
        (long unsigned)(max_offset/disk_car->sector_size), p_fat12, p_fat16, p_fat32, verbose, dump_ind);
  }
#ifdef HAVE_NCURSES
  wmove(stdscr,8,0);
  wprintw(stdscr,"FAT : %s%s%s?\n",p_fat12?"12 ":"", p_fat16?"16 ":"", p_fat32?"32 ":"");
  wmove(stdscr,22,0);
  wattrset(stdscr, A_REVERSE);
  waddstr(stdscr,"  Stop  ");
  wattroff(stdscr, A_REVERSE);
#endif
  for(offset=disk_car->sector_size;
      offset<max_offset && !ind_stop;
      offset+=disk_car->sector_size)
  {
#ifdef HAVE_NCURSES
    const unsigned long int percent=offset*100/max_offset;
    if(percent!=old_percent)
    {
      wmove(stdscr,8,30);
      wclrtoeol(stdscr);	/* before addstr for BSD compatibility */
      wprintw(stdscr,"Searching for FAT table %lu%%",percent);
      old_percent=percent;
      wrefresh(stdscr);
      ind_stop|=check_enter_key_or_s(stdscr);
    }
#endif
    if((unsigned)disk_car->pread(disk_car, buffer, disk_car->sector_size, partition->part_offset + offset) == disk_car->sector_size)
    {
      unsigned long int fat_offset=0;
      const unsigned int fat_type=fat_find_fat_start(buffer,p_fat12,p_fat16,p_fat32,&fat_offset,disk_car->sector_size);
      if(fat_type!=0 && fat_offset<=(offset/disk_car->sector_size))
      {
	unsigned int j;
	if(verbose>1)
	{
	  log_info("fat_find_fat_start FAT%u at %lu:%lu\n", fat_type,
	      (long unsigned)(offset/disk_car->sector_size-fat_offset),
	      (long unsigned)(offset/disk_car->sector_size));
	}
	for(j=0; j<*nbr_offset && !(info_offset[j].offset==offset/disk_car->sector_size-fat_offset &&
	      info_offset[j].fat_type==fat_type); j++);
	if(j<*nbr_offset)
	  info_offset[j].nbr++;
	else
	{
	  unsigned int new_info=0;
	  if(*nbr_offset<max_nbr_offset)
	  {
	    new_info=*nbr_offset;
	    (*nbr_offset)++;
	  }
	  else
	  { /* Overwrite the last information field with the lower nbr */
	    for(j=0;j<max_nbr_offset;j++)
	    {
	      if(info_offset[j].nbr <= info_offset[new_info].nbr)
		new_info=j;
	    }
	  }
	  info_offset[new_info].offset=offset/disk_car->sector_size-fat_offset;
	  info_offset[new_info].nbr=1;
	  info_offset[new_info].fat_type=fat_type;
	}
      }
    }
  }
#ifdef HAVE_NCURSES
  wmove(stdscr,22,0);
  wclrtoeol(stdscr);
  wrefresh(stdscr);
#endif
  free(buffer);
  return 0;
}

static upart_type_t fat_find_info(disk_t *disk_car,unsigned int*reserved, unsigned int*fat_length, const partition_t *partition, const uint64_t max_offset, const int p_fat12, const int p_fat16, const int p_fat32, const int verbose, const int dump_ind, const unsigned int expert, unsigned int *fats)
{
  unsigned int nbr_offset=0;
  unsigned int i;
  info_offset_t info_offset[0x400];
  upart_type_t upart_type=UP_UNK;
  fat_find_type(disk_car, partition, max_offset, p_fat12, p_fat16, p_fat32, verbose, dump_ind, &nbr_offset, &info_offset[0], 0x400);
  for(i=0;i<nbr_offset;i++)
  {
    const uint64_t end=partition->part_offset+(uint64_t)info_offset[i].offset*disk_car->sector_size;
    log_info("FAT%u at %lu(%u/%u/%u), nbr=%u\n",info_offset[i].fat_type,info_offset[i].offset,
	offset2cylinder(disk_car, end),
	offset2head(disk_car,end),
	offset2sector(disk_car,end),
	info_offset[i].nbr);
#ifdef HAVE_NCURSES
    if(dump_ind>0)
    {
      unsigned char *buffer=(unsigned char *)MALLOC(disk_car->sector_size);
      if((unsigned)disk_car->pread(disk_car, &buffer, disk_car->sector_size, end) == disk_car->sector_size)
      {
	dump_ncurses(buffer,disk_car->sector_size);
      }
      free(buffer);
    }
#endif
  }
  if(nbr_offset==0)
  {
    *fat_length=0;
  }
  else
  {
    unsigned int offset_for_max_nbr=0;
    unsigned int fat_found=0;
    unsigned int first_fat=0;
    unsigned int second_fat=0;
    for(i=0; i<nbr_offset; i++)
    {
      /* select the good type in the 3 first possibilities */
      if(i<3 || info_offset[i].offset<=33)
      {
	if(info_offset[i].nbr>info_offset[offset_for_max_nbr].nbr)
	  offset_for_max_nbr=i;
      }
    }
    switch(info_offset[offset_for_max_nbr].fat_type)
    {
      case 12:
	upart_type=UP_FAT12;
	break;
      case 16:
	upart_type=UP_FAT16;
	break;
      case 32:
	upart_type=UP_FAT32;
	break;
    }
    for(i=0; i<nbr_offset; i++)
    {
      if(info_offset[i].fat_type==info_offset[offset_for_max_nbr].fat_type)
      {
	if(fat_found==0 && info_offset[i].nbr>=(info_offset[offset_for_max_nbr].nbr+2-1)/2)
	{
	  first_fat=i;
	  fat_found++;
	}
	else if(fat_found==1 && info_offset[i].nbr>=(info_offset[first_fat].nbr+2-1)/2)
	{
	  second_fat=i;
	  fat_found++;
	}
      }
    }
    if(fat_found==1)
    {
      for(i=first_fat+1;i<nbr_offset;i++)
      {
	if(info_offset[i].fat_type==info_offset[offset_for_max_nbr].fat_type)
	{
	  if(fat_found==1)
	  {
	    second_fat=i;
	    fat_found++;
	  }
	}
      }
    }
    if(fat_found==1)
    {
      switch(upart_type)
      {
	case UP_FAT12:
	case UP_FAT16:
	  *reserved=1;
	  if(info_offset[first_fat].offset>*reserved)
	    *fat_length=info_offset[first_fat].offset-*reserved;
	  else
	    *fat_length=0;
	  break;
	case UP_FAT32:
	  if(info_offset[first_fat].offset==32 || info_offset[first_fat].offset==33)
	    *reserved=info_offset[first_fat].offset;
	  *fat_length=0;
	  break;
	default:
	  log_critical("fat_find_info: severe error\n");
	  return UP_UNK;
      }
    }
    else
    {
      switch(upart_type)
      {
	case UP_FAT12:
	case UP_FAT16:
	  *reserved=info_offset[first_fat].offset;	/* Should be 1 */
	  *fat_length=info_offset[second_fat].offset-*reserved;
	  break;
	case UP_FAT32:
	  *reserved=info_offset[first_fat].offset;
	  *fat_length=info_offset[second_fat].offset-*reserved;
	  if(*reserved==32 || *reserved==33 || comp_FAT(disk_car,partition,*fat_length,*reserved)==0)
	  {
	  } else {
	    *reserved=0;
	    *fat_length=0;
	  }
	  break;
	default:
	  log_critical("fat_find_info: severe error\n");
	  return UP_UNK;
      }
    }
    if(verbose>0)
    {
      log_info("first_fat %lu, second_fat %lu\n",info_offset[first_fat].offset, info_offset[second_fat].offset);
    }
  }
  if(expert>0)
  {
#ifdef HAVE_NCURSES
    return select_fat_info(info_offset,nbr_offset,reserved,fat_length,max_offset/disk_car->sector_size,fats);
#endif
  }
  return upart_type;
}

#ifdef HAVE_NCURSES
static upart_type_t select_fat_info(const info_offset_t *info_offset, const unsigned int nbr_offset,unsigned int*reserved, unsigned int*fat_length, const unsigned long int max_sector_offset, unsigned int *fats)
{
  unsigned int i;
  unsigned long int fat2_location=*reserved+*fat_length;
  const struct MenuItem menuSelectFAT[]=
  {
    { 'P', "Previous",""},
    { 'N', "Next","" },
    { 'Q', "Proceed","Set FAT table location"},
    { 0, NULL, NULL }
  };
  screen_buffer_reset();
  screen_buffer_add("Potential FAT location\n");
  screen_buffer_add("FAT - sector - score\n");
  for(i=0;i<nbr_offset;i++)
  {
    if(nbr_offset<30 || info_offset[i].nbr>1)
      screen_buffer_add(" %02u %8lu   %u\n", info_offset[i].fat_type, info_offset[i].offset, info_offset[i].nbr);
  }
  aff_copy(stdscr);
  wmove(stdscr,4,0);
  screen_buffer_to_log();
  log_flush();
  screen_buffer_display(stdscr,"",menuSelectFAT);
  wmove(stdscr,INTER_FAT_ASK_Y, INTER_FAT_ASK_X);
  *reserved=ask_number(*reserved,0,max_sector_offset,"FAT1 location (Number of reserved sector) ");
  if(*reserved>0)
  {
    wmove(stdscr,INTER_FAT_ASK_Y, INTER_FAT_ASK_X);
    fat2_location=ask_number(fat2_location,0,max_sector_offset,"FAT2 location ");
    if(fat2_location == *reserved)
    {
      *fats=1;
      *fat_length=0;
    }
    else if(fat2_location > *reserved)
    {
      *fat_length=fat2_location-*reserved;
      wmove(stdscr,INTER_FAT_ASK_Y, INTER_FAT_ASK_X);
      *fats=ask_number(*fats,1,2,"Number of FATS (Usually 2) ");
    }
    else
    {
      *fat_length=0;
    }
  }
  else
  {
    *fat_length=0;
  }
  for(i=0;i<nbr_offset;i++)
  {
    if(info_offset[i].offset==fat2_location)
    {
      switch(info_offset[i].fat_type)
      {
	case 12: return UP_FAT12;
	case 16: return UP_FAT16;
	case 32: return UP_FAT32;
      }
    }
  }
  for(i=0;i<nbr_offset;i++)
  {
    if(info_offset[i].offset==*reserved)
    {
      switch(info_offset[i].fat_type)
      {
	case 12: return UP_FAT12;
	case 16: return UP_FAT16;
	case 32: return UP_FAT32;
      }
    }
  }
  *reserved=0;
  *fat_length=0;
  return UP_UNK;
}
#endif

int rebuild_FAT_BS(disk_t *disk_car, partition_t *partition, const int verbose, const int dump_ind, const unsigned int expert, char**current_cmd)
{
  unsigned long int max_offset;
  unsigned int fat_length=0;
  unsigned int sectors_per_cluster=0;
  unsigned int reserved=0;
  unsigned int dir_entries=0;
  unsigned int fats=2;
  int p_fat12,p_fat16,p_fat32;
  upart_type_t upart_type;
  /*
   * Using partition size, check if partition can be FAT12, FAT16 or FAT32
   * */
  if(partition->part_size>(uint64_t)(2*1024+1)*1024*1024)
  {
    p_fat32=1;
    p_fat16=0;
    p_fat12=0;
  }
  else
    /* 1<<12 clusters * 8 secteurs/clusters= 32768 secteurs 
       fat_length=((1<<12+1)*1.5/DEFAULT_SECTOR_SIZE)+1=13; */
    if(partition->part_size>=(uint64_t)(1+2*13+32768+63)*512)
    {
      p_fat32=1;
      p_fat16=1;
      p_fat12=0;
    }
    else
    {
      p_fat32=0;
      p_fat16=1;
      p_fat12=1;
    }
#ifdef TESTING
  p_fat32=1; p_fat16=1; p_fat12=1;
#endif
  if(verbose)
  {
    log_info("\n");
    log_partition(disk_car,partition);
    log_info("rebuild_FAT_BS p_fat12 %d, p_fat16 %d, p_fat32 %d\n", p_fat12,p_fat16,p_fat32);
  }
  {
    /* Set fat_length_max */
    unsigned long int fat_length_max;
    unsigned int sectors_per_cluster_min=disk_car->sector_size;
    if(p_fat32)
    {	/* Cluster 512 bytes */
      fat_length_max=partition->part_size/sectors_per_cluster_min*4;
    }
    else if(p_fat16)
    {
      while(partition->part_size/sectors_per_cluster_min > (1<<16))
	sectors_per_cluster_min*=2;
      fat_length_max=partition->part_size/sectors_per_cluster_min*2;
    }
    else
    {
      /* dead code */
      while(partition->part_size/sectors_per_cluster_min > (1<<12))
	sectors_per_cluster_min*=2;
      fat_length_max=partition->part_size/sectors_per_cluster_min*3/2;
    }
    fat_length_max=fat_length_max/disk_car->sector_size*disk_car->sector_size;
    if(verbose>1)
    {
      log_verbose("sectors_per_cluster_min %u sectors\n", sectors_per_cluster_min/disk_car->sector_size);
      log_verbose("fat_length_max %lu sectors\n", fat_length_max/disk_car->sector_size);
    }
    max_offset=fat_length_max+64*disk_car->sector_size;
  }
  /*
     if(verbose>1)
       log_debug("search_fat16(partition,max_offset=%d,p_fat12=%d,p_fat16=%d,p_fat32=%d,debug=%d,dump_ind=%d)\n",max_offset,p_fat12,p_fat16,p_fat32,verbose,dump_ind);
   */
#ifdef HAVE_NCURSES
  aff_copy(stdscr);
  wmove(stdscr,4,0);
  wprintw(stdscr,"%s",disk_car->description(disk_car));
  mvwaddstr(stdscr,5,0,msg_PART_HEADER_LONG);
  wmove(stdscr,6,0);
  aff_part(stdscr,AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition);
  wrefresh(stdscr);
#endif
  upart_type=fat_find_info(disk_car, &reserved, &fat_length, partition, max_offset, p_fat12, p_fat16, p_fat32, verbose, dump_ind, expert, &fats);
#ifdef HAVE_NCURSES
  aff_copy(stdscr);
  wmove(stdscr,4,0);
  wprintw(stdscr,"%s",disk_car->description(disk_car));
  mvwaddstr(stdscr,5,0,msg_PART_HEADER_LONG);
  wmove(stdscr,6,0);
  aff_part(stdscr,AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition);
  wmove(stdscr,8,0);
  wclrtoeol(stdscr);
  switch(upart_type)
  {
    case UP_FAT12:
      waddstr(stdscr,"FAT : 12");
      break;
    case UP_FAT16:
      waddstr(stdscr,"FAT : 16");
      break;
    case UP_FAT32:
      waddstr(stdscr,"FAT : 32");
      break;
    default:
      waddstr(stdscr,"No FAT found");
      break;
  }
#endif
  if(verbose>0)
  {
    switch(upart_type)
    {
      case UP_FAT12:
	log_info("FAT : 12");
	break;
      case UP_FAT16:
	log_info("FAT : 16");
	break;
      case UP_FAT32:
	log_info("FAT : 32");
	break;
      default:
	log_info("No FAT found");
	break;
    }
    log_info(", reserved=%u, fat_length=%u\n",reserved,fat_length);
  }
  if((upart_type!=UP_FAT12 && upart_type!=UP_FAT16 && upart_type!=UP_FAT32)||
      (fat_length==0)||(reserved==0))
  {
    uint64_t start_data=0;
    if(find_sectors_per_cluster(disk_car, partition, verbose, dump_ind, &sectors_per_cluster, &start_data, upart_type)==0)
    {
      display_message("Can't find cluster size\n");
      return 0;
    }
    if((sectors_per_cluster<=0) || (partition->part_size/disk_car->sector_size<=start_data))
    {
      display_message("Can't find cluster size\n");
      return 0;
    }
    upart_type=no_of_cluster2part_type((partition->part_size/disk_car->sector_size-start_data)/sectors_per_cluster);
    switch(upart_type)
    {
      case UP_FAT12:
	log_info("FAT : 12\n");
	break;
      case UP_FAT16:
	log_info("FAT : 16\n");
	break;
      case UP_FAT32:
	log_info("FAT : 32\n");
	break;
      default:	/* No compiler warning */
	break;
    }
    switch(upart_type)
    {
      case UP_FAT12:
      case UP_FAT16:
	reserved=1;		/* must be 1 */
	dir_entries=find_dir_entries(disk_car,partition,start_data-1,verbose);
	switch(dir_entries)
	{
	  case 0:
	    log_warning("dir_entries not found, should be 512\n");
	    dir_entries=512;
	    break;
	  case 512:
	    if(verbose)
	      log_info("dir_entries: %u\n", dir_entries);
	    break;
	  default:
	    log_warning("dir_entries: %u (unusual value)\n", dir_entries);
	    break;
	}
	fat_length=(start_data-reserved-((dir_entries-1)/16+1))/fats;
	break;
      case UP_FAT32:
	if(reserved==0)
	{
	  reserved=32;
	  if((start_data&1)!=0)
	    reserved+=1;
	}
	fat_length=(start_data-reserved)/fats;
	break;
      default:	/* No compiler warning */
	break;
    }
    if(verbose>0)
      log_info("fat_length %u\n",fat_length);
  }
#ifdef HAVE_NCURSES
  if(fat_length==0)
    waddstr(stdscr," Can't find FAT length\n");
  wrefresh(stdscr);
#endif
  if(upart_type && (fat_length>1))
  {
    unsigned long int data_size;
    /* Initialized by fat32_free_info */
    unsigned int free_cluster_count=0;
    unsigned int first_free_cluster=0;
    /* Initialized by fat32_find_root_cluster */
    unsigned long int root_cluster=0;
    uint64_t start_data=reserved+fats*fat_length;
    /* FAT1x: Find size of root directory */
    if((upart_type==UP_FAT12) || (upart_type==UP_FAT16))
    {
      int old_dir_entries=dir_entries;
      dir_entries=analyse_dir_entries(disk_car,partition,start_data,verbose);
      log_info("dir_entries %u\n",dir_entries);
      dir_entries=analyse_dir_entries2(disk_car,partition,reserved,fat_length,verbose,dir_entries,upart_type,fats);
      log_info("dir_entries %u\n",dir_entries);
      if(dir_entries==0)
      {
        if(old_dir_entries>0)
          fat_length=0;
        /*
           else
           {
           dir_entries=512;
           log_debug("analyse_dir_entries: use default dir_entries %u\n",dir_entries);
           }
         */
      }
      start_data+=(dir_entries+(disk_car->sector_size/32)-1)/(disk_car->sector_size/32);
    }
    if(partition->part_size/disk_car->sector_size<=start_data)
    {
      log_error("Error part_size=%lu <= start_data=%lu\n",
          (unsigned long)(partition->part_size/disk_car->sector_size), (unsigned long)start_data);
      return 0;
    }
    data_size=partition->part_size/disk_car->sector_size-start_data;
    /* Get Cluster Size */
    {
      int old_sectors_per_cluster=sectors_per_cluster;
      sectors_per_cluster=calcul_sectors_per_cluster(upart_type,data_size,fat_length,disk_car->sector_size);
      if(verbose>0)
	log_info("sectors_per_cluster %u\n",sectors_per_cluster);
      if((sectors_per_cluster<=0)||(sectors_per_cluster>128))
      {
	if(old_sectors_per_cluster>0)
	{
	  sectors_per_cluster=old_sectors_per_cluster;
	  log_info("Assumes previous cluster size was good\n");
	}
	else
	{
	  sectors_per_cluster=0;
	}
      }
      if(expert>0)
      {
#ifdef HAVE_NCURSES
	wmove(stdscr, INTER_FAT_ASK_Y, INTER_FAT_ASK_X);
	sectors_per_cluster=ask_number(sectors_per_cluster,0,128,"cluster size ");
#endif
	switch(sectors_per_cluster)
	{
	  case 1:
	  case 2:
	  case 4:
	  case 8:
	  case 16:
	  case 32:
	  case 64:
	  case 128:
	    break;
	  default:
	    sectors_per_cluster=0;
	    break;
	}
      }
      if(sectors_per_cluster==0)
      {
	  display_message("Can't get cluster size\n");
	  return 0;
      }
    }
    if(upart_type==UP_FAT32)
    {
      /* Use first fat */
      fat32_free_info(disk_car,partition,reserved,data_size/sectors_per_cluster,&first_free_cluster,&free_cluster_count);
      /* FAT32 : Find root cluster */
      root_cluster=fat32_find_root_cluster(disk_car, partition, sectors_per_cluster, data_size/sectors_per_cluster, reserved, fat_length, verbose, expert, first_free_cluster, fats);
      if(expert>0)
      {
#ifdef HAVE_NCURSES
	int i;
	for(i=5; i<INTER_FAT_ASK_Y; i++)
	{
	  wmove(stdscr, i, 0);
	  wclrtoeol(stdscr);
	}
        wmove(stdscr, INTER_FAT_ASK_Y, INTER_FAT_ASK_X);
        root_cluster=ask_number(root_cluster,2,data_size/sectors_per_cluster+1,"root cluster ");
#endif
        if(verbose>1)
        {
          log_verbose("root_cluster=%lu (new)\n",root_cluster);
        }
      }
    }
#ifdef HAVE_NCURSES
    wmove(stdscr,9,0);
    wclrtoeol(stdscr);
    wrefresh(stdscr);
#endif
    create_fat_boot_sector(disk_car, partition, reserved, verbose, dir_entries, root_cluster, sectors_per_cluster, fat_length, upart_type, fats, current_cmd);
    if(verbose)
    {
      log_info("\n");
      log_partition(disk_car,partition);
    }
  }
  return 0;
}

int FAT_init_rootdir(disk_t *disk_car, partition_t *partition, const int verbose, char **current_cmd)
{
  unsigned long int fat_length,sector;
  uint64_t start_rootdir,start_data;
  unsigned int error=0;
  struct fat_boot_sector *fat_header;
  unsigned char *buffer;
  if(partition->upart_type!=UP_FAT12 && partition->upart_type!=UP_FAT16)
    return 1;
  if(check_FAT(disk_car,partition,verbose)!=0)
  {
    display_message("Boot sector not valid, can't check FAT.\n");
    return 1;
  }
  buffer=(unsigned char *)MALLOC(disk_car->sector_size);
  fat_header=(struct fat_boot_sector *)buffer;
  if((unsigned)disk_car->pread(disk_car, buffer, disk_car->sector_size, partition->part_offset) != disk_car->sector_size)
  {
    display_message("FAT_init_rootdir: Can't read boot sector\n");
    free(buffer);
    return 1;
  }
  fat_length=le16(fat_header->fat_length)>0?le16(fat_header->fat_length):le32(fat_header->fat32_length);
  start_rootdir=le16(fat_header->reserved)+ fat_header->fats*fat_length;
  start_data=start_rootdir+(get_dir_entries(fat_header)*32+disk_car->sector_size-1)/disk_car->sector_size;
  for(sector=start_rootdir;error==0 && sector<start_data;sector++)
  {
    if((unsigned)disk_car->pread(disk_car, buffer, disk_car->sector_size,
	  partition->part_offset + (uint64_t)sector * disk_car->sector_size) != disk_car->sector_size)
    {
      log_error("FAT_init_rootdir: read error at sector %lu\n", sector);
    }
    else
    {
      unsigned int i;
      for(i=0;error==0 && (i<disk_car->sector_size/0x20);i++)
      {
	if(check_FAT_dir_entry(&buffer[i*0x20],i)==2)
	{
	  error=1;
	}
      }
    }
  }
  if(error==0)
  {
    if(*current_cmd!=NULL)
      log_info("TestDisk doesn't seem needed to reset the root directory.\n");
    else
      display_message("TestDisk doesn't seem needed to reset the root directory.\n");
    free(buffer);
    return 0;
  }
#ifdef HAVE_NCURSES
  if(ask_confirmation("Initialize FAT root directory, confirm ? (Y/N)")!=0)
  {
    int err=0;
    log_info("Initialize FAT root directory\n");
    memset(buffer,0,disk_car->sector_size);
    for(sector=start_rootdir;sector<start_data;sector++)
    {
      if((unsigned)disk_car->pwrite(disk_car, buffer, disk_car->sector_size,
	    partition->part_offset + (uint64_t)sector * disk_car->sector_size) != disk_car->sector_size)
      {
	err=1;
      }
    }
    if(err>0)
    {
      display_message("FAT_init_rootdir: write failed.\n");
      free(buffer);
      return 1;
    }
  }
#endif
  free(buffer);
  return 0;
}

typedef enum { FAT_UNREADABLE=0, FAT_CORRUPTED=1, FAT_OK=2 } fat_status_t;
typedef enum { FAT_REPAIR_ASK=0, FAT_REPAIR_YES=1, FAT_REPAIR_NO=2 } fat_repair_t;

int repair_FAT_table(disk_t *disk_car, partition_t *partition, const int verbose, char **current_cmd)
{
  if(check_FAT(disk_car,partition,verbose)!=0)
  {
    display_message("Boot sector not valid, can't check FAT.\n");
    return 1;
  }
  {
    unsigned long int start_fat1,no_of_cluster,fat_length;
    unsigned int fats;
    unsigned int fat32_root_cluster=0;
    int fat_damaged=0;
#ifdef HAVE_NCURSES
    WINDOW *window=newwin(LINES, COLS, 0, 0);	/* full screen */
    aff_copy(window);
#endif
    {
      struct fat_boot_sector *fat_header;
      uint64_t part_size,start_data;
      unsigned char *buffer;
      buffer=(unsigned char *)MALLOC(disk_car->sector_size);
      fat_header=(struct fat_boot_sector *)buffer;
      if((unsigned)disk_car->pread(disk_car, buffer, disk_car->sector_size, partition->part_offset) != disk_car->sector_size)
      {
        display_message("repair_FAT_table: Can't read boot sector\n");
	free(buffer);
#ifdef HAVE_NCURSES
	delwin(window);
	(void) clearok(stdscr, TRUE);
#ifdef HAVE_TOUCHWIN
	touchwin(stdscr);
#endif
#endif
        return 1;
      }
      fat_length=le16(fat_header->fat_length)>0?le16(fat_header->fat_length):le32(fat_header->fat32_length);
      part_size=(fat_sectors(fat_header)>0?fat_sectors(fat_header):le32(fat_header->total_sect));
      start_fat1=le16(fat_header->reserved);
      fats=fat_header->fats;
      start_data=start_fat1+fats*fat_length+(get_dir_entries(fat_header)*32+disk_car->sector_size-1)/disk_car->sector_size;
      no_of_cluster=(part_size-start_data)/fat_header->sectors_per_cluster;
      fat32_root_cluster=le32(fat_header->root_cluster);
      log_info("repair_FAT_table cluster=2..%lu\n",no_of_cluster+1);
      free(buffer);
    }
    if(fats==0 || fats>2)
    {
#ifdef HAVE_NCURSES
      delwin(window);
      (void) clearok(stdscr, TRUE);
#ifdef HAVE_TOUCHWIN
      touchwin(stdscr);
#endif
#endif
      return 1;
    }
    {
      const unsigned int buffer_size=(partition->upart_type==UP_FAT12?2*disk_car->sector_size:disk_car->sector_size);
      fat_status_t fat_status[2];
      fat_repair_t allow_write[2];
      unsigned int fat_history[2][3];
      unsigned int old_offset_s=1234;
      unsigned int fat_mismatch=0;
      unsigned int fat_nbr;
      unsigned long int cluster;
#ifdef HAVE_NCURSES
      unsigned long int old_percent=0;
#endif
      unsigned char *buffer_fat[2];
      unsigned int rw_size=buffer_size;
      for(fat_nbr=0;fat_nbr<fats;fat_nbr++)
        buffer_fat[fat_nbr]=(unsigned char *)MALLOC(fats*buffer_size);
      for(fat_nbr=0;fat_nbr<fats;fat_nbr++)
      {
        fat_history[fat_nbr][FAT_UNREADABLE]=0;
        fat_history[fat_nbr][FAT_CORRUPTED]=0;
        fat_history[fat_nbr][FAT_OK]=0;
        allow_write[fat_nbr]=FAT_REPAIR_ASK;
        fat_status[fat_nbr]=FAT_OK;
      }
      for(cluster=2;cluster<=no_of_cluster+1;cluster++)
      {
        unsigned long int next_cluster;
        unsigned int offset_s,offset_o;
        if(partition->upart_type==UP_FAT32)
        {
          offset_s=cluster/(disk_car->sector_size/4);
          offset_o=cluster%(disk_car->sector_size/4);
        }
        else if(partition->upart_type==UP_FAT16)
        {
          offset_s=cluster/(disk_car->sector_size/2);
          offset_o=cluster%(disk_car->sector_size/2);
        }
        else
        {
          offset_s=(cluster+cluster/2)/disk_car->sector_size;
          offset_o=(cluster+cluster/2)%disk_car->sector_size;
          if(offset_s==fat_length-1)
            rw_size=disk_car->sector_size;
        }
        if(offset_s!=old_offset_s)
        {
#ifdef HAVE_NCURSES
          const unsigned long int percent=cluster*100/(no_of_cluster+1);
          if(percent!=old_percent)
          {
            wmove(window,4,0);
            wprintw(window,"Checking FAT %lu%%",percent);
            wrefresh(window);
            old_percent=percent;
          }
#endif
          /* Write if necessary */
          {
            unsigned int nbr_fat_unreadable=0;
            unsigned int nbr_fat_corrupted=0;
            unsigned int nbr_fat_ok=0;
            unsigned int good_fat_nbr=0;
            /* Some stats about FAT table */
            for(fat_nbr=0;fat_nbr<fats;fat_nbr++)
            {
              switch(fat_status[fat_nbr])
              {
                case FAT_UNREADABLE:
                  nbr_fat_unreadable++;
                  fat_history[fat_nbr][FAT_UNREADABLE]++;
                  break;
                case FAT_CORRUPTED:
                  nbr_fat_corrupted++;
                  fat_history[fat_nbr][FAT_CORRUPTED]++;
                  break;
                case FAT_OK:
                  nbr_fat_ok++;
                  good_fat_nbr=fat_nbr;
                  fat_history[fat_nbr][FAT_OK]++;
                  break;
              }
            }
            if(fat_mismatch!=0)
            {
              if(nbr_fat_ok>1)
              {
                good_fat_nbr=0;
                for(fat_nbr=1;fat_nbr<fats;fat_nbr++)
                {
                  if(fat_history[fat_nbr][FAT_OK]>fat_history[good_fat_nbr][FAT_OK])
                  {
                    good_fat_nbr=fat_nbr;
                  }
                  else if(fat_history[fat_nbr][FAT_OK] == fat_history[good_fat_nbr][FAT_OK])
                  {
                    unsigned long int fat_offset=0;
                    if(fat_find_fat_start(buffer_fat[fat_nbr], (partition->upart_type==UP_FAT12),
                          (partition->upart_type==UP_FAT16), (partition->upart_type==UP_FAT32),
                          &fat_offset,disk_car->sector_size)!=0)
                      good_fat_nbr=fat_nbr;
                  }
                }
              }
            }
            if(verbose>1 || nbr_fat_ok!=fats || fat_mismatch>0)
            {
              log_verbose("nbr_fat_unreadable %u, nbr_fat_corrupted %u, nbr_fat_ok %u, good_fat_nbr %u, fat_mismatch %u\n",
                  nbr_fat_unreadable, nbr_fat_corrupted, nbr_fat_ok, good_fat_nbr, fat_mismatch);
            }
            /* Write FAT if necessary */
            if(fat_mismatch!=0)
            {
              fat_damaged=1;
              if(nbr_fat_ok>=1)
              {
                /* Use the good/best FAT to repair the bad one */
                for(fat_nbr=0;fat_nbr<fats;fat_nbr++)
                {
                  if(fat_nbr!=good_fat_nbr)
                  {
                    if(verbose>2)
                    {
                      dump_log(buffer_fat[fat_nbr], rw_size);
                    }
                    if(allow_write[fat_nbr]==FAT_REPAIR_ASK)
                    {
#ifdef HAVE_NCURSES
                      if(ask_confirmation("Use FAT%u to repair FAT%u table, confirm ? (Y/N)",good_fat_nbr+1,fat_nbr+1)!=0)
                      {
                        allow_write[fat_nbr]=FAT_REPAIR_YES;
                      }
                      else
#endif
                      {
                        allow_write[fat_nbr]=FAT_REPAIR_NO;
                        log_info("repair_FAT_table: doesn't correct FAT%u (sector %lu) using FAT%u\n",fat_nbr+1,
                            start_fat1+fat_length*fat_nbr+old_offset_s, good_fat_nbr+1);
                      }
                    }
                    if(allow_write[fat_nbr]==FAT_REPAIR_YES)
                    {
                      log_info("repair_FAT_table: correcting FAT%u (sector %lu) using FAT%u\n",fat_nbr+1,
                          start_fat1+fat_length*fat_nbr+old_offset_s, good_fat_nbr+1);
                      if((unsigned)disk_car->pwrite(disk_car, buffer_fat[good_fat_nbr], rw_size,
			    partition->part_offset + (uint64_t)(start_fat1 + fat_length * fat_nbr + old_offset_s) * disk_car->sector_size) != rw_size)
                      {
                        display_message("repair_FAT_table: write failed.\n");
                      }
                    }
                  }
                }
              }
              else
              {
                for(fat_nbr=0;fat_nbr<fats;fat_nbr++)
                {
                  if(allow_write[fat_nbr]==FAT_REPAIR_ASK)
                  {
#ifdef HAVE_NCURSES
                    if(ask_confirmation("Remove invalid cluster from FAT%u table, confirm ? (Y/N)",fat_nbr+1)!=0)
                    {
                      allow_write[fat_nbr]=FAT_REPAIR_YES;
                    }
                    else
#endif
                    {
                      allow_write[fat_nbr]=FAT_REPAIR_NO;
                      log_info("repair_FAT_table: doesn't correct FAT%u (sector %lu)\n",fat_nbr+1,
                          start_fat1+fat_length*fat_nbr+old_offset_s);
                    }
                  }
                  if(allow_write[fat_nbr]==FAT_REPAIR_YES)
                  {
                    log_info("repair_FAT_table: correcting FAT%u (sector %lu)\n",fat_nbr+1,
                        start_fat1+fat_length*fat_nbr+old_offset_s);
                    if((unsigned)disk_car->pwrite(disk_car, buffer_fat[fat_nbr], rw_size,
			  partition->part_offset + (uint64_t)(start_fat1 + fat_length * fat_nbr + old_offset_s) * disk_car->sector_size) != rw_size)
                    {
                      display_message("repair_FAT_table: write failed.\n");
                    }
                  }
                }
              }
            }
            else
            {
              /* only one fat or fat match */
              if(nbr_fat_ok==0)
              { /* fat_corrupted */
                fat_damaged=1;
                for(fat_nbr=0;fat_nbr<fats;fat_nbr++)
                {
                  if(verbose>2)
                  {
                    dump_log(buffer_fat[fat_nbr], rw_size);
                  }
                  if(allow_write[fat_nbr]==FAT_REPAIR_ASK)
                  {
#ifdef HAVE_NCURSES
                    if(ask_confirmation("Remove invalid cluster from FAT%u table, confirm ? (Y/N)",fat_nbr+1)!=0)
                    {
                      allow_write[fat_nbr]=FAT_REPAIR_YES;
                      log_info("repair_FAT_table: correcting FAT%u (sector %lu)\n",fat_nbr+1,
                          start_fat1+fat_length*fat_nbr+old_offset_s);
                    }
                    else
#endif
                    {
                      allow_write[fat_nbr]=FAT_REPAIR_NO;
                      log_info("repair_FAT_table: doesn't correct FAT%u (sector %lu)\n",fat_nbr+1,
                          start_fat1+fat_length*fat_nbr+old_offset_s);
                    }
                  }
                  if(allow_write[fat_nbr]==FAT_REPAIR_YES)
                  {
                    if((unsigned)disk_car->pwrite(disk_car, buffer_fat[fat_nbr], rw_size,
			  partition->part_offset + (uint64_t)(start_fat1 + fat_length * fat_nbr + old_offset_s) * disk_car->sector_size) != rw_size )
                    {
                      display_message("repair_FAT_table: write failed.\n");
                    }
                  }
                }
              }
            }
          }
          /* Read FAT */
          for(fat_nbr=0;fat_nbr<fats;fat_nbr++)
          {
            fat_status[fat_nbr]=FAT_OK;
            if(verbose>1)
            {
              log_info("repair_FAT_table: read sector %lu (FAT%u)\n",(start_fat1+fat_length*fat_nbr+offset_s),fat_nbr+1);
            }
            if((unsigned)disk_car->pread(disk_car, buffer_fat[fat_nbr], rw_size,
		  partition->part_offset + (uint64_t)(start_fat1 + fat_length * fat_nbr + offset_s) * disk_car->sector_size) != rw_size)
            {
              log_error("repair_FAT_table: read error sector %lu\n",(start_fat1+fat_length*fat_nbr+offset_s));
              memset(buffer_fat[fat_nbr],0, rw_size);
              fat_status[fat_nbr]=FAT_UNREADABLE;
            }
            if(verbose>1)
            {
              dump_log(buffer_fat[fat_nbr], rw_size);
            }
          }
          /* Compare FAT */
          fat_mismatch=0;
          for(fat_nbr=1;fat_nbr<fats && fat_mismatch==0;fat_nbr++)
          {
            if(memcmp(buffer_fat[0], buffer_fat[fat_nbr], rw_size)!=0)
              fat_mismatch=1;
          }
        }
        /* Repair FAT if necessary */
        for(fat_nbr=0;fat_nbr<fats;fat_nbr++)
        {
          if(partition->upart_type==UP_FAT32)
          {
            uint32_t *p32=(uint32_t*)buffer_fat[fat_nbr];
            next_cluster=(le32(p32[offset_o]) & 0xFFFFFFF);
            if((next_cluster<0x0FFFFFF7 && (next_cluster==1 || next_cluster>no_of_cluster+1)) ||
                (cluster==fat32_root_cluster && next_cluster==0))
            {
#ifdef DEBUG
              log_trace("FAT%u cluster %lu(%lx)->%lu(%lx)\n",fat_nbr+1,cluster,cluster,next_cluster,next_cluster);
#endif
              p32[offset_o]=le32(FAT32_EOC);
              fat_status[fat_nbr]=FAT_CORRUPTED;
            }
          }
          else if(partition->upart_type==UP_FAT16)
          {
            uint16_t *p16=(uint16_t*)buffer_fat[fat_nbr];
            next_cluster=le16(p16[offset_o]);
            if(next_cluster<0xFFF7 && (next_cluster==1 || next_cluster>no_of_cluster+1))
            {
              p16[offset_o]=le16(FAT16_EOC);
              fat_status[fat_nbr]=FAT_CORRUPTED;
            }
          }
          else
          {
            if((cluster&1)!=0)
              next_cluster=le16((*((uint16_t*)&buffer_fat[fat_nbr][offset_o])))>>4;
            else
              next_cluster=le16(*((uint16_t*)&buffer_fat[fat_nbr][offset_o]))&0x0FFF;
            if(next_cluster<0x0FF7 && (next_cluster==1 || next_cluster>no_of_cluster+1))
            {
              if((cluster&1)!=0)
                *((uint16_t*)&buffer_fat[fat_nbr][offset_o])=le16((FAT12_EOC<<4)|(le16((*((uint16_t*)&buffer_fat[fat_nbr][offset_o])))&0x0F));
              else
                *((uint16_t*)&buffer_fat[fat_nbr][offset_o])=le16(FAT12_EOC     |(le16((*((uint16_t*)&buffer_fat[fat_nbr][offset_o])))&0xF000));
              fat_status[fat_nbr]=FAT_CORRUPTED;
            }
          }
        }
        old_offset_s=offset_s;
      }
      /* Write if necessary the last cluster */
      {
        unsigned int nbr_fat_unreadable=0;
        unsigned int nbr_fat_corrupted=0;
        unsigned int nbr_fat_ok=0;
        unsigned int good_fat_nbr=0;
        /* Some stats about FAT table */
        for(fat_nbr=0;fat_nbr<fats;fat_nbr++)
        {
          switch(fat_status[fat_nbr])
          {
            case FAT_UNREADABLE:
              nbr_fat_unreadable++;
              fat_history[fat_nbr][FAT_UNREADABLE]++;
              break;
            case FAT_CORRUPTED:
              nbr_fat_corrupted++;
              fat_history[fat_nbr][FAT_CORRUPTED]++;
              break;
            case FAT_OK:
              nbr_fat_ok++;
              good_fat_nbr=fat_nbr;
              fat_history[fat_nbr][FAT_OK]++;
              break;
          }
        }
        if(fat_mismatch!=0)
        {
          if(nbr_fat_ok>1)
          {
            for(fat_nbr=0;fat_nbr<fats;fat_nbr++)
            {
              if(fat_nbr!=good_fat_nbr)
              {
                if(fat_history[fat_nbr][FAT_OK]>fat_history[good_fat_nbr][FAT_OK])
                {
                  good_fat_nbr=fat_nbr;
                }
                else if(fat_history[fat_nbr][FAT_OK] == fat_history[good_fat_nbr][FAT_OK])
                {
                  unsigned long int fat_offset=0;
                  if(fat_find_fat_start(buffer_fat[fat_nbr], (partition->upart_type==UP_FAT12),
                        (partition->upart_type==UP_FAT16), (partition->upart_type==UP_FAT32),
                        &fat_offset,disk_car->sector_size)!=0)
                    good_fat_nbr=fat_nbr;
                }
              }
            }
          }
        }
        if(verbose>1 || nbr_fat_ok!=fats || fat_mismatch>0)
        {
          log_info("nbr_fat_unreadable %u, nbr_fat_corrupted %u, nbr_fat_ok %u, good_fat_nbr %u, fat_mismatch %u\n",
              nbr_fat_unreadable, nbr_fat_corrupted, nbr_fat_ok, good_fat_nbr, fat_mismatch);
        }
        /* Write FAT if necessary */
        if(fat_mismatch!=0)
        {
          fat_damaged=1;
          if(nbr_fat_ok>=1)
          {
            /* Use the good/best FAT to repair the bad one */
            for(fat_nbr=0;fat_nbr<fats;fat_nbr++)
            {
              if(fat_nbr!=good_fat_nbr)
              {
                if(verbose>2)
                {
                  dump_log(buffer_fat[fat_nbr], rw_size);
                }
                if(allow_write[fat_nbr]==FAT_REPAIR_ASK)
                {
#ifdef HAVE_NCURSES
                  if(ask_confirmation("Use FAT%u to repair FAT%u table, confirm ? (Y/N)",good_fat_nbr+1,fat_nbr+1)!=0)
                  {
                    allow_write[fat_nbr]=FAT_REPAIR_YES;
                    log_info("repair_FAT_table: correcting FAT%u (sector %lu) using FAT%u\n",fat_nbr+1,
                        start_fat1+fat_length*fat_nbr+old_offset_s, good_fat_nbr+1);
                  }
                  else
#endif
                  {
                    allow_write[fat_nbr]=FAT_REPAIR_NO;
                    log_info("repair_FAT_table: doesn't correct FAT%u (sector %lu) using FAT%u\n",fat_nbr+1,
                        start_fat1+fat_length*fat_nbr+old_offset_s, good_fat_nbr+1);
                  }
                }
                if(allow_write[fat_nbr]==FAT_REPAIR_YES)
                {
                  if((unsigned)disk_car->pwrite(disk_car, buffer_fat[good_fat_nbr], rw_size,
			partition->part_offset + (uint64_t)(start_fat1 + fat_length * fat_nbr + old_offset_s) * disk_car->sector_size) != rw_size)
                  {
                    display_message("repair_FAT_table: write failed.\n");
                  }
                }
              }
            }
          }
          else
          {
            for(fat_nbr=0;fat_nbr<fats;fat_nbr++)
            {
              if(allow_write[fat_nbr]==FAT_REPAIR_ASK)
              {
#ifdef HAVE_NCURSES
                if(ask_confirmation("Remove invalid cluster from FAT%u table, confirm ? (Y/N)",fat_nbr+1)!=0)
                {
                  allow_write[fat_nbr]=FAT_REPAIR_YES;
                  log_info("repair_FAT_table: correcting FAT%u (sector %lu)\n",fat_nbr+1,
                      start_fat1+fat_length*fat_nbr+old_offset_s);
                }
                else
#endif
                {
                  allow_write[fat_nbr]=FAT_REPAIR_NO;
                  log_info("repair_FAT_table: doesn't correct FAT%u (sector %lu)\n",fat_nbr+1,
                      start_fat1+fat_length*fat_nbr+old_offset_s);
                }
              }
              if(allow_write[fat_nbr]==FAT_REPAIR_YES)
              {
                if((unsigned)disk_car->pwrite(disk_car, buffer_fat[fat_nbr], rw_size,
		      partition->part_offset + (uint64_t)(start_fat1 + fat_length * fat_nbr + old_offset_s) * disk_car->sector_size) != rw_size)
                {
                  display_message("repair_FAT_table: write failed.\n");
                }
              }
            }
          }
        }
        else
        {
          /* only one fat or fat match */
          if(nbr_fat_ok==0)
          { /* fat_corrupted */
            fat_damaged=1;
            for(fat_nbr=0;fat_nbr<fats;fat_nbr++)
            {
              if(verbose>2)
              {
                dump_log(buffer_fat[fat_nbr], rw_size);
              }
              if(allow_write[fat_nbr]==FAT_REPAIR_ASK)
              {
#ifdef HAVE_NCURSES
                if(ask_confirmation("Remove invalid cluster from FAT%u table, confirm ? (Y/N)",fat_nbr+1)!=0)
                {
                  allow_write[fat_nbr]=FAT_REPAIR_YES;
                  log_info("repair_FAT_table: correcting FAT%u (sector %lu)\n",fat_nbr+1,
                      start_fat1+fat_length*fat_nbr+old_offset_s);
                }
                else
#endif
                {
                  allow_write[fat_nbr]=FAT_REPAIR_NO;
                  log_info("repair_FAT_table: doesn't correct FAT%u (sector %lu)\n",fat_nbr+1,
                      start_fat1+fat_length*fat_nbr+old_offset_s);
                }
              }
              if(allow_write[fat_nbr]==FAT_REPAIR_YES)
              {
                if((unsigned)disk_car->pwrite(disk_car, buffer_fat[fat_nbr], rw_size,
		      partition->part_offset + (uint64_t)(start_fat1 + fat_length * fat_nbr + old_offset_s) * disk_car->sector_size) != rw_size)
                {
                  display_message("repair_FAT_table: write failed.\n");
                }
              }
            }
          }
        }
      }
      for(fat_nbr=0;fat_nbr<fats;fat_nbr++)
        free(buffer_fat[fat_nbr]);
    }
    if(fat_damaged==0)
    {
      if(current_cmd!=NULL)
	log_info("FATs seems Ok, nothing to do.\n");
      else
	display_message("FATs seems Ok, nothing to do.\n");
    }
    else
    {
      disk_car->sync(disk_car);
    }
#ifdef HAVE_NCURSES
    delwin(window);
    (void) clearok(stdscr, TRUE);
#ifdef HAVE_TOUCHWIN
    touchwin(stdscr);
#endif
#endif
  }
  return 0;
}

static int write_FAT_boot_code_aux(unsigned char *buffer)
{
  const unsigned char boot_code[DEFAULT_SECTOR_SIZE]= {
    0xeb, 0x3c, 0x90, 0x6d, 0x6b, 0x64, 0x6f, 0x73, 0x66, 0x73, 0x00, 0x00, 0x02, 0x08, 0x01, 0x00,
    0x02, 0x00, 0x02, 0x00, 0x00, 0xf8, 0xcc, 0x00, 0x3f, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x29, 0xf8, 0x3f, 0x7c, 0x3e, 'T',   'E',   'S', 'T',  'D',
     'I',  'S',  'K', 0x20, 0x20, 0x20, 0x46, 0x41, 0x54, 0x31, 0x36, 0x20, 0x20, 0x20, 0x0e, 0x1f,
    0xbe, 0x5b, 0x7c, 0xac, 0x22, 0xc0, 0x74, 0x0b, 0x56, 0xb4, 0x0e, 0xbb, 0x07, 0x00, 0xcd, 0x10,
    0x5e, 0xeb, 0xf0, 0x32, 0xe4, 0xcd, 0x16, 0xcd, 0x19, 0xeb, 0xfe,  'T', 'h',   'i',  's',  ' ',
     'i',  's',  ' ',  'n',  'o',  't',  ' ',  'a',  ' ',  'b',  'o',  'o',  't',  'a',  'b',  'l',
     'e',  ' ',  'd',  'i',  's',  'k',  '.',  ' ',  ' ',  'P',  'l',  'e',  'a',  's',  'e',  ' ',
     'i',  'n',  's',  'e',  'r',  't',  ' ',  'a',  ' ',  'b',  'o',  'o',  't',  'a',  'b',  'l',
     'e',  ' ',  'f',  'l',  'o',  'p',  'p',  'y',  ' ',  'a',  'n',  'd', 0x0d, 0x0a,  'p',  'r',
     'e',  's',  's',  ' ',  'a',  'n',  'y',  ' ',  'k',  'e',  'y',  ' ',  't',  'o',  ' ',  't',
     'r', 'y',   ' ',  'a',  'g',  'a',  'i',  'n',  ' ',  '.',  '.',  '.',  ' ', 0x0d, 0x0a, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0xaa
  };
  memcpy(buffer,&boot_code,DEFAULT_SECTOR_SIZE);
  return 0;
}
