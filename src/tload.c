/*

    File: tload.c

    Copyright (C) 2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#endif
#include "fnctdsk.h"
#include "savehdr.h"
#include "log.h"
#include "log_part.h"
#include "tload.h"

#ifdef HAVE_NCURSES
static list_part_t *merge_partition_list(list_part_t *list_part, list_part_t *backup_part);

#define INTER_LOAD	13
#define INTER_LOAD_X    0
#define INTER_LOAD_Y	22

static struct td_list_head *interface_load_ncurses(disk_t *disk_car, backup_disk_t *backup_list)
{
  int offset=0;
  int backup_current_num=0;
  int rewrite=1;
  unsigned int menu=3;   /* default : quit */
  struct td_list_head *backup_current=backup_list->list.next;
  struct td_list_head *backup_walker=NULL;
  const struct MenuItem menuLoadBackup[]=
  {
    { 'P', "Previous",""},
    { 'N', "Next","" },
    { 'L',"Load","Load partition structure from backup and try to locate partition"},
    { 'Q',"Cancel","Don't use backup and try to locate partition"},
    { 0, NULL, NULL }
  };
  char options[20];
  while(1)
  {
    int i;
    if(rewrite)
    {
      aff_copy(stdscr);
      mvwaddstr(stdscr,4,0,disk_car->description(disk_car));
      if(!td_list_empty(&backup_list->list))
      {
	mvwaddstr(stdscr,5,0,"Choose the backup you want to restore:");
	mvwaddstr(stdscr,20,0,"PS: Don't worry, you will have to confirm the partition restoration.");
      }
      else
      {
	mvwaddstr(stdscr,5,0,"No backup found!");
      }
      rewrite=0;
    }
    if(!td_list_empty(&backup_list->list))
    {
      backup_disk_t *backup=NULL;
      for(i=0,backup_walker=backup_list->list.next;
	  backup_walker!=&backup_list->list && i<offset+INTER_LOAD;
	  backup_walker=backup_walker->next,i++)
      {
	if(i<offset)
	  continue;
	backup=td_list_entry(backup_walker, backup_disk_t, list);
	wmove(stdscr,8+i-offset,0);
	wclrtoeol(stdscr);	/* before addstr for BSD compatibility */
	if(backup_walker==backup_current)
	{
	  wattrset(stdscr, A_REVERSE);
	  wprintw(stdscr,">%s %s",backup->description,ctime(&backup->my_time));
	  wattroff(stdscr, A_REVERSE);
	} else
	{
	  wprintw(stdscr," %s %s",backup->description,ctime(&backup->my_time));
	}
      }
      if(i<=INTER_LOAD && backup==NULL)
      {
	strncpy(options,"LQ",sizeof(options));
	menu=0;
      }
      else
      {
	strncpy(options,"PNLQ",sizeof(options));
	menu=2;
      }
    }
    else
    {
      menu=0;
      strncpy(options,"Q",sizeof(options));
    }
    switch(wmenuSelect(stdscr, INTER_LOAD_Y+1, INTER_LOAD_Y,INTER_LOAD_X, menuLoadBackup, 8, options, MENU_HORIZ| MENU_BUTTON | MENU_ACCEPT_OTHERS, menu))
    {
      case 'q':
      case 'Q':
	return NULL;
      case 'l':
      case 'L':
	if(backup_current==&backup_list->list)
	  return NULL;
	return backup_current;
      case KEY_UP:
	if(backup_current->prev!=&backup_list->list)
	{
	  backup_current=backup_current->prev;
	  backup_current_num--;
	}
	break;
      case KEY_DOWN:
	if(backup_current->next!=&backup_list->list)
	{
	  backup_current=backup_current->next;
	  backup_current_num++;
	}
	break;
      case KEY_PPAGE:
	for(i=0;(i<INTER_LOAD) && (backup_current->prev!=&backup_list->list);i++)
	{
	  backup_current=backup_current->prev;
	  backup_current_num--;
	}
	break;
      case KEY_NPAGE:
	for(i=0;(i<INTER_LOAD) && (backup_current->next!=&backup_list->list);i++)
	{
	  backup_current=backup_current->next;
	  backup_current_num++;
	}
	break;
      default:
	/*	log_trace("ask_structure car=%x\n",car); */
	break;
    }
    if(backup_current_num<offset)
      offset=backup_current_num;
    if(backup_current_num>=offset+INTER_LOAD)
      offset=backup_current_num-INTER_LOAD+1;
  }
}

static list_part_t *merge_partition_list(list_part_t *list_part, list_part_t *backup_part)
{
  list_part_t *partition;
  for(partition=backup_part;partition!=NULL;partition=partition->next)
  {
    int insert_error=0;
    partition_t *new_partition=partition_new(NULL);
    dup_partition_t(new_partition,partition->part);
    list_part=insert_new_partition(list_part, new_partition, 0, &insert_error);
    if(insert_error>0)
      free(new_partition);
  }
  return list_part;
}

list_part_t *interface_load(disk_t *disk_car,list_part_t *list_part, const int verbose)
{
  struct td_list_head *backup_walker=NULL;
  struct td_list_head *backup_current=NULL;
  backup_disk_t *backup_list=partition_load(disk_car,verbose);
  log_info("interface_load\n");
  td_list_for_each(backup_walker,&backup_list->list)
  {
    backup_disk_t *backup;
    backup=td_list_entry(backup_walker, backup_disk_t, list);
    log_info("%s %s",backup->description,ctime(&backup->my_time));
    log_all_partitions(disk_car, backup->list_part);
  }
#ifdef HAVE_NCURSES
  backup_current=interface_load_ncurses(disk_car, backup_list);
#endif
  if(backup_current!=NULL)
  {
    list_part_t *partition;
    backup_disk_t *backup;
    backup=td_list_entry(backup_current, backup_disk_t, list);
    for(partition=backup->list_part;partition!=NULL;partition=partition->next)
    {
      /* Check partition and load partition name */
      disk_car->arch->check_part(disk_car,verbose,partition->part,0);
    }
    list_part=merge_partition_list(list_part, backup->list_part);
  } 
  { /* Cleanup */
    struct td_list_head *backup_walker_next = NULL;
    td_list_for_each_safe(backup_walker,backup_walker_next,&backup_list->list)
    {
      backup_disk_t *backup;
      backup=td_list_entry(backup_walker, backup_disk_t, list);
      part_free_list(backup->list_part);
      free(backup);
    }
    free(backup_list);
  }
  return list_part;
}
#endif
