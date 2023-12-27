/*

    File: dirn.c

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

#if defined(DISABLED_FOR_FRAMAC)
#undef HAVE_NCURSES
#endif
 
#ifdef HAVE_NCURSES
#include <stdio.h>
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#include "types.h"
#include "common.h"
#include "intrf.h"
#include "intrfn.h"
#include "dir.h"
#include "log.h"
#include "log_part.h"
#include "dirn.h"
#include "askloc.h"
#include "setdate.h"

typedef enum { CD_FINISHED = 0, CD_STOPPED = 1, CD_NOSPACE = 2 } copy_dir_t;
static copy_dir_t copy_dir(WINDOW *window, disk_t *disk, const partition_t *partition, dir_data_t *dir_data, const file_info_t *dir, unsigned int *copy_ok, unsigned int *copy_bad);
static copy_dir_t copy_selection(file_info_t*dir_list, WINDOW *window, disk_t *disk, const partition_t *partition, dir_data_t *dir_data, unsigned int *copy_ok, unsigned int *copy_bad);

#define INTER_DIR (LINES-25+15)
#define MAX_DIR_NBR 256

static int copy_progress(WINDOW *window, const unsigned int copy_ok, const unsigned int copy_bad)
{
  static time_t prev_time=0;
  const time_t tmp=time(NULL);
  if(tmp!=prev_time)
  {
    prev_time=tmp;
    wmove(window,5,0);
    wclrtoeol(window);
    if(has_colors())
    {
      if(copy_bad > 0)
	wbkgdset(window,' ' | A_BOLD | COLOR_PAIR(1));
      else
	wbkgdset(window,' ' | A_BOLD | COLOR_PAIR(2));
    }
    wprintw(window,"Copying, please wait... %u ok, %u failed", copy_ok, copy_bad);
    if(has_colors())
      wbkgdset(window,' ' | COLOR_PAIR(0));
    wrefresh(window);
  }
  return check_enter_key_or_s(window);
}

static void copy_done(WINDOW *window, const unsigned int copy_ok, const unsigned int copy_bad, const copy_dir_t copy_stopped)
{
  wmove(window,5,0);
  wclrtoeol(window);
  if(has_colors())
  {
    if(copy_bad > 0)
      wbkgdset(window,' ' | A_BOLD | COLOR_PAIR(1));
    else
      wbkgdset(window,' ' | A_BOLD | COLOR_PAIR(2));
  }
  if(copy_stopped == CD_STOPPED)
    wprintw(window,"Copy stopped! %u ok, %u failed", copy_ok, copy_bad);
  else if(copy_stopped == CD_NOSPACE)
    wprintw(window,"Copy stopped! %u ok, %u failed - Not enough space", copy_ok, copy_bad);
  else
    wprintw(window,"Copy done! %u ok, %u failed", copy_ok, copy_bad);
  if(has_colors())
    wbkgdset(window,' ' | COLOR_PAIR(0));
  wrefresh(window);
}

static long int dir_aff_ncurses(disk_t *disk, const partition_t *partition, dir_data_t *dir_data, file_info_t*dir_list, const unsigned long int inode, const unsigned int depth)
{
  /* Return value
   * -1: quit
   *  1: back
   *  other: new inode
   * */
  int quit=0;
  int ask_destination=1;
  WINDOW *window=(WINDOW*)dir_data->display;
  const char *needle=NULL;
  do
  {
    int offset=0;
    int pos_num=0;
    struct td_list_head *pos=dir_list->list.next;
    const int old_LINES=LINES;
    unsigned int status=FILE_STATUS_MARKED;
    aff_copy(window);
    wmove(window,3,0);
    aff_part(window, AFF_PART_ORDER|AFF_PART_STATUS, disk, partition);
    wmove(window,4,0);
    wprintw(window,"Directory %s\n",dir_data->current_directory);
    do
    {
      int i;
      int car;
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
	wmove(window, 6+i-offset, 0);
	wclrtoeol(window);	/* before addstr for BSD compatibility */
	if(&current_file->list==pos)
	{
	  wattrset(window, A_REVERSE);
	  waddstr(window, ">");
	}
	else if((current_file->status&FILE_STATUS_MARKED)!=0)
	  waddstr(window, "*");
	else
	  waddstr(window, " ");
	if(has_colors())
	{
	  if((current_file->status&FILE_STATUS_MARKED)!=0)
	    wbkgdset(window,' ' | COLOR_PAIR(2));
	  else if((current_file->status&FILE_STATUS_DELETED)!=0)
	    wbkgdset(window,' ' | COLOR_PAIR(1));
	}
	set_datestr((char *)&datestr, sizeof(datestr), current_file->td_mtime);
	mode_string(current_file->st_mode, str);
	wprintw(window, "%s %5u %5u ", 
	    str, (unsigned int)current_file->st_uid, (unsigned int)current_file->st_gid);
	wprintw(window, "%9llu", (long long unsigned int)current_file->st_size);
	/* screen may overlap due to long filename */
	wprintw(window, " %s %s", datestr, current_file->name);
	if((current_file->status&(FILE_STATUS_DELETED|FILE_STATUS_MARKED))!=0 &&
	    has_colors())
	  wbkgdset(window,' ' | COLOR_PAIR(0));
	if(&current_file->list==pos)
	  wattroff(window, A_REVERSE);
      }
      wmove(window, 6-1, 51);
      wclrtoeol(window);
      if(offset>0)
	wprintw(window, "Previous");
      /* Clear the last line, useful if overlapping */
      wmove(window,6+i-offset,0);
      wclrtoeol(window);
      wmove(window, 6+INTER_DIR, 51);
      wclrtoeol(window);
      if(file_walker->next!=&dir_list->list)
	wprintw(window, "Next");
      if(td_list_empty(&dir_list->list))
      {
	wmove(window,6,0);
	wprintw(window,"No file found, filesystem may be damaged.");
      }
      /* Redraw the bottom of the screen everytime because very long filenames may have corrupt it*/
      mvwaddstr(window,LINES-3,0,"Use ");
      if(depth>0)
      {
	if(has_colors())
	  wbkgdset(window,' ' | A_BOLD | COLOR_PAIR(0));
	waddstr(window, "Left");
	if(has_colors())
	  wbkgdset(window,' ' | COLOR_PAIR(0));
	waddstr(window," arrow to go back, ");
      }
      if(has_colors())
	wbkgdset(window,' ' | A_BOLD | COLOR_PAIR(0));
      waddstr(window,"Right");
      if(has_colors())
	wbkgdset(window,' ' | COLOR_PAIR(0));
      waddstr(window," to change directory");
      if((dir_data->capabilities&CAPA_LIST_DELETED)!=0)
      {
	waddstr(window,", ");
	if(has_colors())
	  wbkgdset(window,' ' | A_BOLD | COLOR_PAIR(0));
	waddstr(window,"'h'");
	if(has_colors())
	  wbkgdset(window,' ' | COLOR_PAIR(0));
	if((dir_data->param&FLAG_LIST_DELETED)==0)
	  waddstr(window," to unhide deleted files");
	else
	  waddstr(window," to hide deleted files");
      }
      else if((dir_data->capabilities&CAPA_LIST_ADS)!=0)
      {
	waddstr(window,", ");
	if(has_colors())
	  wbkgdset(window,' ' | A_BOLD | COLOR_PAIR(0));
	waddstr(window,"'h'");
	if(has_colors())
	  wbkgdset(window,' ' | COLOR_PAIR(0));
	if((dir_data->param&FLAG_LIST_ADS)==0)
	  waddstr(window," to unhide Alternate Data Stream");
	else
	  waddstr(window," to hide Alternate Data Stream");
      }
      wmove(window,LINES-2,4);
      if(has_colors())
	wbkgdset(window,' ' | A_BOLD | COLOR_PAIR(0));
      waddstr(window,"'q'");
      if(has_colors())
	wbkgdset(window,' ' | COLOR_PAIR(0));
      waddstr(window," to quit");
      if(dir_data->copy_file!=NULL)
      {
	waddstr(window,", ");
	if(has_colors())
	  wbkgdset(window,' ' | A_BOLD | COLOR_PAIR(0));
	waddstr(window,"':'");
	if(has_colors())
	  wbkgdset(window,' ' | COLOR_PAIR(0));
	waddstr(window," to select the current file, ");
	if(has_colors())
	  wbkgdset(window,' ' | A_BOLD | COLOR_PAIR(0));
	waddstr(window,"'a'");
	if(has_colors())
	  wbkgdset(window,' ' | COLOR_PAIR(0));
	if((status&FILE_STATUS_MARKED)==FILE_STATUS_MARKED)
	  waddstr(window," to select all files  ");
	else
	  waddstr(window," to deselect all files");
	if(has_colors())
	  wbkgdset(window,' ' | A_BOLD | COLOR_PAIR(0));
	mvwaddstr(window,LINES-1,4,"'C'");
	if(has_colors())
	  wbkgdset(window,' ' | COLOR_PAIR(0));
	waddstr(window," to copy the selected files, ");
	if(has_colors())
	  wbkgdset(window,' ' | A_BOLD | COLOR_PAIR(0));
	waddstr(window,"'c'");
	if(has_colors())
	  wbkgdset(window,' ' | COLOR_PAIR(0));
	waddstr(window," to copy the current file");
      }
      wrefresh(window);
      /* Using gnome terminal under FC3, TERM=xterm, the screen is not always correct */
      wredrawln(window,0,getmaxy(window));	/* redrawwin def is boggus in pdcur24 */
      car=wgetch(window);
      wmove(window,5,0);
      wclrtoeol(window);
      switch(car)
      {
	case key_ESC:
	case 'q':
	case 'M':
	  quit=1;
	  break;
	case '-':
	case KEY_LEFT:
	case '4':
	  if(depth>0)
	    return 1;
	  break;
	case 'h':
	  if((dir_data->capabilities&CAPA_LIST_DELETED)!=0)
	    dir_data->param^=FLAG_LIST_DELETED;
	  else if((dir_data->capabilities&CAPA_LIST_ADS)!=0)
	    dir_data->param^=FLAG_LIST_ADS;
	  return inode;
	case 0x0c:	/* ctrl+L */
	  touchwin(stdscr);
	  touchwin(window);
	  wrefresh(window);
	  break;
      }
      if(!td_list_empty(&dir_list->list))
      {
	switch(car)
	{
	  case KEY_UP:
	  case '8':
	    if(pos->prev!=&dir_list->list)
	    {
	      pos=pos->prev;
	      pos_num--;
	    }
	    break;
	  case KEY_DOWN:
	  case '2':
	    if(pos->next!=&dir_list->list)
	    {
	      pos=pos->next;
	      pos_num++;
	    }
	    break;
	  case ':':
	    {
	      file_info_t *selected_file;
	      selected_file=td_list_entry(pos, file_info_t, list);
	      if(!(selected_file->name[0]=='.' && selected_file->name[1]=='\0') &&
		  !(selected_file->name[0]=='.' && selected_file->name[1]=='.' && selected_file->name[2]=='\0'))
		selected_file->status^=FILE_STATUS_MARKED;
	    }
	    if(pos->next!=&dir_list->list)
	    {
	      pos=pos->next;
	      pos_num++;
	    }
	    break;
	  case 'a':
	    {
	      struct td_list_head *tmpw= NULL;
	      td_list_for_each(tmpw, &dir_list->list)
	      {
		file_info_t *tmp=td_list_entry(tmpw, file_info_t, list);
		if((tmp->name[0]=='.' && tmp->name[1]=='\0') ||
		    (tmp->name[0]=='.' && tmp->name[1]=='.' && tmp->name[2]=='\0'))
		{
		  tmp->status&=~FILE_STATUS_MARKED;
		}
		else
		{
		  if((tmp->status & FILE_STATUS_MARKED)!=status)
		    tmp->status^=FILE_STATUS_MARKED;
		}
	      }
	      status^=FILE_STATUS_MARKED;
	    }
	    break;
	  case 'p':
	  case 'P':
	  case '+':
	  case ' ':
	  case KEY_RIGHT:
	  case '\r':
	  case '\n':
	  case '6':
	  case KEY_ENTER:
#ifdef PADENTER
	  case PADENTER:
#endif
	    {
	      file_info_t *tmp=td_list_entry(pos, file_info_t, list);
	      if(pos!=&dir_list->list && (LINUX_S_ISDIR(tmp->st_mode)!=0))
	      {
		const unsigned long int new_inode=tmp->st_ino;
		if((new_inode!=inode) &&(strcmp(tmp->name,".")!=0))
		{
		  if(strcmp(tmp->name,"..")==0)
		    return 1;
		  if(strlen(dir_data->current_directory)+1+strlen(tmp->name)+1<=sizeof(dir_data->current_directory))
		  {
		    if(strcmp(dir_data->current_directory,"/"))
		      strcat(dir_data->current_directory,"/");
		    strcat(dir_data->current_directory,tmp->name);
		    return (long int)new_inode;
		  }
		}
	      }
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
	  case 'c':
	    if(dir_data->copy_file!=NULL)
	    {
	      const unsigned int current_directory_namelength=strlen(dir_data->current_directory);
	      file_info_t *tmp=td_list_entry(pos, file_info_t, list);
	      if(pos!=&dir_list->list &&
		  strcmp(tmp->name,"..")!=0 &&
		  current_directory_namelength+1+strlen(tmp->name)<sizeof(dir_data->current_directory)-1)
	      {
		if(strcmp(dir_data->current_directory,"/"))
		  strcat(dir_data->current_directory,"/");
		if(strcmp(tmp->name,".")!=0)
		  strcat(dir_data->current_directory,tmp->name);
		if(dir_data->local_dir==NULL || ask_destination>0)
		{
		  char dst_directory[4096];
		  dst_directory[0]='\0';
		  if(dir_data->local_dir!=NULL)
		  {
		    strncpy(dst_directory, dir_data->local_dir, sizeof(dst_directory)-1);
		    dst_directory[sizeof(dst_directory)-1]='\0';
		  }
		  if(LINUX_S_ISDIR(tmp->st_mode)!=0)
		    ask_location(dst_directory, sizeof(dst_directory), "Please select a destination where %s and any files below will be copied.",
			dir_data->current_directory);
		  else
		    ask_location(dst_directory, sizeof(dst_directory), "Please select a destination where %s will be copied.",
			dir_data->current_directory);
		  free(dir_data->local_dir);
		  dir_data->local_dir=NULL;
		  if(dst_directory[0]!='\0')
		    dir_data->local_dir=strdup(dst_directory);
		  ask_destination=0;
		}
		if(dir_data->local_dir!=NULL)
		{
		  unsigned int copy_bad=0;
		  unsigned int copy_ok=0;
		  copy_dir_t copy_stopped=CD_FINISHED;
		  aff_copy(window);
		  wmove(window,3,0);
		  aff_part(window, AFF_PART_ORDER|AFF_PART_STATUS, disk, partition);
		  wmove(window,4,0);
		  wprintw(window,"Directory %s\n",dir_data->current_directory);
		  if(LINUX_S_ISDIR(tmp->st_mode)!=0)
		  {
		    wmove(window,22,0);
		    wattrset(window, A_REVERSE);
		    waddstr(window,"  Stop  ");
		    wattroff(window, A_REVERSE);
		    copy_stopped=copy_dir(window, disk, partition, dir_data, tmp, &copy_ok, &copy_bad);
		  }
		  else if(LINUX_S_ISREG(tmp->st_mode)!=0)
		  {
		    copy_file_t res;
		    copy_progress(window, copy_ok, copy_bad);
		    res=dir_data->copy_file(disk, partition, dir_data, tmp);
		    if(res==CP_NOSPACE)
		      copy_stopped=CD_NOSPACE;
		    if(res==CP_OK)
		      copy_ok++;
		    else
		      copy_bad++;
		  }
		  wmove(window,22,0);
		  wclrtoeol(window);
		  copy_done(window, copy_ok, copy_bad, copy_stopped);
		}
		dir_data->current_directory[current_directory_namelength]='\0';
	      }
	    }
	    break;
	  case 'C':
	    if(dir_data->copy_file!=NULL)
	    {
	      if(dir_data->local_dir==NULL || ask_destination>0)
	      {
		char dst_directory[4096];
		dst_directory[0]='\0';
		if(dir_data->local_dir!=NULL)
		{
		  strncpy(dst_directory, dir_data->local_dir, sizeof(dst_directory)-1);
		  dst_directory[sizeof(dst_directory)-1]='\0';
		}
		ask_location(dst_directory, sizeof(dst_directory), "Please select a destination where the marked files will be copied.", NULL);
		free(dir_data->local_dir);
		dir_data->local_dir=NULL;
		if(dst_directory[0]!='\0')
		  dir_data->local_dir=strdup(dst_directory);
		ask_destination=0;
	      }
	      if(dir_data->local_dir!=NULL)
	      {
		unsigned int copy_bad=0;
		unsigned int copy_ok=0;
		copy_dir_t copy_stopped;
		aff_copy(window);
		wmove(window,3,0);
		aff_part(window, AFF_PART_ORDER|AFF_PART_STATUS, disk, partition);
		wmove(window,4,0);
		wprintw(window,"Directory %s\n",dir_data->current_directory);
		wmove(window,22,0);
		wattrset(window, A_REVERSE);
		waddstr(window,"  Stop  ");
		wattroff(window, A_REVERSE);
		copy_stopped=copy_selection(dir_list, window, disk, partition, dir_data, &copy_ok, &copy_bad);
		wmove(window,22,0);
		wclrtoeol(window);
		copy_done(window, copy_ok, copy_bad, copy_stopped);
	      }
	    }
	    break;
	  case '/':
	  case 'f':
	    needle=ask_string_ncurses("Filename to find ? ");
	    if(needle!=NULL && needle[0]!='\0' && pos->next!=&dir_list->list)
	    {
	      const file_info_t *tmp;
	      struct td_list_head *pos_org=pos;
	      const int pos_num_org=pos_num;
	      tmp=td_list_entry(pos, file_info_t, list);
	      while(pos->next!=&dir_list->list &&
		  strcasestr(tmp->name, needle)==NULL)
	      {
		pos=pos->next;
		tmp=td_list_entry(pos, file_info_t, list);
		pos_num++;
	      }
	      if(strcasestr(tmp->name, needle)==NULL)
	      {
		pos=pos_org;
		pos_num=pos_num_org;
	      }
	    }
	    break;
	  case 'n':
	    if(needle!=NULL && needle[0]!='\0' && pos->next!=&dir_list->list)
	    {
	      const file_info_t *tmp;
	      struct td_list_head *pos_org=pos;
	      const int pos_num_org=pos_num;
	      pos=pos->next;
	      tmp=td_list_entry(pos, file_info_t, list);
	      pos_num++;
	      while(pos->next!=&dir_list->list &&
		  strcasestr(tmp->name, needle)==0)
	      {
		pos=pos->next;
		tmp=td_list_entry(pos, file_info_t, list);
		pos_num++;
	      }
	      if(strcasestr(tmp->name, needle)==0)
	      {
		pos=pos_org;
		pos_num=pos_num_org;
	      }
	    }
	    break;
	  case 'N':
	    if(needle!=NULL && needle[0]!='\0' && pos->prev!=&dir_list->list)
	    {
	      const file_info_t *tmp;
	      struct td_list_head *pos_org=pos;
	      const int pos_num_org=pos_num;
	      pos=pos->prev;
	      tmp=td_list_entry(pos, file_info_t, list);
	      pos_num--;
	      while(pos->prev!=&dir_list->list &&
		  strcasestr(tmp->name, needle)==0)
	      {
		pos=pos->prev;
		tmp=td_list_entry(pos, file_info_t, list);
		pos_num--;
	      }
	      if(strcasestr(tmp->name, needle)==0)
	      {
		pos=pos_org;
		pos_num=pos_num_org;
	      }
	    }
	    break;
	  case 'F':
	    {
	      needle=ask_string_ncurses("Filter ? ");
	      if(needle!=NULL && needle[0]!='\0')
	      {
		struct td_list_head *tmpw= NULL;
		td_list_for_each(tmpw, &dir_list->list)
		{
		  file_info_t *tmp=td_list_entry(tmpw, file_info_t, list);
		  if(strcasestr(tmp->name, needle) != NULL)
		  {
		    tmp->status^=FILE_STATUS_MARKED;
		  }
		}
	      }
	      status^=FILE_STATUS_MARKED;
	    }
	    break;
	}
	if(pos_num<offset)
	  offset=pos_num;
	if(pos_num>=offset+INTER_DIR)
	  offset=pos_num-INTER_DIR+1;
      }
    } while(quit==0 && old_LINES==LINES);
  } while(quit==0);
  return -1;
}

static int is_inode_valid(const unsigned long int new_inode, const unsigned long int inode_known[MAX_DIR_NBR], const unsigned int dir_nbr)
{
  unsigned int i;
  if(new_inode<2)
    return 0;
  for(i=0; i<dir_nbr; i++)
    if(new_inode == inode_known[i]) /* Avoid loop */
      return 0;
  return 1;
}

static int can_copy_dir(const file_info_t *current_file, const unsigned long int inode_known[MAX_DIR_NBR], const unsigned int dir_nbr)
{
  if(strcmp(current_file->name,"..")==0 || strcmp(current_file->name,".")==0)
    return 0;
  return is_inode_valid(current_file->st_ino, inode_known, dir_nbr);
}

static int dir_partition_aux(disk_t *disk, const partition_t *partition, dir_data_t *dir_data, const unsigned long int inode, const unsigned int depth, char**current_cmd)
{
  static unsigned long int inode_known[MAX_DIR_NBR];
  if(depth==MAX_DIR_NBR)
    return 1;	/* subdirectories depth is too high => Back */
  if(dir_data->verbose>0)
  {
    log_info("\ndir_partition inode=%lu\n",inode);
    log_partition(disk, partition);
  }
  while(1)
  {
    const unsigned int current_directory_namelength=strlen(dir_data->current_directory);
    long int new_inode;
    file_info_t dir_list;
    TD_INIT_LIST_HEAD(&dir_list.list);
    /* Not perfect for FAT32 root cluster */
    inode_known[depth]=inode;
    dir_data->get_dir(disk, partition, dir_data, inode, &dir_list);
    dir_aff_log(dir_data, &dir_list);
    if(current_cmd!=NULL && *current_cmd!=NULL)
    {
      /* TODO: handle copy_files */
      dir_data->current_directory[current_directory_namelength]='\0';
      delete_list_file(&dir_list);
      return -1;	/* Quit */
    }
    new_inode=dir_aff_ncurses(disk, partition, dir_data, &dir_list, inode, depth);
    if(new_inode==-1 || new_inode==1) /* -1:Quit or 1:Back */
    {
      delete_list_file(&dir_list);
      return new_inode;
    }
    if(is_inode_valid(new_inode, &inode_known[0], depth) > 0)
    {
      dir_partition_aux(disk, partition, dir_data, (unsigned long int)new_inode, depth+1, current_cmd);
    }
    /* restore current_directory name */
    dir_data->current_directory[current_directory_namelength]='\0';
    delete_list_file(&dir_list);
  }
}

int dir_partition_aff(disk_t *disk, const partition_t *partition, dir_data_t *dir_data, const unsigned long int inode, char **current_cmd)
{
  if(dir_data==NULL)
    return -1;
  return dir_partition_aux(disk, partition, dir_data, inode, 0, current_cmd);
}

static copy_dir_t copy_dir(WINDOW *window, disk_t *disk, const partition_t *partition, dir_data_t *dir_data, const file_info_t *dir, unsigned int *copy_ok, unsigned int *copy_bad)
{
  static unsigned int dir_nbr=0;
  static unsigned long int inode_known[MAX_DIR_NBR];
  file_info_t dir_list;
  const unsigned int current_directory_namelength=strlen(dir_data->current_directory);
  char *dir_name;
  struct td_list_head *file_walker = NULL;
  TD_INIT_LIST_HEAD(&dir_list.list);
  if(dir_data->get_dir==NULL || dir_data->copy_file==NULL)
    return CD_FINISHED;
  inode_known[dir_nbr++]=dir->st_ino;
  dir_name=mkdir_local(dir_data->local_dir, dir_data->current_directory);
  dir_data->get_dir(disk, partition, dir_data, (const unsigned long int)dir->st_ino, &dir_list);
  td_list_for_each(file_walker, &dir_list.list)
  {
    const file_info_t *current_file;
    current_file=td_list_entry(file_walker, file_info_t, list);
    dir_data->current_directory[current_directory_namelength]='\0';
    if(current_directory_namelength+1+strlen(current_file->name)<sizeof(dir_data->current_directory)-1)
    {
      copy_dir_t copy_stopped=CD_FINISHED;
      if(strcmp(dir_data->current_directory,"/"))
	strcat(dir_data->current_directory,"/");
      strcat(dir_data->current_directory,current_file->name);
      if(LINUX_S_ISDIR(current_file->st_mode)!=0)
      {
	if(can_copy_dir(current_file, &inode_known[0], dir_nbr) > 0)
	{
	  copy_stopped=copy_dir(window, disk, partition, dir_data, current_file, copy_ok, copy_bad);
	}
      }
      else if(LINUX_S_ISREG(current_file->st_mode)!=0)
      {
	if(copy_progress(window, *copy_ok, *copy_bad))
	  copy_stopped=CD_STOPPED;
	else
	{
	  const copy_file_t res=dir_data->copy_file(disk, partition, dir_data, current_file);
	  if(res==CP_NOSPACE)
	    copy_stopped=CD_NOSPACE;
	  if(res==CP_OK)
	    (*copy_ok)++;
	  else
	    (*copy_bad)++;
	}
      }
      if(copy_stopped != CD_FINISHED)
      {
	dir_data->current_directory[current_directory_namelength]='\0';
	delete_list_file(&dir_list);
	set_date(dir_name, dir->td_atime, dir->td_mtime);
	free(dir_name);
	dir_nbr--;
	return copy_stopped;
      }
    }
  }
  dir_data->current_directory[current_directory_namelength]='\0';
  delete_list_file(&dir_list);
  set_date(dir_name, dir->td_atime, dir->td_mtime);
  free(dir_name);
  dir_nbr--;
  return CD_FINISHED;
}

static copy_dir_t copy_selection(file_info_t*dir_list, WINDOW *window, disk_t *disk, const partition_t *partition, dir_data_t *dir_data, unsigned int *copy_ok, unsigned int *copy_bad)
{
  const unsigned int current_directory_namelength=strlen(dir_data->current_directory);
  struct td_list_head *tmpw=NULL;
  td_list_for_each(tmpw, &dir_list->list)
  {
    copy_dir_t copy_stopped=CD_FINISHED;
    file_info_t *tmp=td_list_entry(tmpw, file_info_t, list);
    if((tmp->status&FILE_STATUS_MARKED)!=0 &&
	current_directory_namelength + 1 + strlen(tmp->name) <
	sizeof(dir_data->current_directory)-1)
    {
      tmp->status&=~FILE_STATUS_MARKED;
      if(strcmp(dir_data->current_directory,"/"))
	strcat(dir_data->current_directory,"/");
      if(strcmp(tmp->name,".")!=0)
	strcat(dir_data->current_directory,tmp->name);
      if(LINUX_S_ISDIR(tmp->st_mode)!=0)
      {
	copy_stopped=copy_dir(window, disk, partition, dir_data, tmp, copy_ok, copy_bad);
	if(copy_stopped!=CD_FINISHED)
	{
	  dir_data->current_directory[current_directory_namelength]='\0';
	  return copy_stopped;
	}
      }
      else if(LINUX_S_ISREG(tmp->st_mode)!=0)
      {
	copy_file_t res;
	copy_progress(window, *copy_ok, *copy_bad);
	res=dir_data->copy_file(disk, partition, dir_data, tmp);
	if(res==CP_NOSPACE)
	  copy_stopped=CD_NOSPACE;
	if(res == CP_OK)
	  (*copy_ok)++;
	else
	  (*copy_bad)++;
      }
    }
    dir_data->current_directory[current_directory_namelength]='\0';
    if(copy_stopped!=CD_FINISHED)
      return copy_stopped;
  }
  return CD_FINISHED;
}
#endif
