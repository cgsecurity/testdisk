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

extern const char *monstr[];

static int dir_partition_aux(disk_t *disk, const partition_t *partition, dir_data_t *dir_data, const unsigned long int inode, const unsigned int depth, char **current_cmd);
static long int dir_aff_ncurses(disk_t *disk, const partition_t *partition, dir_data_t *dir_data, file_data_t*dir_list, const unsigned long int inode, const unsigned int depth);
static int copy_dir(disk_t *disk, const partition_t *partition, dir_data_t *dir_data, const file_data_t *dir);

#define INTER_DIR (LINES-25+15)

static long int dir_aff_ncurses(disk_t *disk, const partition_t *partition, dir_data_t *dir_data, file_data_t*dir_list, const unsigned long int inode, const unsigned int depth)
{
  /* Return value
   * -1: quit
   *  1: back
   *  other: new inode
   * */
  int quit=0;
  int ask_destination=1;
  WINDOW *window=(WINDOW*)dir_data->display;
  do
  {
    int offset=0;
    int pos_num=0;
    file_data_t *pos=dir_list;
    int old_LINES=LINES;
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
      const file_data_t *current_file;
      for(i=0,current_file=dir_list;(current_file!=NULL) && (i<offset);current_file=current_file->next,i++);
      for(i=offset;(current_file!=NULL) &&((i-offset)<INTER_DIR);i++,current_file=current_file->next)
      {
	char str[11];
	char		datestr[80];
	wmove(window, 6+i-offset, 0);
	wclrtoeol(window);	/* before addstr for BSD compatibility */
	if(current_file==pos)
	{
	  wattrset(window, A_REVERSE);
	  waddstr(window, ">");
	}
	else
	  waddstr(window, " ");
	if((current_file->status&FILE_STATUS_DELETED)!=0 && has_colors())
	  wbkgdset(window,' ' | COLOR_PAIR(1));
	else if((current_file->status&FILE_STATUS_MARKED)!=0 && has_colors())
	  wbkgdset(window,' ' | COLOR_PAIR(2));
	if(current_file->td_mtime!=0)
	{
	  struct tm		*tm_p;
	  tm_p = localtime(&current_file->td_mtime);
	  snprintf(datestr, sizeof(datestr),"%2d-%s-%4d %02d:%02d",
	      tm_p->tm_mday, monstr[tm_p->tm_mon],
	      1900 + tm_p->tm_year, tm_p->tm_hour,
	      tm_p->tm_min);
	  /* May have to use %d instead of %e */
	} else {
	  strncpy(datestr, "                 ",sizeof(datestr));
	}
	mode_string(current_file->st_mode, str);
	wprintw(window, "%s %5u %5u ", 
	    str, (unsigned int)current_file->st_uid, (unsigned int)current_file->st_gid);
	wprintw(window, "%9llu", (long long unsigned int)current_file->st_size);
	/* screen may overlap due to long filename */
	wprintw(window, " %s %s", datestr, current_file->name);
	if(((current_file->status&FILE_STATUS_DELETED)!=0 ||
	      (current_file->status&FILE_STATUS_MARKED)!=0) && has_colors())
	  wbkgdset(window,' ' | COLOR_PAIR(0));
	if(current_file==pos)
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
      if(current_file!=NULL)
	wprintw(window, "Next");
      if(dir_list==NULL)
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
	waddstr(window,"h");
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
	waddstr(window,"h");
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
      waddstr(window,"q");
      if(has_colors())
	wbkgdset(window,' ' | COLOR_PAIR(0));
      waddstr(window," to quit");
      if(dir_data->copy_file!=NULL)
      {
	waddstr(window,", ");
	if(has_colors())
	  wbkgdset(window,' ' | A_BOLD | COLOR_PAIR(0));
	waddstr(window,":");
	if(has_colors())
	  wbkgdset(window,' ' | COLOR_PAIR(0));
	waddstr(window," to select the current file, ");
	if(has_colors())
	  wbkgdset(window,' ' | A_BOLD | COLOR_PAIR(0));
	waddstr(window,"a");
	if(has_colors())
	  wbkgdset(window,' ' | COLOR_PAIR(0));
	if((status&FILE_STATUS_MARKED)==FILE_STATUS_MARKED)
	  waddstr(window," to select all files  ");
	else
	  waddstr(window," to deselect all files");
	if(has_colors())
	  wbkgdset(window,' ' | A_BOLD | COLOR_PAIR(0));
	mvwaddstr(window,LINES-1,4,"C");
	if(has_colors())
	  wbkgdset(window,' ' | COLOR_PAIR(0));
	waddstr(window," to copy the selected files, ");
	if(has_colors())
	  wbkgdset(window,' ' | A_BOLD | COLOR_PAIR(0));
	waddstr(window,"c");
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
      if(dir_list!=NULL)
      {
	switch(car)
	{
	  case KEY_UP:
	  case '8':
	    if(pos->prev!=NULL)
	    {
	      pos=pos->prev;
	      pos_num--;
	    }
	    break;
	  case KEY_DOWN:
	  case '2':
	    if(pos->next!=NULL)
	    {
	      pos=pos->next;
	      pos_num++;
	    }
	    break;
	  case ':':
	    if(!(pos->name[0]=='.' && pos->name[1]=='\0') &&
		!(pos->name[0]=='.' && pos->name[1]=='.' && pos->name[2]=='\0'))
	      pos->status^=FILE_STATUS_MARKED;
	    if(pos->next!=NULL)
	    {
	      pos=pos->next;
	      pos_num++;
	    }
	    break;
	  case 'a':
	    {
	      file_data_t *tmp;
	      for(tmp=dir_list; tmp!=NULL; tmp=tmp->next)
	      {
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
	    if((pos!=NULL) && (LINUX_S_ISDIR(pos->st_mode)!=0))
	    {
	      unsigned long int new_inode=pos->st_ino;
	      if((new_inode!=inode) &&(strcmp(pos->name,".")!=0))
	      {
		if(strcmp(pos->name,"..")==0)
		  return 1;
		if(strlen(dir_data->current_directory)+1+strlen(pos->name)+1<=sizeof(dir_data->current_directory))
		{
		  if(strcmp(dir_data->current_directory,"/"))
		    strcat(dir_data->current_directory,"/");
		  strcat(dir_data->current_directory,pos->name);
		  return (long int)new_inode;
		}
	      }
	    }
	    break;
	  case KEY_PPAGE:
	    for(i=0;(i<INTER_DIR-1)&&(pos->prev!=NULL);i++)
	    {
	      pos=pos->prev;
	      pos_num--;
	    }
	    break;
	  case KEY_NPAGE:
	    for(i=0;(i<INTER_DIR-1)&&(pos->next!=NULL);i++)
	    {
	      pos=pos->next;
	      pos_num++;
	    }
	    break;
	  case 'c':
	    if(dir_data->copy_file!=NULL)
	    {
	      const unsigned int current_directory_namelength=strlen(dir_data->current_directory);
	      if(strcmp(pos->name,"..")!=0 &&
		  current_directory_namelength+1+strlen(pos->name)<sizeof(dir_data->current_directory)-1)
	      {
		if(strcmp(dir_data->current_directory,"/"))
		  strcat(dir_data->current_directory,"/");
		if(strcmp(pos->name,".")!=0)
		  strcat(dir_data->current_directory,pos->name);
		if(dir_data->local_dir==NULL || ask_destination>0)
		{
		  char *local_dir=dir_data->local_dir;
		  if(LINUX_S_ISDIR(pos->st_mode)!=0)
		    dir_data->local_dir=ask_location("Please select a destination where %s and any files below will be copied.",
			dir_data->current_directory, local_dir);
		  else
		    dir_data->local_dir=ask_location("Please select a destination where %s will be copied.",
			dir_data->current_directory, local_dir);
		  free(local_dir);
		  ask_destination=0;
		}
		if(dir_data->local_dir!=NULL)
		{
		  int res=-1;
		  wmove(window,5,0);
		  wclrtoeol(window);
		  if(has_colors())
		    wbkgdset(window,' ' | A_BOLD | COLOR_PAIR(1));
		  wprintw(window,"Copying, please wait...");
		  if(has_colors())
		    wbkgdset(window,' ' | COLOR_PAIR(0));
		  wrefresh(window);
		  if(LINUX_S_ISDIR(pos->st_mode)!=0)
		  {
		    res=copy_dir(disk, partition, dir_data, pos);
		  }
		  else if(LINUX_S_ISREG(pos->st_mode)!=0)
		  {
		    res=dir_data->copy_file(disk, partition, dir_data, pos);
		  }
		  wmove(window,5,0);
		  wclrtoeol(window);
		  if(res < -1)
		  {
		    if(has_colors())
		      wbkgdset(window,' ' | A_BOLD | COLOR_PAIR(1));
		    wprintw(window,"Copy failed!");
		  }
		  else
		  {
		    if(has_colors())
		      wbkgdset(window,' ' | A_BOLD | COLOR_PAIR(2));
		    if(res < 0)
		      wprintw(window,"Copy done! (Failed to copy some files)");
		    else
		      wprintw(window,"Copy done!");
		  }
		  if(has_colors())
		    wbkgdset(window,' ' | COLOR_PAIR(0));
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
		char *local_dir=dir_data->local_dir;
		dir_data->local_dir=ask_location("Please select a destination where the marked files will be copied.", NULL, local_dir);
		free(local_dir);
		ask_destination=0;
	      }
	      if(dir_data->local_dir!=NULL)
	      {
		file_data_t *tmp;
		int copy_bad=0;
		int copy_ok=0;
		const unsigned int current_directory_namelength=strlen(dir_data->current_directory);
		wmove(window,5,0);
		wclrtoeol(window);
		if(has_colors())
		  wbkgdset(window,' ' | A_BOLD | COLOR_PAIR(1));
		wprintw(window,"Copying, please wait...");
		if(has_colors())
		  wbkgdset(window,' ' | COLOR_PAIR(0));
		wrefresh(window);
		for(tmp=dir_list; tmp!=NULL; tmp=tmp->next)
		{
		  if((tmp->status&FILE_STATUS_MARKED)!=0 &&
		      current_directory_namelength + 1 + strlen(tmp->name) <
		      sizeof(dir_data->current_directory)-1)
		  {
		    if(strcmp(dir_data->current_directory,"/"))
		      strcat(dir_data->current_directory,"/");
		    if(strcmp(tmp->name,".")!=0)
		      strcat(dir_data->current_directory,tmp->name);
		    if(LINUX_S_ISDIR(tmp->st_mode)!=0)
		    {
		      const int res=copy_dir(disk, partition, dir_data, tmp);
		      if(res >=-1)
		      {
			tmp->status&=~FILE_STATUS_MARKED;
			copy_ok=1;
		      }
		      else if(res < 0)
			copy_bad=1;
		    }
		    else if(LINUX_S_ISREG(tmp->st_mode)!=0)
		    {
		      if(dir_data->copy_file(disk, partition, dir_data, tmp) == 0)
		      {
			tmp->status&=~FILE_STATUS_MARKED;
			copy_ok=1;
		      }
		      else
			copy_bad=1;
		    }
		  }
		  dir_data->current_directory[current_directory_namelength]='\0';
		}
		wmove(window,5,0);
		wclrtoeol(window);
		if(copy_bad > 0 && copy_ok==0)
		{
		  if(has_colors())
		    wbkgdset(window,' ' | A_BOLD | COLOR_PAIR(1));
		  wprintw(window,"Copy failed!");
		}
		else
		{
		  if(has_colors())
		    wbkgdset(window,' ' | A_BOLD | COLOR_PAIR(2));
		  if(copy_bad > 0)
		    wprintw(window,"Copy done! (Failed to copy some files)");
		  else if(copy_ok == 0)
		    wprintw(window,"No file selected");
		  else
		    wprintw(window,"Copy done!");
		}
		if(has_colors())
		  wbkgdset(window,' ' | COLOR_PAIR(0));
	      }
	    }
	    break;	
	  case 'f':
	    {
	      const char *needle=ask_string_ncurses("Filename to find ? ");
	      if(needle!=NULL && needle[0]!='\0')
	      {
		file_data_t *pos_org=pos;
		const int pos_num_org=pos_num;
		while(strcmp(pos->name, needle)!=0 && pos->next!=NULL)
		{
		  pos=pos->next;
		  pos_num++;
		}
		if(strcmp(pos->name, needle)!=0)
		{
		  pos=pos_org;
		  pos_num=pos_num_org;
		}
	      }
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

static int dir_partition_aux(disk_t *disk, const partition_t *partition, dir_data_t *dir_data, const unsigned long int inode, const unsigned int depth, char**current_cmd)
{
#define MAX_DIR_NBR 256
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
    long int new_inode=-1;	/* Quit */
    file_data_t *dir_list;
    /* Not perfect for FAT32 root cluster */
    inode_known[depth]=inode;
    dir_list=dir_data->get_dir(disk, partition, dir_data, inode);
    dir_aff_log(dir_data, dir_list);
    if(*current_cmd!=NULL)
    {
      /* TODO: handle copy_files */
      dir_data->current_directory[current_directory_namelength]='\0';
      delete_list_file(dir_list);
      return -1;	/* Quit */
    }
    new_inode=dir_aff_ncurses(disk, partition, dir_data,dir_list,inode,depth);
    if(new_inode==-1 || new_inode==1) /* -1:Quit or 1:Back */
    {
      delete_list_file(dir_list);
      return new_inode;
    }
    if(new_inode>=2)
    {
      unsigned int new_inode_ok=1;
      unsigned int i;
      for(i=0;i<=depth && new_inode_ok!=0;i++)
	if((unsigned)new_inode==inode_known[i]) /* Avoid loop */
	  new_inode_ok=0;
      if(new_inode_ok>0)
      {
	dir_partition_aux(disk, partition, dir_data, (unsigned long int)new_inode, depth+1, current_cmd);
      }
    }
    /* restore current_directory name */
    dir_data->current_directory[current_directory_namelength]='\0';
    delete_list_file(dir_list);
  }
}

int dir_partition_aff(disk_t *disk, const partition_t *partition, dir_data_t *dir_data, const unsigned long int inode, char **current_cmd)
{
  if(dir_data==NULL)
    return -1;
  return dir_partition_aux(disk, partition, dir_data, inode, 0, current_cmd);
}

/*
Returns
-2: no file copied
-1: failed to copy some files
0: all files has been copied
*/
#define MAX_DIR_NBR 256
static int copy_dir(disk_t *disk, const partition_t *partition, dir_data_t *dir_data, const file_data_t *dir)
{
  static unsigned int dir_nbr=0;
  static unsigned long int inode_known[MAX_DIR_NBR];
  file_data_t *dir_list;
  const unsigned int current_directory_namelength=strlen(dir_data->current_directory);
  file_data_t *current_file;
  char *dir_name;
  int copy_bad=0;
  int copy_ok=0;
  if(dir_data->get_dir==NULL || dir_data->copy_file==NULL)
    return -2;
  inode_known[dir_nbr++]=dir->st_ino;
  dir_name=mkdir_local(dir_data->local_dir, dir_data->current_directory);
  dir_list=dir_data->get_dir(disk, partition, dir_data, (const unsigned long int)dir->st_ino);
  for(current_file=dir_list;current_file!=NULL;current_file=current_file->next)
  {
    dir_data->current_directory[current_directory_namelength]='\0';
    if(current_directory_namelength+1+strlen(current_file->name)<sizeof(dir_data->current_directory)-1)
    {
      if(strcmp(dir_data->current_directory,"/"))
	strcat(dir_data->current_directory,"/");
      strcat(dir_data->current_directory,current_file->name);
      if(LINUX_S_ISDIR(current_file->st_mode)!=0)
      {
	const unsigned long int new_inode=current_file->st_ino;
	unsigned int new_inode_ok=1;
	unsigned int i;
	if(new_inode<2)
	  new_inode_ok=0;
	if(strcmp(current_file->name,"..")==0 || strcmp(current_file->name,".")==0)
	  new_inode_ok=0;
	for(i=0;i<dir_nbr && new_inode_ok!=0;i++)
	  if(new_inode==inode_known[i]) /* Avoid loop */
	    new_inode_ok=0;
	if(new_inode_ok>0)
	{
	  int tmp;
	  tmp=copy_dir(disk, partition, dir_data, current_file);
	  if(tmp>=-1)
	    copy_ok=1;
	  if(tmp<0)
	    copy_bad=1;
	}
      }
      else if(LINUX_S_ISREG(current_file->st_mode)!=0)
      {
//	log_trace("copy_file %s\n",dir_data->current_directory);
	int tmp;
	tmp=dir_data->copy_file(disk, partition, dir_data, current_file);
	if(tmp==0)
	  copy_ok=1;
	else
	  copy_bad=1;
      }
    }
  }
  dir_data->current_directory[current_directory_namelength]='\0';
  delete_list_file(dir_list);
  set_date(dir_name, dir->td_atime, dir->td_mtime);
  free(dir_name);
  dir_nbr--;
  return (copy_bad>0?(copy_ok>0?-1:-2):0);
}

#endif
