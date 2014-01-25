/*

    File: askloc.c

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
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_CYGWIN_H
#include <sys/cygwin.h>
#endif
#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif
#include <stdarg.h>
#include "types.h"
#include "common.h"
#include "intrf.h"
#include "intrfn.h"
#include "list.h"
#include "list_sort.h"
#include "dir.h"
#include "askloc.h"
#include "log.h"

static char *td_getcwd(char *buf, unsigned long size)
{
  /* buf must non-NULL*/
#ifdef HAVE_GETCWD
  if(getcwd(buf, size)!=NULL)
    return buf;
#endif
  buf[0]='.';
  buf[1]='\0';
  return buf;
}

char *get_default_location(void)
{
  char dst_directory[4096];
  td_getcwd(dst_directory, sizeof(dst_directory));
  return strdup(dst_directory);
}

#ifdef HAVE_NCURSES
extern const char *monstr[];

#ifdef __MINGW32__
#define SPATH_SEP "\\"
#define PATH_SEP '\\'
#else
#define SPATH_SEP "/"
#define PATH_SEP '/'
#endif
#if defined(__CYGWIN__)
/* /cygdrive/c/ */
#define CYGDRIVE_LEN 9
#endif

#define ASK_LOCATION_WAITKEY 	0
#define ASK_LOCATION_UPDATE	1
#define ASK_LOCATION_NEWDIR	2
#define ASK_LOCATION_QUIT	3

static void set_parent_directory(char *dst_directory);
static void dir_aff_entry(WINDOW *window, file_info_t *file_info);
static int aff_txt(int line, WINDOW *window, const char *_format, ...) __attribute__ ((format (printf, 3, 4)));

#if defined(DJGPP) || defined(__OS2__)
void get_dos_drive_list(struct td_list_head *list);

void get_dos_drive_list(struct td_list_head *list)
{
  int i;
  for(i='a';i<='z';i++)
  {
    file_info_t *new_drive;
    new_drive=(file_info_t*)MALLOC(sizeof(*new_drive));
    new_drive->name=(char*)MALLOC(4);
    sprintf(new_drive->name, "%c:/", i);
    new_drive->st_mode=LINUX_S_IFDIR|LINUX_S_IRWXUGO;
    td_list_add_tail(&new_drive->list, list);
  }
}
#endif
static void set_parent_directory(char *dst_directory)
{
  int i;
  int last_sep=-1;
  for(i=0;dst_directory[i]!='\0';i++)
    if(dst_directory[i]==PATH_SEP)
      last_sep=i;
#ifdef __CYGWIN__
  if(memcmp(dst_directory, "/cygdrive", 9)==0)
  {
    if(last_sep > CYGDRIVE_LEN)
      dst_directory[last_sep]='\0';
    else
      dst_directory[CYGDRIVE_LEN]='\0';
  }
  else if(last_sep>0)
      dst_directory[last_sep]='\0';
  else if(last_sep==0 && dst_directory[1]=='\0')
    strcpy(dst_directory, "/cygdrive");
  else
  {
    dst_directory[0]=PATH_SEP;
    dst_directory[1]='\0';
  }
#elif defined(DJGPP) || defined(__OS2__)
  if(last_sep > 2 )
    dst_directory[last_sep]='\0';	/* subdirectory */
  else if(last_sep == 2 && dst_directory[3]!='\0')
    dst_directory[3]='\0';	/* root directory */
  else
    dst_directory[0]='\0';	/* drive list */
#else
  if(last_sep>0)
    dst_directory[last_sep]='\0';
  else
  {
    dst_directory[0]=PATH_SEP;
    dst_directory[1]='\0';
  }
#endif
}

char *ask_location(const char*msg, const char *src_dir, const char *dst_org)
{
  char dst_directory[4096];
  char *res=NULL;
  int quit;
  WINDOW *window=newwin(LINES, COLS, 0, 0);	/* full screen */
  aff_copy_short(window);
  if(dst_org != NULL)
  {
    strncpy(dst_directory, dst_org, sizeof(dst_directory));
    dst_directory[sizeof(dst_directory)-1]='\0';
  }
  else
    td_getcwd(dst_directory, sizeof(dst_directory));
  do
  {
    DIR* dir;
    file_info_t dir_list = {
      .list = TD_LIST_HEAD_INIT(dir_list.list),
      .name = NULL
    };
    wmove(window,5,0);
    wclrtoeol(window);	/* before addstr for BSD compatibility */
    if(has_colors())
      wbkgdset(window,' ' | A_BOLD | COLOR_PAIR(0));
    waddstr(window,"Directory listing in progress...");
    if(has_colors())
      wbkgdset(window,' ' | COLOR_PAIR(0));
    wrefresh(window);
#if defined(DJGPP) || defined(__OS2__)
    if(dst_directory[0]=='\0')
    {
      get_dos_drive_list(&dir_list.list);
      dir=NULL;
    }
    else
      dir=opendir(dst_directory);
#else
    dir=opendir(dst_directory);
#endif
    if(dir==NULL)
    {
      log_info("opendir(%s) failed\n", dst_directory);
      strncpy(dst_directory, SPATH_SEP, sizeof(dst_directory));
      dir=opendir(dst_directory);
    }
    if(dir==NULL)
    {
      td_getcwd(dst_directory, sizeof(dst_directory));
      dir=opendir(dst_directory);
    }
    if(dir==NULL)
    {
      delwin(window);
      (void) clearok(stdscr, TRUE);
#ifdef HAVE_TOUCHWIN
      touchwin(stdscr);
#endif
      return NULL;
    }
    {
      file_info_t *file_info;
      file_info=(file_info_t*)MALLOC(sizeof(*file_info));
      while(1)
      {
        char current_file[4096];
	const struct dirent *dir_entrie=readdir(dir);
        if(dir_entrie==NULL)
	  break;
	/* hide filename beginning by '.' except '.' and '..' */
	if(dir_entrie->d_name[0]=='.' &&
	    !dir_entrie->d_name[1]=='\0' &&
	    !(dir_entrie->d_name[1]=='.' && dir_entrie->d_name[2]=='\0'))
	  continue;
        if(strlen(dst_directory) + 1 + strlen(dir_entrie->d_name) + 1 <= sizeof(current_file)
#ifdef __CYGWIN__
	    && (memcmp(dst_directory, "/cygdrive", 9)!=0 ||
	      (dst_directory[9]!='\0' && dst_directory[10]!='\0') ||
	      dir_entrie->d_name[0]!='.')
#endif
          )
        {
	  struct stat file_stat;
          strcpy(current_file,dst_directory);
#if defined(DJGPP) || defined(__OS2__)
          if(current_file[0]!='\0'&&current_file[1]!='\0'&&current_file[2]!='\0'&&current_file[3]!='\0')
#else
            if(current_file[1]!='\0')
#endif
              strcat(current_file,SPATH_SEP);
          strcat(current_file,dir_entrie->d_name);
#ifdef HAVE_LSTAT
          if(lstat(current_file,&file_stat)==0)
#else
            if(stat(current_file,&file_stat)==0)
#endif
	    {
	      file_info->st_ino=file_stat.st_ino;
	      file_info->st_mode=file_stat.st_mode;
	      file_info->st_uid=file_stat.st_uid;
	      file_info->st_gid=file_stat.st_gid;
	      file_info->st_size=file_stat.st_size;
	      file_info->td_atime=file_stat.st_atime;
	      file_info->td_mtime=file_stat.st_mtime;
	      file_info->td_ctime=file_stat.st_ctime;
#if defined(DJGPP) || defined(__OS2__)
	      /* If the C library doesn't use posix definition, st_mode need to be fixed */
	      if(S_ISDIR(file_info->st_mode))
		file_info->st_mode=LINUX_S_IFDIR|LINUX_S_IRWXUGO;
	      else
		file_info->st_mode=LINUX_S_IFREG|LINUX_S_IRWXUGO;
#endif
#ifdef __CYGWIN__
	      /* Fix Drive list */
	      if(memcmp(dst_directory, "/cygdrive", 9)==0 && (dst_directory[10]=='\0' || dst_directory[11]=='\0'))
	      {
		file_info->st_mode=LINUX_S_IFDIR|LINUX_S_IRWXUGO;
		file_info->td_mtime=0;
		file_info->st_uid=0;
		file_info->st_gid=0;
	      }
#endif
	      file_info->name=strdup(dir_entrie->d_name);
	      td_list_add_tail(&file_info->list, &dir_list.list);
	      file_info=(file_info_t*)MALLOC(sizeof(*file_info));
	    }
        }
      }
      free(file_info);
      closedir(dir);
      td_list_sort(&dir_list.list, filesort);
    }
    if(dir_list.list.next!=&dir_list.list)
    {
      struct td_list_head *current_file=dir_list.list.next;
      int offset=0;
      int pos_num=0;
      int old_LINES=0;
      int old_COLS=1;
      do
      {
	int dst_directory_ok=0;
	int line_directory;
	int line_base;
	if(old_LINES!=LINES)
	{ /* Screen size has changed, reset to initial values */
	  current_file=dir_list.list.next;
	  offset=0;
	  pos_num=0;
	  old_LINES=LINES;
	  old_COLS=COLS;
	}
        aff_copy_short(window);
	line_directory=aff_txt(2, window, msg, src_dir);
        wmove(window, line_directory, 0);
        wprintw(window,"Keys: ");
	if(has_colors())
	  wbkgdset(window,' ' | A_BOLD | COLOR_PAIR(0));
	waddstr(window, "Arrow");
	if(has_colors())
	  wbkgdset(window,' ' | COLOR_PAIR(0));
	wprintw(window," keys to select another directory");
        wmove(window, ++line_directory, 6);
	if(has_colors())
	  wbkgdset(window,' ' | A_BOLD | COLOR_PAIR(0));
	waddstr(window, "C");
	if(has_colors())
	  wbkgdset(window,' ' | COLOR_PAIR(0));
	wprintw(window, " when the destination is correct");
        wmove(window, ++line_directory, 6);
	if(has_colors())
	  wbkgdset(window,' ' | A_BOLD | COLOR_PAIR(0));
	waddstr(window, "Q");
	if(has_colors())
	  wbkgdset(window,' ' | COLOR_PAIR(0));
	waddstr(window," to quit");
	line_directory++;
	line_base=line_directory+1;
	line_base+=(strlen("Directory ")+strlen(dst_directory))/old_COLS;
	{
          struct td_list_head *file_walker = NULL;
          int i=0;
          td_list_for_each(file_walker,&dir_list.list)
          {
	    if(i++<offset)
	      continue;
            {
              file_info_t *file_info;
              file_info=td_list_entry(file_walker, file_info_t, list);
              wmove(window, line_base - 1 + i - offset, 0);
              wclrtoeol(window);	/* before addstr for BSD compatibility */
              if(file_walker==current_file)
	      {
                wattrset(window, A_REVERSE);
		waddstr(window, ">");
		dir_aff_entry(window,file_info);
                wattroff(window, A_REVERSE);
	      }
	      else
	      {
		wprintw(window, " ");
		dir_aff_entry(window,file_info);
	      }
            }
            if(old_LINES-2 <= line_base - 1+i-offset)
              break;
          }
	  wmove(window,  old_LINES-1, 4);
	  wclrtoeol(window);
	  if(file_walker!=&dir_list.list && file_walker->next!=&dir_list.list)
	    wprintw(window, "Next");
        }
	wmove(window, line_directory, 0);
	wclrtoeol(window);	/* before addstr for BSD compatibility */
	if(strcmp(dst_directory,".")==0)
	{
	  wprintw(window, "Current directory");
	  dst_directory_ok=1;
	}
	else
	{
#ifdef __CYGWIN__
	  if(memcmp(dst_directory, "/cygdrive", 9)!=0 ||
	      (dst_directory[9]!='\0' && dst_directory[10]!='\0'))
	  {
	    char beautifull_dst_directory[4096];
	    if(cygwin_conv_path (CCP_POSIX_TO_WIN_A | CCP_ABSOLUTE, dst_directory, beautifull_dst_directory, sizeof(beautifull_dst_directory))==0)
	      wprintw(window, "Directory %s", beautifull_dst_directory);
	    else
	      wprintw(window, "Directory %s", dst_directory);
	    dst_directory_ok=1;
	  }
#elif defined(DJGPP) || defined(__OS2__)
	  if(strlen(dst_directory)>0)
	  {
	    wprintw(window, "Directory %s", dst_directory);
	    dst_directory_ok=1;
	  }
#else
	  wprintw(window, "Directory %s", dst_directory);
	  dst_directory_ok=1;
#endif
	}
        wrefresh(window);
        do
        {
	  const int command=wgetch(window);
          quit=ASK_LOCATION_WAITKEY;
#if defined(KEY_MOUSE) && defined(ENABLE_MOUSE)
	  if(command==KEY_MOUSE)
	  {
	    MEVENT event;
	    if(getmouse(&event) == OK)
	    {	/* When the user clicks left mouse button */
	      if((event.bstate & BUTTON1_CLICKED) || (event.bstate & BUTTON1_DOUBLE_CLICKED))
	      {
		if(event.y => line_base - 1 && event.y < old_LINES)
		{
		  const int pos_num_old=pos_num;
		  /* Disk selection */
		  while(pos_num > event.y - (line_base - offset) && current_file->prev!=&dir_list.list)
		  {
		    current_file=current_file->prev;
		    pos_num--;
		  }
		  while(pos_num < event.y - (line_base - offset) && current_file->next!=&dir_list.list)
		  {
		    current_file=current_file->next;
		    pos_num++;
		  }
		  quit=ASK_LOCATION_UPDATE;
		  if(((event.bstate & BUTTON1_CLICKED) && pos_num==pos_num_old) ||
		      (event.bstate & BUTTON1_DOUBLE_CLICKED))
		    command=KEY_ENTER;
		}
#if 0
		else if(file_walker!=&dir_list.list && file_walker->next!=&dir_list.list)
		{
		}
#endif
	      }
	    }
	  }
#endif
          switch(command)
          {
            case 'y':
            case 'Y':
            case 'c':
            case 'C':
              if(dst_directory_ok>0)
              {
                res=strdup(dst_directory);
                quit=ASK_LOCATION_QUIT;
              }
              break;
            case 'n':
            case 'N':
	    case 'q':
	    case 'Q':
              res=NULL;
              quit=ASK_LOCATION_QUIT;
              break;
            case KEY_UP:
	    case '8':
              if(current_file->prev!=&dir_list.list)
              {
                current_file=current_file->prev;
                pos_num--;
                quit=ASK_LOCATION_UPDATE;
              }
              break;
            case KEY_DOWN:
	    case '2':
              if(current_file->next!=&dir_list.list)
              {
                current_file=current_file->next;
                pos_num++;
                quit=ASK_LOCATION_UPDATE;
              }
              break;
            case KEY_PPAGE:
              {
                int i;
                for(i=0; i<old_LINES-line_base - 1-3 && current_file->prev!=&dir_list.list; i++)
                {
                  current_file=current_file->prev;
                  pos_num--;
                  quit=ASK_LOCATION_UPDATE;
                }
              }
              break;
            case KEY_NPAGE:
              {
                int i;
                for(i=0; i<old_LINES-line_base - 1-3 && current_file->next!=&dir_list.list; i++)
                {
                  current_file=current_file->next;
                  pos_num++;
                  quit=ASK_LOCATION_UPDATE;
                }
              }
              break;
	    case KEY_LEFT:
	    case '4':
	      set_parent_directory(dst_directory);
	      quit=ASK_LOCATION_NEWDIR;
	      break;
            case KEY_RIGHT:
            case '\r':
            case '\n':
	    case '6':
            case KEY_ENTER:
#ifdef PADENTER
            case PADENTER:
#endif
	      {
		file_info_t *file_info;
		file_info=td_list_entry(current_file, file_info_t, list);
		if(current_file!=&dir_list.list &&
		  (LINUX_S_ISDIR(file_info->st_mode) || LINUX_S_ISLNK(file_info->st_mode)))
		if(current_file!=&dir_list.list)
		{
		  if(strcmp(file_info->name, ".")==0)
		  {
		  }
		  else if(strcmp(file_info->name, "..")==0)
		  {
		    set_parent_directory(dst_directory);
		    quit=ASK_LOCATION_NEWDIR;
		  }
		  else if(strlen(dst_directory) + 1 + strlen(file_info->name) + 1 <= sizeof(dst_directory))
		  {
#if defined(DJGPP) || defined(__OS2__)
		    if(dst_directory[0]!='\0'&&dst_directory[1]!='\0'&&dst_directory[2]!='\0'&&dst_directory[3]!='\0')
#else
		      if(dst_directory[1]!='\0')
#endif
			strcat(dst_directory,SPATH_SEP);
		    strcat(dst_directory, file_info->name);
		    quit=ASK_LOCATION_NEWDIR;
		  }
		}
	      }
              break;

          }
	  if(pos_num<offset)
	    offset=pos_num;
	  if(offset+old_LINES <= pos_num+line_base+1)
	    offset=pos_num + line_base + 2 - old_LINES;
        } while(quit==ASK_LOCATION_WAITKEY && old_LINES==LINES);
      } while(quit==ASK_LOCATION_UPDATE || old_LINES!=LINES);
      delete_list_file(&dir_list);
    }
    else
    {
      set_parent_directory(dst_directory);
      quit=ASK_LOCATION_NEWDIR;
    }
  } while(quit==ASK_LOCATION_NEWDIR);
  delwin(window);
  (void) clearok(stdscr, TRUE);
#ifdef HAVE_TOUCHWIN
  touchwin(stdscr);
#endif
  return res;
}

static void dir_aff_entry(WINDOW *window, file_info_t *file_info)
{
  char str[11];
  char datestr[80];
  {
    const struct tm *tm_p;
    if(file_info->td_mtime!=0 && (tm_p= localtime(&file_info->td_mtime))!=NULL)
    {
      snprintf(datestr, sizeof(datestr),"%2d-%s-%4d %02d:%02d",
	  tm_p->tm_mday, monstr[tm_p->tm_mon],
	  1900 + tm_p->tm_year, tm_p->tm_hour,
	  tm_p->tm_min);
    } else {
      strncpy(datestr, "                 ",sizeof(datestr));
    }
  }
  mode_string(file_info->st_mode, str);
  wprintw(window, "%s %5u %5u ", 
      str, (unsigned int)file_info->st_uid, (unsigned int)file_info->st_gid);
  wprintw(window, "%9llu", (long long unsigned int)file_info->st_size);
  /* screen may overlap due to long filename */
  wprintw(window, " %s %s", datestr, file_info->name);
}

static int aff_txt(int line, WINDOW *window, const char *_format, ...)
{
  va_list ap;
  va_start(ap,_format);
  line=vaff_txt(line, window, _format, ap);
  va_end(ap);
  return line;
}
#endif

