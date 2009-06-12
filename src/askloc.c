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
 
#ifdef HAVE_NCURSES
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
#include "types.h"
#include "common.h"
#include "intrf.h"
#include "intrfn.h"
#include "list.h"
#include "dir.h"
#include "askloc.h"

extern const char *monstr[];

#define INTER_DIR (LINES-25+16)

#define SPATH_SEP "/"
#define PATH_SEP '/'
#if defined(__CYGWIN__)
/* /cygdrive/c/ => */
#define PATH_DRIVE_LENGTH 9
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
    new_drive->name[0]=i;
    new_drive->name[1]=':';
    new_drive->name[2]=PATH_SEP;
    new_drive->name[3]='\0';
    new_drive->stat.st_mode=LINUX_S_IFDIR|LINUX_S_IRWXUGO;
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
  /* /cygdrive */
  if(last_sep>PATH_DRIVE_LENGTH)
    dst_directory[last_sep]='\0';
  else
    dst_directory[PATH_DRIVE_LENGTH]='\0';
#elif defined(DJGPP) || defined(__OS2__)
  if(last_sep > 2 )
    dst_directory[last_sep]='\0';	/* subdirectory */
  else if(last_sep == 2 && dst_directory[3]!='\0')
    dst_directory[3]='\0';	/* root directory */
  else
    dst_directory[0]='\0';	/* drive list */
#else
  if(last_sep>1)
    dst_directory[last_sep]='\0';
  else
    dst_directory[1]='\0';
#endif
}

char *ask_location(const char*msg, const char *src_dir, const char *dst_org)
{
  char dst_directory[4096];
  char *res=NULL;
  int quit;
  WINDOW *window=newwin(0,0,0,0);	/* full screen */
  aff_copy(window);
  if(dst_org != NULL)
    strncpy(dst_directory, dst_org, sizeof(dst_directory));
  else
    td_getcwd(dst_directory, sizeof(dst_directory));
  do
  {
    DIR* dir;
    static file_info_t dir_list = {
      .list = TD_LIST_HEAD_INIT(dir_list.list),
      .name = {0}
    };
    wmove(window,7,0);
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
    if(dir!=NULL)
    {
      struct dirent *dir_entrie;
      file_info_t *file_info;
      file_info=(file_info_t*)MALLOC(sizeof(*file_info));
      do
      {
        char current_file[4096];
        dir_entrie=readdir(dir);
	/* if dir_entrie exists
	 *   there is enough room to store the filename
	 *   dir_entrie->d_name is ".", ".." or something that doesn't begin by a "."
	 * */
        if(dir_entrie!=NULL
            && strlen(dst_directory)+1+strlen(file_info->name)+1<=sizeof(current_file) &&
            (dir_entrie->d_name[0]!='.' ||
             dir_entrie->d_name[1]=='\0' ||
             (dir_entrie->d_name[1]=='.' && dir_entrie->d_name[2]=='\0'))
#ifdef __CYGWIN__
            && (strlen(dst_directory)>PATH_DRIVE_LENGTH || dir_entrie->d_name[0]!='.')
#endif
          )
        {
          strcpy(current_file,dst_directory);
#if defined(DJGPP) || defined(__OS2__)
          if(current_file[0]!='\0'&&current_file[1]!='\0'&&current_file[2]!='\0'&&current_file[3]!='\0')
#else
            if(current_file[1]!='\0')
#endif
              strcat(current_file,SPATH_SEP);
          strcat(current_file,dir_entrie->d_name);
#ifdef HAVE_LSTAT
          if(lstat(current_file,&file_info->stat)==0)
#else
            if(stat(current_file,&file_info->stat)==0)
#endif
	    {
#if defined(DJGPP) || defined(__OS2__)
	      /* If the C library doesn't use posix definition, st_mode need to be fixed */
	      if(S_ISDIR(file_info->stat.st_mode))
		file_info->stat.st_mode=LINUX_S_IFDIR|LINUX_S_IRWXUGO;
	      else
		file_info->stat.st_mode=LINUX_S_IFREG|LINUX_S_IRWXUGO;
#endif
#ifdef __CYGWIN__
	      /* Fix Drive list */
	      if(strlen(dst_directory)<=PATH_DRIVE_LENGTH)
	      {
		file_info->stat.st_mode=LINUX_S_IFDIR|LINUX_S_IRWXUGO;
		file_info->stat.st_mtime=0;
		file_info->stat.st_uid=0;
		file_info->stat.st_gid=0;
	      }
#endif
	      strncpy(file_info->name,dir_entrie->d_name,sizeof(file_info->name));
	      td_list_add_sorted(&file_info->list, &dir_list.list, filesort);
	      file_info=(file_info_t*)MALLOC(sizeof(*file_info));
	    }
        }
      } while(dir_entrie!=NULL);
      free(file_info);
      closedir(dir);
    }
    if(dir_list.list.next!=&dir_list.list)
    {
      struct td_list_head *current_file=dir_list.list.next;
      int offset=0;
      int pos_num=0;
      int old_LINES=LINES;
      do
      {
	int dst_directory_ok=0;
	if(old_LINES!=LINES)
	{ /* Screen size has changed, reset to initial values */
	  current_file=dir_list.list.next;
	  offset=0;
	  pos_num=0;
	  old_LINES=LINES;
	}
        aff_copy(window);
        wmove(window,7,0);
#ifdef __CYGWIN__
        if(strlen(dst_directory)<=PATH_DRIVE_LENGTH)
          wprintw(window,"To select a drive, use the arrow keys.");
        else
          wprintw(window,"To select another directory, use the arrow keys.");
#elif defined(DJGPP) || defined(__OS2__)
        if(dst_directory[0]=='\0')
          wprintw(window,"To select a drive, use the arrow keys.");
        else
          wprintw(window,"To select another directory, use the arrow keys.");
#else
        wprintw(window,"To select another directory, use the arrow keys.");
#endif
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
              wmove(window,8-1+i-offset,0);
              wclrtoeol(window);	/* before addstr for BSD compatibility */
              if(file_walker==current_file)
                wattrset(window, A_REVERSE);
              dir_aff_entry(window,file_info);
              if(file_walker==current_file)
                wattroff(window, A_REVERSE);
            }
            if(offset+INTER_DIR<=i)
              break;
          }
	  wmove(window, 8+INTER_DIR, 4);
	  wclrtoeol(window);
	  if(file_walker!=&dir_list.list && file_walker->next!=&dir_list.list)
	    wprintw(window, "Next");
        }
	if(strcmp(dst_directory,".")==0)
	{
	  aff_txt(4, window, msg, src_dir, "the program is running from");
	  dst_directory_ok=1;
	}
	else
	{
#ifdef __CYGWIN__
	  if(strlen(dst_directory)>PATH_DRIVE_LENGTH)
	  {
	    char beautifull_dst_directory[4096];
	    cygwin_conv_to_win32_path(dst_directory, beautifull_dst_directory);
	    aff_txt(4, window, msg, src_dir, beautifull_dst_directory);
	    dst_directory_ok=1;
	  }
#elif defined(DJGPP) || defined(__OS2__)
	  if(strlen(dst_directory)>0)
	  {
	    aff_txt(4, window, msg, src_dir, dst_directory);
	    dst_directory_ok=1;
	  }
#else
	  aff_txt(4, window, msg, src_dir, dst_directory);
	  dst_directory_ok=1;
#endif
	}
        wclrtoeol(window);	/* before addstr for BSD compatibility */
        wrefresh(window);
        do
        {
          quit=ASK_LOCATION_WAITKEY;
          switch(wgetch(window))
          {
            case 'y':
            case 'Y':
              if(dst_directory_ok>0)
              {
                res=strdup(dst_directory);
                quit=ASK_LOCATION_QUIT;
              }
              break;
            case 'n':
            case 'N':
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
                for(i=0; i<INTER_DIR-1 && current_file->prev!=&dir_list.list; i++)
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
                for(i=0; i<INTER_DIR-1 && current_file->next!=&dir_list.list; i++)
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
		  (LINUX_S_ISDIR(file_info->stat.st_mode) || LINUX_S_ISLNK(file_info->stat.st_mode)))
		if(current_file!=&dir_list.list)
		{
		  if(strcmp(file_info->name,".")==0)
		  {
		  }
		  else if(strcmp(file_info->name,"..")==0)
		  {
		    set_parent_directory(dst_directory);
		    quit=ASK_LOCATION_NEWDIR;
		  }
		  else if(strlen(dst_directory)+1+strlen(file_info->name)+1<=sizeof(dst_directory))
		  {
#if defined(DJGPP) || defined(__OS2__)
		    if(dst_directory[0]!='\0'&&dst_directory[1]!='\0'&&dst_directory[2]!='\0'&&dst_directory[3]!='\0')
#else
		      if(dst_directory[1]!='\0')
#endif
			strcat(dst_directory,SPATH_SEP);
		    strcat(dst_directory,file_info->name);
		    quit=ASK_LOCATION_NEWDIR;
		  }
		}
	      }
              break;

          }
	  if(pos_num<offset)
	    offset=pos_num;
	  if(pos_num>=offset+INTER_DIR)
	    offset=pos_num-INTER_DIR+1;
        } while(quit==ASK_LOCATION_WAITKEY && old_LINES==LINES);
      } while(quit==ASK_LOCATION_UPDATE || old_LINES!=LINES);
      delete_list_file_info(&dir_list.list);
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
  struct tm		*tm_p;
  char str[11];
  char		datestr[80];
  if(file_info->stat.st_mtime!=0)
  {
    tm_p = localtime(&file_info->stat.st_mtime);
    snprintf(datestr, sizeof(datestr),"%2d-%s-%4d %02d:%02d",
        tm_p->tm_mday, monstr[tm_p->tm_mon],
        1900 + tm_p->tm_year, tm_p->tm_hour,
        tm_p->tm_min);
    /* May have to use %d instead of %e */
  } else {
    strncpy(datestr, "                 ",sizeof(datestr));
  }
  mode_string(file_info->stat.st_mode,str);
  wprintw(window, "%s %5u %5u   ", 
      str, (unsigned int)file_info->stat.st_uid, (unsigned int)file_info->stat.st_gid);
  wprintw(window, "%7llu", (long long unsigned int)file_info->stat.st_size);
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
