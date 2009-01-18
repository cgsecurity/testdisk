/*

    File: fidentify.c

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
#include <dirent.h>
#include "types.h"
#include "common.h"
#include "filegen.h"
#include "log.h"
#include "phcfg.h"

extern file_enable_t list_file_enable[];
extern file_check_list_t file_check_list;

#define READ_SIZE 1024*512

static int file_identify(const char *filename)
{
  FILE *file;
  unsigned char *buffer_start;
  unsigned char *buffer_olddata;
  unsigned char *buffer;
  unsigned int blocksize=65536;
  unsigned int buffer_size;
  const unsigned int read_size=(blocksize>65536?blocksize:65536);
  file_recovery_t file_recovery;
  buffer_size=blocksize + READ_SIZE;
  buffer_start=(unsigned char *)MALLOC(buffer_size);
  buffer_olddata=buffer_start;
  buffer=buffer_olddata + blocksize;
  reset_file_recovery(&file_recovery);
  file=fopen(filename, "rb");
  if(file==NULL)
    return -1;
  if(fread(buffer, 1, READ_SIZE, file)<=0)
  {
    fclose(file);
    free(buffer_start);
    return 0;
  }
  fclose(file);
  {
    file_recovery_t file_recovery_new;
    struct td_list_head *tmpl;
    file_recovery_new.file_stat=NULL;
    td_list_for_each(tmpl, &file_check_list.list)
    {
      struct td_list_head *tmp;
      const file_check_list_t *pos=td_list_entry(tmpl, file_check_list_t, list);
      td_list_for_each(tmp, &pos->file_checks[pos->has_value==0?0:buffer[pos->offset]].list)
      {
	const file_check_t *file_check=td_list_entry(tmp, file_check_t, list);
	if((file_check->length==0 || memcmp(buffer + file_check->offset, file_check->value, file_check->length)==0) &&
	    file_check->header_check(buffer, read_size, 0, &file_recovery, &file_recovery_new)!=0)
	{
	  file_recovery_new.file_stat=file_check->file_stat;
	  break;
	}
      }
      if(file_recovery_new.file_stat!=NULL)
	break;
    }
    if(file_recovery_new.file_stat!=NULL && file_recovery_new.file_stat->file_hint!=NULL)
    {
      printf("%s: %s\n", filename,
	  ((file_recovery_new.extension!=NULL && file_recovery_new.extension[0]!='\0')?
	   file_recovery_new.extension:file_recovery_new.file_stat->file_hint->description));
    }
    else
    {
      printf("%s: unknown\n", filename);
    }
  }
  free(buffer_start);
  return 0;
}

static void file_identify_dir(const char *current_dir)
{
  DIR *dir;
  struct dirent *entry;
  dir=opendir(current_dir);
  if(dir==NULL)
    return;
  while((entry=readdir(dir))!=NULL)
  {
    char current_file[4096];
    strcpy(current_file, current_dir);
    strcat(current_file, "/");
    strcat(current_file, entry->d_name);
    if(strcmp(entry->d_name,".")!=0 && strcmp(entry->d_name,"..")!=0)
    {
      struct stat buf_stat;
#ifdef HAVE_LSTAT
      if(lstat(current_file, &buf_stat)==0)
#else
	if(stat(current_file, &buf_stat)==0)
#endif
	{
	  if(S_ISDIR(buf_stat.st_mode))
	    file_identify_dir(current_file);
	  else if(S_ISREG(buf_stat.st_mode))
	    file_identify(current_file);
	}
    }
  }
  closedir(dir);
}

int main(int argc, char **argv)
{
  FILE *log_handle=NULL;
  file_stat_t *file_stats;
  log_handle=log_open("fidentify.log", TD_LOG_CREATE);
  reset_list_file_enable(list_file_enable);
  file_stats=init_file_stats(list_file_enable);
  if(argc>1)
  {
    int i;
    for(i=1; i<argc; i++)
    {
      struct stat buf_stat;
#ifdef HAVE_LSTAT
      if(lstat(argv[i], &buf_stat)==0)
#else
	if(stat(argv[i], &buf_stat)==0)
#endif
	{
	  if(S_ISDIR(buf_stat.st_mode))
	    file_identify_dir(argv[i]);
	  else if(S_ISREG(buf_stat.st_mode))
	    file_identify(argv[i]);
	}
    }
  }
  else
    file_identify_dir(".");
  free_header_check();
  free(file_stats);
  log_close();
  return 0;
}
