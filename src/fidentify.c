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
#include "misc.h"
#include "file_jpg.h"

extern file_enable_t list_file_enable[];
extern file_check_list_t file_check_list;

#define READ_SIZE 1024*512

static int file_identify(const char *filename, const unsigned int check)
{
  FILE *file;
  unsigned char *buffer_start;
  unsigned char *buffer_olddata;
  unsigned char *buffer;
  const unsigned int blocksize=65536;
  const unsigned int read_size=65536;
  unsigned int buffer_size;
  file_recovery_t file_recovery;
  reset_file_recovery(&file_recovery);
  file_recovery.blocksize=blocksize;
  buffer_size=blocksize + READ_SIZE;
  buffer_start=(unsigned char *)MALLOC(buffer_size);
  buffer_olddata=buffer_start;
  buffer=buffer_olddata + blocksize;
  file=fopen(filename, "rb");
  if(file==NULL)
  {
    free(buffer_start);
    return -1;
  }
  if(fread(buffer, 1, READ_SIZE, file)<=0)
  {
    fclose(file);
    free(buffer_start);
    return 0;
  }
  {
    struct td_list_head *tmpl;
    file_recovery_t file_recovery_new;
    file_recovery_new.blocksize=blocksize;
    file_recovery_new.file_stat=NULL;
    td_list_for_each(tmpl, &file_check_list.list)
    {
      struct td_list_head *tmp;
      const file_check_list_t *pos=td_list_entry(tmpl, file_check_list_t, list);
      td_list_for_each(tmp, &pos->file_checks[buffer[pos->offset]].list)
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
      printf("%s: %s", filename,
	  ((file_recovery_new.extension!=NULL && file_recovery_new.extension[0]!='\0')?
	   file_recovery_new.extension:file_recovery_new.file_stat->file_hint->description));
      if(check > 0 && file_recovery_new.file_check!=NULL)
      {
	file_recovery_new.handle=file;
#ifdef HAVE_FSEEKO
	fseeko(file_recovery_new.handle, 0, SEEK_END);
#else
	fseek(file_recovery_new.handle, 0, SEEK_END);
#endif
#ifdef HAVE_FTELLO
	file_recovery_new.file_size=ftello(file_recovery_new.handle);
#else
	file_recovery_new.file_size=ftell(file_recovery_new.handle);
#endif
	file_recovery_new.calculated_file_size=file_recovery_new.file_size;
	(file_recovery_new.file_check)(&file_recovery_new);
	printf(" file_size=%llu", (long long unsigned)file_recovery_new.file_size);
      }
      printf("\n");
    }
    else
    {
      printf("%s: unknown\n", filename);
    }
    fclose(file);
  }
  free(buffer_start);
  return 0;
}

static void file_identify_dir(const char *current_dir, const unsigned int check)
{
  DIR *dir;
  struct dirent *entry;
  dir=opendir(current_dir);
  if(dir==NULL)
    return;
  while((entry=readdir(dir))!=NULL)
  {
    if(strcmp(entry->d_name,".")!=0 && strcmp(entry->d_name,"..")!=0)
    {
      struct stat buf_stat;
      char *current_file=(char *)MALLOC(strlen(current_dir)+1+strlen(entry->d_name)+1);
      strcpy(current_file, current_dir);
      strcat(current_file, "/");
      strcat(current_file, entry->d_name);
#ifdef HAVE_LSTAT
      if(lstat(current_file, &buf_stat)==0)
#else
	if(stat(current_file, &buf_stat)==0)
#endif
	{
	  if(S_ISDIR(buf_stat.st_mode))
	    file_identify_dir(current_file, check);
	  else if(S_ISREG(buf_stat.st_mode))
	    file_identify(current_file, check);
	}
      free(current_file);
    }
  }
  closedir(dir);
}

static void display_help(void)
{
  printf("\nUsage: fidentify [--check] [directory]\n"\
      "       fidentify --version\n" \
      "\n" \
      "fidentify determine the file type, the 'extension', by using the same database than PhotoRec.\n");
}

static void display_version(void)
{
  printf("fidentify %s, Data Recovery Utility, %s\nChristophe GRENIER <grenier@cgsecurity.org>\nhttp://www.cgsecurity.org\n",VERSION,TESTDISKDATE);
  printf("\n");
  printf("Version: %s\n", VERSION);
  printf("Compiler: %s\n", get_compiler());
  printf("Compilation date: %s\n", get_compilation_date());
  printf("libjpeg: %s\n", td_jpeg_version());
  printf("OS: %s\n" , get_os());
}

int main(int argc, char **argv)
{
  int i;
  unsigned int check=0;
  FILE *log_handle=NULL;
  int log_errno=0;
  int todo=1;
  file_stat_t *file_stats;
  log_set_levels(LOG_LEVEL_DEBUG|LOG_LEVEL_TRACE|LOG_LEVEL_QUIET|LOG_LEVEL_INFO|LOG_LEVEL_VERBOSE|LOG_LEVEL_PROGRESS|LOG_LEVEL_WARNING|LOG_LEVEL_ERROR|LOG_LEVEL_PERROR|LOG_LEVEL_CRITICAL);
  for(i=1; i<argc; i++)
  {
    if(strcmp(argv[i], "/check")==0 || strcmp(argv[i], "-check")==0 || strcmp(argv[i], "--check")==0)
    {
      check++;
    }
    else if(strcmp(argv[i],"/help")==0 || strcmp(argv[i],"-help")==0 || strcmp(argv[i],"--help")==0 ||
      strcmp(argv[i],"/h")==0 || strcmp(argv[i],"-h")==0 ||
      strcmp(argv[i],"/?")==0 || strcmp(argv[i],"-?")==0)
    {
      display_help();
      return 0;
    }
    else if((strcmp(argv[i],"/version")==0) || (strcmp(argv[i],"-version")==0) || (strcmp(argv[i],"--version")==0) ||
      (strcmp(argv[i],"/v")==0) || (strcmp(argv[i],"-v")==0))
    {
      display_version();
      return 0;
    }
  }
  log_handle=log_open("fidentify.log", TD_LOG_CREATE, &log_errno);
  if(log_handle!=NULL)
  {
    time_t my_time;
#ifdef HAVE_DUP2
    dup2(fileno(log_handle),2);
#endif
    my_time=time(NULL);
    log_info("\n\n%s",ctime(&my_time));
    log_info("Command line: fidentify");
    for(i=1;i<argc;i++)
      log_info(" %s", argv[i]);
    log_info("\n\n");
    log_flush();
  }
  log_info("fidentify %s, Data Recovery Utility, %s\nChristophe GRENIER <grenier@cgsecurity.org>\nhttp://www.cgsecurity.org\n", VERSION, TESTDISKDATE);
  {
    /* Enable all file formats */
    file_enable_t *file_enable;
    for(file_enable=list_file_enable;file_enable->file_hint!=NULL;file_enable++)
      file_enable->enable=1;
  }
  file_stats=init_file_stats(list_file_enable);
  for(i=1; i<argc; i++)
  {
    if(strcmp(argv[i], "/check")==0 || strcmp(argv[i], "-check")==0 || strcmp(argv[i], "--check")==0)
    {
    }
    else
    {
      struct stat buf_stat;
      todo=0;
#ifdef HAVE_LSTAT
      if(lstat(argv[i], &buf_stat)==0)
#else
	if(stat(argv[i], &buf_stat)==0)
#endif
	{
	  if(S_ISDIR(buf_stat.st_mode))
	    file_identify_dir(argv[i], check);
	  else if(S_ISREG(buf_stat.st_mode))
	    file_identify(argv[i], check);
	}
    }
  }
  if(todo)
    file_identify_dir(".", check);
  free_header_check();
  free(file_stats);
  log_close();
  return 0;
}
