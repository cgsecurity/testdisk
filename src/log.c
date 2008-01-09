/*

    File: log.c

    Copyright (C) 1998-2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include <stdarg.h>
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include "types.h"
#include "common.h"
#include "log.h"
#include "intrf.h"	/* ask_log_location */
#include "fnctdsk.h"

static FILE *log_handle=NULL;
static int f_status=0;
static int log_handler(const char *_format, va_list ap);
/* static unsigned int log_levels=LOG_LEVEL_DEBUG|LOG_LEVEL_TRACE|LOG_LEVEL_QUIET|LOG_LEVEL_INFO|LOG_LEVEL_VERBOSE|LOG_LEVEL_PROGRESS|LOG_LEVEL_WARNING|LOG_LEVEL_ERROR|LOG_LEVEL_PERROR|LOG_LEVEL_CRITICAL; */
static unsigned int log_levels=LOG_LEVEL_TRACE|LOG_LEVEL_QUIET|LOG_LEVEL_INFO|LOG_LEVEL_VERBOSE|LOG_LEVEL_PROGRESS|LOG_LEVEL_WARNING|LOG_LEVEL_ERROR|LOG_LEVEL_PERROR|LOG_LEVEL_CRITICAL;

int log_set_levels(const unsigned int levels)
{
  const int old_levels=log_levels;
  log_levels=levels;
  return old_levels;
}

int log_open(const char*default_filename, const int mode, const int interface, const char *prog_name, int argc, char**argv)
{
  const char*filename=default_filename;
  if(mode!=TD_LOG_CREATE && mode!=TD_LOG_APPEND)
    return mode;
  do
  {
    log_handle=fopen(filename,(mode==TD_LOG_CREATE?"w":"a"));
    if(log_handle==NULL)
    {
      if(interface==0)
      {
	printf("Can't create %s file\n", default_filename);
	return mode;
      }
      filename=ask_log_location(filename);
      if(filename==NULL)
	return TD_LOG_REFUSED;
    }
  } while(log_handle==NULL);
  {
    int i;
    time_t my_time;
#ifdef HAVE_DUP2
    dup2(fileno(log_handle),2);
#endif
    my_time=time(NULL);
    fprintf(log_handle,"\n\n%s",ctime(&my_time));
    fprintf(log_handle,"Command line: %s", prog_name);
    for(i=1;i<argc;i++)
      fprintf(log_handle," %s", argv[i]);
    fprintf(log_handle,"\n\n");
    fflush(log_handle);
  }
  return TD_LOG_DONE;
}

int log_flush(void)
{
  return fflush(log_handle);
}

static int log_handler(const char *_format, va_list ap)
{
  int res;
  res=vfprintf(log_handle,_format,ap);
  if(res<0)
  {
    f_status=1;
  }
  /* flushing the outputs slow down the program, don't flush. Hope it's not a bad idea */
  /*
     fflush(stderr);
     if(fflush(log_handle))
     {
     f_status=1;
     }
   */
  return res;
}

int log_close(void)
{
  if(log_handle!=NULL)
  {
    if(fclose(log_handle))
      f_status=1;
  }
  return f_status;
}

int log_redirect(unsigned int level, const char *format, ...)
{
  if((log_levels & level)==0)
    return 0;
  if(log_handle==NULL)
    return 0;
  {
    int res;
    va_list ap;
    va_start(ap, format);
    res=log_handler(format, ap);
    va_end(ap);
    return res;
  }
}

void dump_log(const void *nom_dump,unsigned int lng)
{
  unsigned int i,j;
  unsigned int nbr_line;
  unsigned char car;
  nbr_line=(lng+0x10-1)/0x10;
  /* write dump to log file*/
  for (i=0; (i<nbr_line); i++)
  {
    log_info("%04X ",i*0x10);
    for(j=0; j< 0x10;j++)
    {
      if(i*0x10+j<lng)
      {
        car=*((const unsigned char *)nom_dump+i*0x10+j);
        log_info("%02x", car);
      }
      else
        log_info("  ");
      if(j%4==(4-1))
        log_info(" ");
    }
    log_info("  ");
    for(j=0; j< 0x10;j++)
    {
      if(i*0x10+j<lng)
      {
        car=*((const unsigned char*)nom_dump+i*0x10+j);
        if ((car<32)||(car >= 127))
          log_info(".");
        else
          log_info("%c",  car);
      }
      else
        log_info("  ");
    }
    log_info("\n");
  }
}

void dump2_log(const void *dump_1, const void *dump_2, const unsigned int lng)
{
  unsigned int i,j;
  unsigned int nbr_line;
  nbr_line=(lng+0x08-1)/0x08;
  /* write dump to log file*/
  for (i=0; (i<nbr_line); i++)
  {
    log_info("%04X ",i*0x08);
    for(j=0; j<0x08;j++)
    {
      if(i*0x08+j<lng)
      {
        unsigned char car=*((const unsigned char *)dump_1+i*0x08+j);
        log_info("%02x", car);
      }
      else
        log_info("  ");
      if(j%4==(4-1))
        log_info(" ");
    }
    log_info("  ");
    for(j=0; j<0x08;j++)
    {
      if(i*0x08+j<lng)
      {
        unsigned char car=*((const unsigned char*)dump_1+i*0x08+j);
        if ((car<32)||(car >= 127))
          log_info(".");
        else
          log_info("%c",  car);
      }
      else
        log_info(" ");
    }
    log_info("  ");
    for(j=0; j<0x08;j++)
    {
      if(i*0x08+j<lng)
      {
        unsigned char car=*((const unsigned char *)dump_2+i*0x08+j);
        log_info("%02x", car);
      }
      else
        log_info("  ");
      if(j%4==(4-1))
        log_info(" ");
    }
    log_info("  ");
    for(j=0; j<0x08;j++)
    {
      if(i*0x08+j<lng)
      {
        unsigned char car=*((const unsigned char*)dump_2+i*0x08+j);
        if ((car<32)||(car >= 127))
          log_info(".");
        else
          log_info("%c",  car);
      }
      else
        log_info(" ");
    }
    log_info("\n");
  }
}

void log_partition(const disk_t *disk_car,const partition_t *partition)
{
  const char *msg;
  char buffer_part_size[100];
  msg=aff_part_aux(AFF_PART_ORDER|AFF_PART_STATUS, disk_car, partition);
  log_info("%s",msg);
  if(partition->info[0]!='\0')
    log_info("\n     %s, %s",partition->info,size_to_unit(partition->part_size,buffer_part_size));
  log_info("\n");
}

