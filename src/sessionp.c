/*

    File: sessionp.c

    Copyright (C) 2006-2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>	/* unlink */
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
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <errno.h>
#include "types.h"
#include "common.h"
#include "intrf.h"
#include "filegen.h"
#include "sessionp.h"
#include "log.h"

#define SESSION_MAXSIZE 40960
#define SESSION_FILENAME "photorec.ses"

int session_load(char **cmd_device, char **current_cmd, alloc_data_t *list_free_space)
{
  FILE *f_session;
  char *buffer;
  char *pos;
  int taille;
  struct stat stat_rec;
  unsigned int buffer_size;
  f_session=fopen(SESSION_FILENAME,"rb");
  if(!f_session)
  {
    log_info("Can't open photorec.ses file: %s\n",strerror(errno));
    session_save(NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, 0, 0, 0);
    return -1;
  }
  if(fstat(fileno(f_session), &stat_rec)<0)
    buffer_size=SESSION_MAXSIZE;
  else
    buffer_size=stat_rec.st_size;
  buffer=MALLOC(buffer_size+1);
  taille=fread(buffer,1,buffer_size,f_session);
  buffer[taille]='\0';
  fclose(f_session);
  pos=buffer;
  if(*pos!='#')
  {
    free(buffer);
    return -1;
  }
  {
    time_t my_time;
    char *info=NULL;
    pos++;
    /* load time */
    my_time=strtol(pos,&pos,10);
    if(pos==NULL)
    {
      free(buffer);
      return 0;
    }
    pos=strstr(pos,"\n");
    if(pos==NULL)
    {
      free(buffer);
      return 0;
    }
    pos++;
    /* get current disk */
    info=pos;
    pos=strstr(info," ");
    if(pos==NULL)
    {
      free(buffer);
      return 0;
    }
    *pos='\0';
    pos++;
    *cmd_device=strdup(info);
    /* search part_name_option */
    info=pos;
    pos=strstr(pos,"\n");
    if(pos==NULL)
    {
      free(buffer);
      return 0;
    }
    *pos='\0';
    pos++;
    *current_cmd=strdup(info);
    do
    {
      long unsigned start,end;
      if(sscanf(pos,"%lu-%lu\n",&start,&end)==2)
      {
        if(start<=end)
        {
          alloc_data_t *new_free_space;
          new_free_space=(alloc_data_t*)MALLOC(sizeof(*new_free_space));
          /* Temporary storage, values need to be multiply by sector_size */
          new_free_space->start=start;
          new_free_space->end=end;
          new_free_space->file_stat=NULL;
          td_list_add_tail(&new_free_space->list, &list_free_space->list);
#ifdef DEBUG
          log_trace(">%lu-%lu<\n",start,end);
#endif
        }
        pos=strstr(pos,"\n");
        if(pos!=NULL)
          pos++;
      }
      else
        pos=NULL;
    } while(pos!=NULL);
  }
  free(buffer);
  return 0;
}

int session_save(alloc_data_t *list_free_space, disk_t *disk_car, const partition_t *partition, const file_enable_t *files_enable, const unsigned int blocksize, const unsigned int paranoid, const unsigned int keep_corrupted_file, const unsigned int mode_ext2, const unsigned int expert, const unsigned int lowmem, const unsigned int carve_free_space_only, const int verbose)
{
  FILE *f_session;
  if(verbose>1)
  {
    log_trace("session_save\n");
  }
  f_session=fopen(SESSION_FILENAME,"wb");
  if(!f_session)
  {
    log_critical("Can't create photorec.ses file: %s\n",strerror(errno));
    return -1;
  }
  if(disk_car!=NULL)
  {
    struct td_list_head *free_walker = NULL;
    unsigned int i;
    fprintf(f_session,"#%u\n%s %s,%u,blocksize,%u,fileopt,",
	(unsigned int)time(NULL), disk_car->device, disk_car->arch->part_name_option, partition->order, blocksize);
    for(i=0;files_enable[i].file_hint!=NULL;i++)
    {
      if(files_enable[i].file_hint->extension!=NULL && files_enable[i].file_hint->extension[0]!='\0')
      {
	fprintf(f_session,"%s,%s,",files_enable[i].file_hint->extension,(files_enable[i].enable!=0?"enable":"disable"));
      }
    }
    /* Save options */
    fprintf(f_session, "options,");
    if(paranoid==0)
      fprintf(f_session, "paranoid_no,");
    else if(paranoid==1)
      fprintf(f_session, "paranoid,");
    else
      fprintf(f_session, "paranoid_bf,");
    /* TODO: allow_partial_last_cylinder ? */
    if(keep_corrupted_file>0)
      fprintf(f_session, "keep_corrupted_file,");
    else
      fprintf(f_session, "keep_corrupted_file_no,");
    if(mode_ext2>0)
      fprintf(f_session, "mode_ext2,");
    if(expert>0)
      fprintf(f_session, "expert,");
    if(lowmem>0)
      fprintf(f_session, "lowmem,");
    /* Save options - End */
    if(carve_free_space_only>0)
      fprintf(f_session,"freespace,");
    else
      fprintf(f_session,"wholespace,");
    fprintf(f_session,"search,inter\n");
    td_list_for_each(free_walker, &list_free_space->list)
    {
      alloc_data_t *current_free_space;
      current_free_space=td_list_entry(free_walker, alloc_data_t, list);
      fprintf(f_session,"%lu-%lu\n",(long unsigned)(current_free_space->start/disk_car->sector_size),
	  (long unsigned)(current_free_space->end/disk_car->sector_size));
    }
  }
  { /* Reserve some space */
    int res;
    char *buffer;
    buffer=MALLOC(SESSION_MAXSIZE);
    memset(buffer,0,SESSION_MAXSIZE);
    res=fwrite(buffer,1,SESSION_MAXSIZE,f_session);
    free(buffer);
    if(res<SESSION_MAXSIZE)
    {
      fclose(f_session);
      return -1;
    }
  }
  fclose(f_session);
  return 0;
}


