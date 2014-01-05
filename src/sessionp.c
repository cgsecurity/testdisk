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
#include "photorec.h"
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
//  time_t my_time;
  char *info=NULL;
  f_session=fopen(SESSION_FILENAME,"rb");
  if(!f_session)
  {
    log_info("Can't open photorec.ses file: %s\n",strerror(errno));
    session_save(NULL, NULL, NULL);
    return -1;
  }
  if(fstat(fileno(f_session), &stat_rec)<0)
    buffer_size=SESSION_MAXSIZE;
  else
    buffer_size=stat_rec.st_size;
  buffer=(char *)MALLOC(buffer_size+1);
  taille=fread(buffer,1,buffer_size,f_session);
  buffer[taille]='\0';
  fclose(f_session);
  pos=buffer;
  if(*pos!='#')
  {
    free(buffer);
    return -1;
  }
  pos++;
  /* load time */
  strtol(pos,&pos,10); 	// my_time=strtol(pos,&pos,10);
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
  while(1)
  {
    uint64_t start=0;
    uint64_t end=0;
    while(*pos>='0' && *pos<='9')
    {
      start=start*10 + (*pos - '0');
      pos++;
    }
    if(*pos++ != '-')
    {
      free(buffer);
      return 0;
    }
    while(*pos >= '0' && *pos <= '9')
    {
      end=end*10+(*pos -'0');
      pos++;
    }
    if(start <= end)
    {
      alloc_data_t *new_free_space;
      new_free_space=(alloc_data_t*)MALLOC(sizeof(*new_free_space));
      /* Temporary storage, values need to be multiplied by sector_size */
      new_free_space->start=start;
      new_free_space->end=end;
      new_free_space->file_stat=NULL;
      new_free_space->data=1;
      td_list_add_tail(&new_free_space->list, &list_free_space->list);
#ifdef DEBUG
      log_trace(">%lu-%lu<\n", start, end);
#endif
    }
    while(*pos=='\n' || *pos=='\r')
      pos++;
  }
}

int session_save(alloc_data_t *list_free_space, struct ph_param *params,  const struct ph_options *options)
{
  FILE *f_session;
  if(params!=NULL && params->status==STATUS_QUIT)
    return 0;
  f_session=fopen(SESSION_FILENAME,"wb");
  if(!f_session)
  {
    log_critical("Can't create photorec.ses file: %s\n",strerror(errno));
    return -1;
  }
  if(params!=NULL)
  {
    struct td_list_head *free_walker = NULL;
    unsigned int i;
    const file_enable_t *files_enable=options->list_file_format;
    unsigned int disable=0;
    unsigned int enable=0;
    unsigned int enable_by_default=0;
    if(options->verbose>1)
    {
      log_trace("session_save\n");
    }
    fprintf(f_session,"#%u\n%s %s,%u,",
	(unsigned int)time(NULL), params->disk->device, params->disk->arch->part_name_option, params->partition->order);
    if(params->blocksize>0)
      fprintf(f_session,"blocksize,%u,", params->blocksize);
    fprintf(f_session,"fileopt,");
    for(i=0;files_enable[i].file_hint!=NULL;i++)
    {
      if(files_enable[i].enable==0)
	disable++;
      else
	enable++;
      if(files_enable[i].enable==files_enable[i].file_hint->enable_by_default)
	enable_by_default++;
    }
    if(enable_by_default >= disable && enable_by_default >= enable)
    {
      for(i=0;files_enable[i].file_hint!=NULL;i++)
      {
	if(files_enable[i].enable!=files_enable[i].file_hint->enable_by_default &&
	      files_enable[i].file_hint->extension!=NULL &&
	      files_enable[i].file_hint->extension[0]!='\0')
	{
	  fprintf(f_session,"%s,%s,", files_enable[i].file_hint->extension,
	      (files_enable[i].enable!=0?"enable":"disable"));
	}
      }
    }
    else if(enable > disable)
    {
      fprintf(f_session,"everything,enable,");
      for(i=0;files_enable[i].file_hint!=NULL;i++)
      {
	if(files_enable[i].enable==0 &&
	      files_enable[i].file_hint->extension!=NULL &&
	      files_enable[i].file_hint->extension[0]!='\0')
	{
	  fprintf(f_session,"%s,disable,", files_enable[i].file_hint->extension);
	}
      }
    }
    else
    {
      fprintf(f_session,"everything,disable,");
      for(i=0;files_enable[i].file_hint!=NULL;i++)
      {
	if(files_enable[i].enable!=0 &&
	      files_enable[i].file_hint->extension!=NULL &&
	      files_enable[i].file_hint->extension[0]!='\0')
	{
	  fprintf(f_session,"%s,enable,", files_enable[i].file_hint->extension);
	}
      }
    }
    /* Save options */
    fprintf(f_session, "options,");
    if(options->paranoid==0)
      fprintf(f_session, "paranoid_no,");
    else if(options->paranoid==1)
      fprintf(f_session, "paranoid,");
    else
      fprintf(f_session, "paranoid_bf,");
    if(options->keep_corrupted_file>0)
      fprintf(f_session, "keep_corrupted_file,");
    else
      fprintf(f_session, "keep_corrupted_file_no,");
    if(options->mode_ext2>0)
      fprintf(f_session, "mode_ext2,");
    if(options->expert>0)
      fprintf(f_session, "expert,");
    if(options->lowmem>0)
      fprintf(f_session, "lowmem,");
    /* Save options - End */
    if(params->carve_free_space_only>0)
      fprintf(f_session,"freespace,");
    else
      fprintf(f_session,"wholespace,");
    fprintf(f_session,"search,");
    switch(params->status)
    {
      case STATUS_UNFORMAT:
        fprintf(f_session, "status=unformat,");
	break;
      case STATUS_FIND_OFFSET:
        fprintf(f_session, "status=find_offset,");
	break;
      case STATUS_EXT2_ON_BF:
	fprintf(f_session, "status=ext2_on_bf,");
	break;
      case STATUS_EXT2_ON_SAVE_EVERYTHING:
	fprintf(f_session, "status=ext2_on_save_everything,");
	break;
      case STATUS_EXT2_ON:
	fprintf(f_session, "status=ext2_on,");
	break;
      case STATUS_EXT2_OFF_SAVE_EVERYTHING:
	fprintf(f_session, "status=ext2_off_save_everything,");
	break;
      case STATUS_EXT2_OFF_BF:
	fprintf(f_session, "status=ext2_off_bf,");
	break;
      case STATUS_EXT2_OFF:
	fprintf(f_session, "status=ext2_off,");
	break;
      case STATUS_QUIT:
        break;
    }
    if(params->status!=STATUS_FIND_OFFSET && params->offset!=-1)
      fprintf(f_session, "%llu,",
	  (long long unsigned)(params->offset/params->disk->sector_size));
    fprintf(f_session,"inter\n");
    td_list_for_each(free_walker, &list_free_space->list)
    {
      alloc_data_t *current_free_space;
      current_free_space=td_list_entry(free_walker, alloc_data_t, list);
      fprintf(f_session,"%llu-%llu\n",
	  (long long unsigned)(current_free_space->start/params->disk->sector_size),
	  (long long unsigned)(current_free_space->end/params->disk->sector_size));
    }
  }
  { /* Reserve some space */
    int res;
    char *buffer;
    buffer=(char *)MALLOC(SESSION_MAXSIZE);
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
