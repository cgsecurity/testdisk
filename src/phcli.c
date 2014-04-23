/*

    File: phcli.c

    Copyright (C) 1998-2008,2014 Christophe GRENIER <grenier@cgsecurity.org>

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
#include <ctype.h>      /* isdigit */
#include "types.h"
#include "common.h"
#include "filegen.h"
#include "log.h"
#include "photorec.h"
#include "ext2grp.h"
#include "geometry.h"
#include "poptions.h"
#include "phcli.h"

typedef enum { INIT_SPACE_WHOLE, INIT_SPACE_PREINIT, INIT_SPACE_EXT2_GROUP, INIT_SPACE_EXT2_INODE } init_mode_t;

static int spacerange_cmp(const struct td_list_head *a, const struct td_list_head *b)
{
  const alloc_data_t *space_a=td_list_entry_const(a, const alloc_data_t, list);
  const alloc_data_t *space_b=td_list_entry_const(b, const alloc_data_t, list);
  if(space_a->start < space_b->start)
    return -1;
  if(space_a->start > space_b->start)
    return 1;
  return space_a->end - space_b->end;
}

static int file_select_cli(file_enable_t *files_enable, char**current_cmd)
{
  int keep_asking;
  log_info("\nInterface File Select\n");
  do
  {
    file_enable_t *file_enable;
    keep_asking=0;
    while(*current_cmd[0]==',')
      (*current_cmd)++;
    if(strncmp(*current_cmd,"everything",10)==0)
    {
      int enable_status;
      keep_asking=1;
      (*current_cmd)+=10;
      while(*current_cmd[0]==',')
	(*current_cmd)++;
      if(strncmp(*current_cmd,"enable",6)==0)
      {
	(*current_cmd)+=6;
	enable_status=1;
      }
      else if(strncmp(*current_cmd,"disable",7)==0)
      {
	(*current_cmd)+=7;
	enable_status=0;
      }
      else
      {
	log_critical("Syntax error %s\n",*current_cmd);
	return -1;
      }
      for(file_enable=&files_enable[0];file_enable->file_hint!=NULL;file_enable++)
	file_enable->enable=enable_status;
    }
    else
    {
      unsigned int cmd_length=0;
      while((*current_cmd)[cmd_length]!='\0' && (*current_cmd)[cmd_length]!=',')
	cmd_length++;
      for(file_enable=&files_enable[0];file_enable->file_hint!=NULL;file_enable++)
      {
	if(file_enable->file_hint->extension!=NULL &&
	    strlen(file_enable->file_hint->extension)==cmd_length &&
	    memcmp(file_enable->file_hint->extension,*current_cmd,cmd_length)==0)
	{
	  keep_asking=1;
	  (*current_cmd)+=cmd_length;
	  while(*current_cmd[0]==',')
	    (*current_cmd)++;
	  if(strncmp(*current_cmd,"enable",6)==0)
	  {
	    (*current_cmd)+=6;
	    file_enable->enable=1;
	  }
	  else if(strncmp(*current_cmd,"disable",7)==0)
	  {
	    (*current_cmd)+=7;
	    file_enable->enable=0;
	  }
	  else
	  {
	    log_critical("Syntax error %s\n",*current_cmd);
	    return -1;
	  }
	}
      }
    }
  } while(keep_asking>0);
  return 0;
}

int menu_photorec_cli(list_part_t *list_part, struct ph_param *params, struct ph_options *options, alloc_data_t*list_search_space)
{
  unsigned int user_blocksize=0;
  init_mode_t mode_init_space=(td_list_empty(&list_search_space->list)?INIT_SPACE_WHOLE:INIT_SPACE_PREINIT);
  params->partition=(list_part->next!=NULL ? list_part->next->part : list_part->part);
  while(1)
  {
    while(params->cmd_run[0]==',')
      params->cmd_run++;
    if(params->cmd_run[0]=='\0')
      return 0;
    if(strncmp(params->cmd_run,"search",6)==0)
    {
      params->cmd_run+=6;
      if(mode_init_space==INIT_SPACE_EXT2_GROUP)
      {
	params->blocksize=ext2_fix_group(list_search_space, params->disk, params->partition);
	if(params->blocksize==0)
	{
	  log_error("Not a valid ext2/ext3/ext4 filesystem");
	  return -1;
	}
      }
      else if(mode_init_space==INIT_SPACE_EXT2_INODE)
      {
	params->blocksize=ext2_fix_inode(list_search_space, params->disk, params->partition);
	if(params->blocksize==0)
	{
	  log_error("Not a valid ext2/ext3/ext4 filesystem");
	  return -1;
	}
      }
      if(td_list_empty(&list_search_space->list))
      {
	init_search_space(list_search_space, params->disk, params->partition);
      }
      if(params->carve_free_space_only>0)
      {
	params->blocksize=remove_used_space(params->disk, params->partition, list_search_space);
      }
      if(user_blocksize > 0)
	params->blocksize=user_blocksize;
      return 1;
    }
    else if(strncmp(params->cmd_run,"options",7)==0)
    {
      params->cmd_run+=7;
      interface_options_photorec_cli(options, &params->cmd_run);
    }
    else if(strncmp(params->cmd_run,"fileopt",7)==0)
    {
      params->cmd_run+=7;
      if(file_select_cli(options->list_file_format, &params->cmd_run) < 0)
	return -1;
    }
    else if(strncmp(params->cmd_run,"blocksize,",10)==0)
    {
      params->cmd_run+=10;
      user_blocksize=atoi(params->cmd_run);
      while(params->cmd_run[0]!=',' && params->cmd_run[0]!='\0')
	params->cmd_run++;
    }
    else if(strncmp(params->cmd_run,"geometry,",9)==0)
    {
      params->cmd_run+=9;
      change_geometry_cli(params->disk, &params->cmd_run);
    }
    else if(strncmp(params->cmd_run,"inter",5)==0)
    {	/* Start interactive mode */
      params->cmd_run=NULL;
      return 0;
    }
    else if(strncmp(params->cmd_run,"wholespace",10)==0)
    {
      params->cmd_run+=10;
      params->carve_free_space_only=0;
    }
    else if(strncmp(params->cmd_run,"freespace",9)==0)
    {
      params->cmd_run+=9;
      params->carve_free_space_only=1;
    }
    else if(strncmp(params->cmd_run,"ext2_group,",11)==0)
    {
      unsigned int groupnr;
      params->cmd_run+=11;
      options->mode_ext2=1;
      groupnr=atoi(params->cmd_run);
      while(params->cmd_run[0]!=',' && params->cmd_run[0]!='\0')
	params->cmd_run++;
      if(mode_init_space==INIT_SPACE_WHOLE)
	mode_init_space=INIT_SPACE_EXT2_GROUP;
      if(mode_init_space==INIT_SPACE_EXT2_GROUP)
      {
	alloc_data_t *new_free_space;
	new_free_space=(alloc_data_t*)MALLOC(sizeof(*new_free_space));
	/* Temporary storage, values need to be multiplied by group size and aligned */
	new_free_space->start=groupnr;
	new_free_space->end=groupnr;
	new_free_space->file_stat=NULL;
	new_free_space->data=1;
	if(td_list_add_sorted_uniq(&new_free_space->list, &list_search_space->list, spacerange_cmp))
	  free(new_free_space);
      }
    }
    else if(strncmp(params->cmd_run,"ext2_inode,",11)==0)
    {
      unsigned int inodenr;
      params->cmd_run+=11;
      options->mode_ext2=1;
      inodenr=atoi(params->cmd_run);
      while(params->cmd_run[0]!=',' && params->cmd_run[0]!='\0')
	params->cmd_run++;
      if(mode_init_space==INIT_SPACE_WHOLE)
	mode_init_space=INIT_SPACE_EXT2_INODE;
      if(mode_init_space==INIT_SPACE_EXT2_INODE)
      {
	alloc_data_t *new_free_space;
	new_free_space=(alloc_data_t*)MALLOC(sizeof(*new_free_space));
	/* Temporary storage, values need to be multiplied by group size and aligned */
	new_free_space->start=inodenr;
	new_free_space->end=inodenr;
	new_free_space->file_stat=NULL;
	new_free_space->data=1;
	if(td_list_add_sorted_uniq(&new_free_space->list, &list_search_space->list, spacerange_cmp))
	  free(new_free_space);
      }
    }
    else if(isdigit(params->cmd_run[0]))
    {
      list_part_t *element;
      const unsigned int order= atoi(params->cmd_run);
      while(params->cmd_run[0]!=',' && params->cmd_run[0]!='\0')
	params->cmd_run++;
      for(element=list_part;element!=NULL && element->part->order!=order;element=element->next);
      if(element!=NULL)
	params->partition=element->part;
    }
    else
    {
      log_critical("Syntax error in command line: %s\n", params->cmd_run);
      return -1;
    }
  }
}
