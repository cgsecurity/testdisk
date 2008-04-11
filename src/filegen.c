/*

    File: filegen.c

    Copyright (C) 2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "common.h"
#include "filegen.h"

file_check_t *file_check_list=NULL;

void register_header_check(const unsigned int offset, const unsigned char *value, const unsigned int length, 
  int (*header_check)(const unsigned char *buffer, const unsigned int buffer_size,
      const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new),
  file_stat_t *file_stat)
{
  /* No need to use the more advanced list.h, this structure should be updated to a tree */
  file_check_t *file_check_new=(file_check_t *)MALLOC(sizeof(*file_check_new));
  file_check_new->value=value;
  file_check_new->length=length;
  file_check_new->offset=offset;
  file_check_new->header_check=header_check;
  file_check_new->file_stat=file_stat;
  if(length==0)
  {
    file_check_t *last;
    /* tail */
    for(last=file_check_list;last!=NULL && last->next!=NULL;last=last->next);
    if(last==NULL)
      file_check_list=file_check_new;
    else
      last->next=file_check_new;
    file_check_new->next=NULL;
  }
  else
  { /* head */
    file_check_new->next=file_check_list;
    file_check_list=file_check_new;
  }
}

void free_header_check(void)
{
  file_check_t *current=file_check_list;
  while(current!=NULL)
  {
    file_check_t *next=current->next;
    free(current);
    current=next;
  }
  file_check_list=NULL;
}

void file_allow_nl(file_recovery_t *file_recovery, const unsigned int nl_mode)
{
  unsigned char buffer[4096];
  int taille;
  if(fseek(file_recovery->handle, file_recovery->file_size,SEEK_SET)<0)
    return;
  taille=fread(buffer,1, 4096,file_recovery->handle);
  if(taille > 0 && buffer[0]=='\n' && (nl_mode&NL_BARENL)==NL_BARENL)
    file_recovery->file_size++;
  else if(taille > 1 && buffer[0]=='\r' && buffer[1]=='\n' && (nl_mode&NL_CRLF)==NL_CRLF)
    file_recovery->file_size+=2;
  else if(taille > 0 && buffer[0]=='\r' && (nl_mode&NL_BARECR)==NL_BARECR)
    file_recovery->file_size++;
}

