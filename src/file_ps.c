/*

    File: file_ps.c

    Copyright (C) 2005,2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ps)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "filegen.h"
#include "common.h"


/*@ requires \valid(file_stat); */
static void register_header_check_ps(file_stat_t *file_stat);
static data_check_t data_check_ps(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery);

const file_hint_t file_hint_ps= {
  .extension="ps",
  .description="PostScript or Encapsulated PostScript document",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_ps
};

static const unsigned char ps_header[11]= { '%','!','P','S','-','A','d','o','b','e','-'};

/*@
  @ requires \valid(file_recovery);
  @ requires \valid(file_recovery->handle);
  @ requires valid_file_recovery(file_recovery);
  @ requires \separated(file_recovery, file_recovery->handle, file_recovery->extension, &errno, &Frama_C_entropy_source);
  @ ensures \valid(file_recovery->handle);
  @ ensures valid_file_recovery(file_recovery);
  @ assigns *file_recovery->handle, errno, file_recovery->file_size;
  @ assigns Frama_C_entropy_source;
  @*/
static void file_check_ps(file_recovery_t *file_recovery)
{
  const unsigned char ps_footer[5]="%%EOF";
  file_search_footer(file_recovery, ps_footer, sizeof(ps_footer), 1);
}

/*@
  @ requires buffer_size > 8;
  @ requires (buffer_size&1)==0;
  @ requires \valid_read(buffer+(0..buffer_size-1));
  @ requires \valid(file_recovery);
  @ requires file_recovery->data_check==&data_check_ps;
  @ requires file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE;
  @ requires \separated(buffer, file_recovery);
  @ ensures \result == DC_CONTINUE || \result == DC_STOP;
  @ assigns file_recovery->calculated_file_size;
  @*/
static data_check_t data_check_ps(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  unsigned int i;
  /*@
    @ loop assigns i, file_recovery->calculated_file_size;
    @*/
  for(i=(buffer_size/2)-4;i+4<buffer_size;i++)
  {
    if(buffer[i]=='%' && buffer[i+1]=='%' && buffer[i+2]=='E' && buffer[i+3]=='O' && buffer[i+4]=='F')
    {
      file_recovery->calculated_file_size=file_recovery->file_size+i+5-(buffer_size/2);
      return DC_STOP;
    }
  }
  file_recovery->calculated_file_size=file_recovery->file_size+(buffer_size/2);
  return DC_CONTINUE;
}

/*@
  @ requires buffer_size > 0;
  @ requires \valid_read(buffer+(0..buffer_size-1));
  @ requires valid_file_recovery(file_recovery);
  @ requires \valid(file_recovery_new);
  @ requires file_recovery_new->blocksize > 0;
  @ requires separation: \separated(&file_hint_ps, buffer+(..), file_recovery, file_recovery_new);
  @ assigns  *file_recovery_new;
  @ ensures  \result!=0 ==> valid_file_recovery(file_recovery_new);
  @*/
static int header_check_ps(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /* PS or EPSF */
  int i;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->min_filesize=sizeof(ps_header);
  file_recovery_new->file_check=&file_check_ps;
  /*@ loop assigns i, file_recovery_new->extension, file_recovery_new->data_check; */
  for(i=sizeof(ps_header); i < 20; i++)
  {
    switch(buffer[i])
    {
      case '\n':
	file_recovery_new->extension=file_hint_ps.extension;
	if(file_recovery_new->blocksize > 8)
	  file_recovery_new->data_check=&data_check_ps;
	return 1;
      case 'E':
	if(i+5 <= buffer_size && memcmp(&buffer[i],"EPSF-",5)==0)
	{
	  file_recovery_new->extension="eps";
	  return 1;
	}
	break;
    }
  }
  file_recovery_new->extension=file_hint_ps.extension;
  if(file_recovery_new->blocksize > 8)
    file_recovery_new->data_check=&data_check_ps;
  return 1;
}

static void register_header_check_ps(file_stat_t *file_stat)
{
  register_header_check(0, ps_header,sizeof(ps_header), &header_check_ps, file_stat);
}
#endif
