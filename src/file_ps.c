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


static void register_header_check_ps(file_stat_t *file_stat);
static int header_check_ps(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);
static data_check_t data_check_ps(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery);

const file_hint_t file_hint_ps= {
  .extension="ps",
  .description="PostScript or Encapsulated PostScript document",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_ps
};

static const unsigned char ps_header[11]= { '%','!','P','S','-','A','d','o','b','e','-'};

static void register_header_check_ps(file_stat_t *file_stat)
{
  register_header_check(0, ps_header,sizeof(ps_header), &header_check_ps, file_stat);
}

static int header_check_ps(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(buffer,ps_header,sizeof(ps_header))==0)
  { /* PS or EPSF */
    int i;
    for(i=sizeof(ps_header);i<20;i++)
    {
      switch(buffer[i])
      {
	case '\n':
	  reset_file_recovery(file_recovery_new);
	  file_recovery_new->extension=file_hint_ps.extension;
	  file_recovery_new->data_check=&data_check_ps;
	  file_recovery_new->file_check=&file_check_size;
	  return 1;
	case 'E':
	  if(memcmp(&buffer[i],"EPSF-",5)==0)
	  {
	    reset_file_recovery(file_recovery_new);
	    file_recovery_new->extension="eps";
	    return 1;
	  }
	  break;
      }
    }
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_ps.extension;
    file_recovery_new->data_check=&data_check_ps;
    file_recovery_new->file_check=&file_check_size;
    return 1;
  }
  return 0;
}

static data_check_t data_check_ps(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  if(buffer_size>8)
  {
    unsigned int i;
    for(i=(buffer_size/2)-4;i+4<buffer_size;i++)
    {
      if(buffer[i]=='%' && buffer[i+1]=='%' && buffer[i+2]=='E' && buffer[i+3]=='O' && buffer[i+4]=='F')
      {
	file_recovery->calculated_file_size=file_recovery->file_size+i+5-(buffer_size/2);
	return DC_STOP;
      }
    }
  }
  file_recovery->calculated_file_size=file_recovery->file_size+(buffer_size/2);
  return DC_CONTINUE;
}
