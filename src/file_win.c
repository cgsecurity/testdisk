/*

    File: file_win.c

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
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "filegen.h"
#include "file_txt.h"
#include "common.h"

static void register_header_check_win(file_stat_t *file_stat);
static int header_check_win(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);
static data_check_t data_check_win(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery);

const file_hint_t file_hint_win= {
  .extension="win",
  .description="Opera preferences",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_win
};

static const unsigned char win_header[31]=  {
  0xef, 0xbb, 0xbf, 'O' , 'p' , 'e' , 'r' , 'a' ,
  ' ' , 'P' , 'r' , 'e' , 'f' , 'e' , 'r' , 'e' ,
  'n' , 'c' , 'e' , 's' , ' ' , 'v' , 'e' , 'r' ,
  's' , 'i' , 'o' , 'n' , ' ' , '2' , '.' 
};

static void register_header_check_win(file_stat_t *file_stat)
{
  register_header_check(0, win_header, sizeof(win_header), &header_check_win, file_stat);
}

static int header_check_win(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(buffer, win_header, sizeof(win_header))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_win.extension;
    file_recovery_new->data_check=&data_check_win;
    file_recovery_new->file_check=&file_check_size;
    return 1;
  }
  return 0;
}

static data_check_t data_check_win(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  unsigned int i;
  char *buffer_lower=(char *)MALLOC(buffer_size+16);
  unsigned int offset=0;
  if(file_recovery->calculated_file_size==0)
    offset=3;
  i=UTF2Lat((unsigned char*)buffer_lower, &buffer[buffer_size/2+offset], buffer_size/2-offset);
  if(i<buffer_size/2-offset)
  {
    if(i>=10)
      file_recovery->calculated_file_size=file_recovery->file_size+offset+i;
    free(buffer_lower);
    return DC_STOP;
  }
  free(buffer_lower);
  file_recovery->calculated_file_size=file_recovery->file_size+(buffer_size/2);
  return DC_CONTINUE;
}
