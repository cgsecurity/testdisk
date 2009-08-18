/*

    File: file_r3d.c

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
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include <ctype.h>
#include "types.h"
#include "filegen.h"

static void register_header_check_r3d(file_stat_t *file_stat);
static int header_check_r3d(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);
static void file_rename_r3d(const char *old_filename);

const file_hint_t file_hint_r3d= {
  .extension="r3d",
  .description="RED r3d camera",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_r3d
};

static const unsigned char r3d_header[16]=  {
  0x00, 0x00, 0x01, 'D' , 'R' , 'E' , 'D' , '1' ,
  0x04, 0x03, 'R' , '1' , 0x00, 0x00, 0xbb, 0x80
};

static void register_header_check_r3d(file_stat_t *file_stat)
{
  register_header_check(0, r3d_header, sizeof(r3d_header), &header_check_r3d, file_stat);
}

static int header_check_r3d(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(buffer, r3d_header, sizeof(r3d_header))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_r3d.extension;
    file_recovery_new->file_rename=&file_rename_r3d;
    return 1;
  }
  return 0;
}

static void file_rename_r3d(const char *old_filename)
{
  unsigned char buffer[512];
  FILE *file;
  int buffer_size;
  unsigned int i;
  if((file=fopen(old_filename, "rb"))==NULL)
    return;
  buffer_size=fread(buffer, 1, sizeof(buffer), file);
  fclose(file);
  if(buffer_size<10)
    return;
  for(i=0x43; i< buffer_size && buffer[i]!=0 && buffer[i]!='.'; i++)
  {
    if(!isalnum(buffer[i]) && buffer[i]!='_')
      return ;
  }
  file_rename(old_filename, buffer, i, 0x43, NULL, 1);
}
