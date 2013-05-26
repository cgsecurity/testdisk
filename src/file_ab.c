/*

    File: file_addressbook.c

    Copyright (C) 2007-2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include "types.h"
#include "filegen.h"
#include "log.h"

static void register_header_check_ab(file_stat_t *file_stat);
static int header_check_addressbook(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);
static int data_check_addressbook(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery);

const file_hint_t file_hint_addressbook= {
  .extension="ab",
  .description="MAC Address Book",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_ab
};

static const unsigned char ab_header[2]={ 'L', 'J' };

static void register_header_check_ab(file_stat_t *file_stat)
{
  register_header_check(0, ab_header,sizeof(ab_header), &header_check_addressbook, file_stat);
}

static int header_check_addressbook(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(buffer[0]=='L' && buffer[1]=='J' && (buffer[2]==0x1a || buffer[2]==0x0a) && buffer[3]==0x00)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->calculated_file_size=(buffer[4]<<24)+(buffer[5]<<16)+(buffer[6]<<8)+buffer[7];
    file_recovery_new->data_check=&data_check_addressbook;
    file_recovery_new->file_check=&file_check_size;
    file_recovery_new->extension=file_hint_addressbook.extension;
    return 1;
  }
  return 0;
}

static int data_check_addressbook(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 8 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size - file_recovery->file_size + buffer_size/2;
#ifdef DEBUG_AB
    log_debug("data_check_addressbook i=0x%x buffer_size=0x%x calculated_file_size=%lu file_size=%lu\n",
        i, buffer_size,
        (long unsigned)file_recovery->calculated_file_size,
        (long unsigned)file_recovery->file_size);
    dump_log(buffer+i,8);
#endif
    if(buffer[i+0]=='L' && buffer[i+1]=='J' && buffer[i+3]==0x00)
    {
      const unsigned int length=(buffer[i+4]<<24)+(buffer[i+5]<<16)+(buffer[i+6]<<8)+buffer[i+7];
      if(length<8)
      {
        return 2;
      }
      file_recovery->calculated_file_size+=length;
    }
    else
    {
      return 2;
    }
  }
  return 1;
}
