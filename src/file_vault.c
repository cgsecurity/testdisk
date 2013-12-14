/*

    File: file_vault.c

    Copyright (C) 2011 Christophe GRENIER <grenier@cgsecurity.org>
  
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

static void register_header_check_vault(file_stat_t *file_stat);
static int header_check_vault(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_vault= {
  .extension="vault",
  .description="McAfee Anti-Theft/FileVault",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_vault
};

static const unsigned char vault_header[0x12]=  {
  'S' , 'a' , 'f' , 'e' , 'B' , 'o' , 'o' , 't' ,
  'E' , 'n' , 'c' , 'V' , 'o' , 'l' , '1' , 0x00,
  0x01, 0x01
};

static void register_header_check_vault(file_stat_t *file_stat)
{
  register_header_check(0, vault_header, sizeof(vault_header), &header_check_vault, file_stat);
}

/* 
 * 03200be0  00 00 00 38 65 31 39 37  34 32 30 2d 39 35 65 34  |...8e197420-95e4|
 * 03200bf0  2d 34 36 33 33 2d 61 33  34 66 2d 34 61 66 64 36  |-4633-a34f-4afd6|
 * 03200c00  30 64 61 62 64 64 37 00                           |0dabdd7.|
 * */
static data_check_t data_check_vault(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  if(buffer_size>8)
  {
    unsigned int i;
    for(i=(buffer_size/2)-28;i+28<buffer_size;i++)
    {
      if(buffer[i]=='-' && buffer[i+5]=='-' && buffer[i+10]=='-' && buffer[i+15]=='-' && buffer[i+28]=='\0')
      {
	file_recovery->calculated_file_size=file_recovery->file_size+i+28+1-(buffer_size/2);
	return DC_STOP;
      }
    }
  }
  file_recovery->calculated_file_size=file_recovery->file_size+(buffer_size/2);
  return DC_CONTINUE;
}

static int header_check_vault(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(&buffer[0], vault_header, sizeof(vault_header))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_vault.extension;
    file_recovery_new->data_check=&data_check_vault;
    file_recovery_new->file_check=&file_check_size;
    return 1;
  }
  return 0;
}

