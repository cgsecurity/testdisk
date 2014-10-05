/*

    File: file_tar.c

    Copyright (C) 1998-2005,2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include "file_tar.h"

static void register_header_check_tar(file_stat_t *file_stat);

const file_hint_t file_hint_tar= {
  .extension="tar",
  .description="tar archive",
  .min_header_distance=0x200,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_tar
};

static const unsigned char tar_header_gnu[6]	= { 'u','s','t','a','r',0x00};
static const unsigned char tar_header_posix[8]  = { 'u','s','t','a','r',' ',' ',0x00};

static void register_header_check_tar(file_stat_t *file_stat)
{
  register_header_check(0x101, tar_header_gnu,sizeof(tar_header_gnu), &header_check_tar, file_stat);
  register_header_check(0x101, tar_header_posix,sizeof(tar_header_posix), &header_check_tar, file_stat);
}

int header_check_tar(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(file_recovery->file_stat!=NULL && file_recovery->file_stat->file_hint==&file_hint_tar)
    return 0;
  if(memcmp(&buffer[0x101],tar_header_gnu,sizeof(tar_header_gnu))==0 ||
      memcmp(&buffer[0x101],tar_header_posix,sizeof(tar_header_posix))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_tar.extension;
    return 1;
  }
  return 0;
}
