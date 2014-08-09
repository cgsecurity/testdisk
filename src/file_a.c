/*

    File: file_a.c

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
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "filegen.h"

static void register_header_check_a(file_stat_t *file_stat);

const file_hint_t file_hint_a= {
  .extension="a",
  .description="Unix Archive/Debian package",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_a
};

struct file_header
{
  char name[16];
  char mtime[12];
  char uid[6];
  char gid[6];
  char mode[8];
  char size[10];
  char magic[2];
} __attribute__ ((__packed__));

static int header_check_a(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only,  const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  static const unsigned char a_header_debian[14]  = { '!','<','a','r','c','h','>','\n','d','e','b','i','a','n'};
  static const char magic[2]= { 0x60, 0x0a};
  const struct file_header *fh=(const struct file_header *)&buffer[8];
  if(memcmp(fh->magic, magic, 2)!=0)
    return 0;
  /* http://en.wikipedia.org/wiki/Ar_%28Unix%29 */
  reset_file_recovery(file_recovery_new);
  if(memcmp(buffer,a_header_debian,sizeof(a_header_debian))==0)
    file_recovery_new->extension="deb";
  else
    file_recovery_new->extension=file_hint_a.extension;
  return 1;
}

static void register_header_check_a(file_stat_t *file_stat)
{
  static const unsigned char a_header[8]  = { '!','<','a','r','c','h','>','\n'};
  register_header_check(0, a_header,sizeof(a_header), &header_check_a, file_stat);
}
