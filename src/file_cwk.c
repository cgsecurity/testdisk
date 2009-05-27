/*

    File: file_cwk.c

    Copyright (C) 2006-2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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

static void register_header_check_cwk(file_stat_t *file_stat);
static int header_check_cwk(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);
static void file_check_cwk(file_recovery_t *file_recovery);

const file_hint_t file_hint_cwk= {
  .extension="cwk",
  .description="AppleWorks",
  .min_header_distance=0,
  .max_filesize=200*1024*1024,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_cwk
};

static const unsigned char cwk_header[4]= {'B','O','B','O'};

static void register_header_check_cwk(file_stat_t *file_stat)
{
  register_header_check(4, cwk_header,sizeof(cwk_header), &header_check_cwk, file_stat);
}

static int header_check_cwk(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(buffer+4, cwk_header, sizeof(cwk_header))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_cwk.extension;
    file_recovery_new->file_check=&file_check_cwk;
    return 1;
  }
  return 0;
}

static void file_check_cwk(file_recovery_t *file_recovery)
{
  const unsigned char cwk_footer[4]= {0xf0, 0xf1, 0xf2, 0xf3};
  file_search_footer(file_recovery, cwk_footer, sizeof(cwk_footer), 4);
}
