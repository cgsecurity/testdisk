/*

    File: file_xcf.c

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

static void register_header_check_xcf(file_stat_t *file_stat);
static int header_check_xcf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_xcf= {
  .extension="xcf",
  .description="Gimp XCF File",
  .min_header_distance=0,
  .max_filesize=1024*1024*1024,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_xcf
};

// version 0: gimp xcf file
// version 1: gimp xcf v001
static const unsigned char xcf_header_v0[13]= {'g','i','m','p',' ','x','c','f',' ','f','i','l','e'};
static const unsigned char xcf_header_v1[10]= {'g','i','m','p',' ','x','c','f',' ','v'};

static void register_header_check_xcf(file_stat_t *file_stat)
{
  register_header_check(0, xcf_header_v0,sizeof(xcf_header_v0), &header_check_xcf, file_stat);
  register_header_check(0, xcf_header_v1,sizeof(xcf_header_v1), &header_check_xcf, file_stat);
}

static int header_check_xcf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(buffer,xcf_header_v0, sizeof(xcf_header_v0))==0 ||
      memcmp(buffer,xcf_header_v1, sizeof(xcf_header_v1))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_xcf.extension;
    return 1;
  }
  return 0;
}
