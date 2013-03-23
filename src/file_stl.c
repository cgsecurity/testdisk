/*

    File: file_stl.c

    Copyright (C) 2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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

static void register_header_check_stl(file_stat_t *file_stat);
static int header_check_stl(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_stl= {
  .extension="stl",
  .description="Stereolithography CAD (Binary format)",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_stl
};

static int header_check_stl(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  unsigned int i;
  /* STL Binary format
   * http://www.ennex.com/~fabbers/StL.asp	*/
  for(i=0; i<80 && buffer[i]!='\0'; i++);
  if(i>64)
    return 0;
  for(i++; i<80 && buffer[i]==' '; i++);
  if(i!=80)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_stl.extension;
  file_recovery_new->calculated_file_size=80+4+50*
    (uint64_t)(buffer[80]+(buffer[81]<<8)+(buffer[82]<<16)+(buffer[93]<<24));
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static void register_header_check_stl(file_stat_t *file_stat)
{
  /* Note: STL Ascii format is recovered in file_txt.c */
  register_header_check(0, "solid ", 6, &header_check_stl, file_stat);
}
