/*

    File: file_cdt.c

    Copyright (C) 2010 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_cdt)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "filegen.h"

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_cdt(file_stat_t *file_stat);

const file_hint_t file_hint_cdt= {
  .extension="cdt",
  .description="cdl/cdt/cdd Concept Draw",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_cdt
};

/*@
  @ requires separation: \separated(&file_hint_cdt, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_cdt(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  reset_file_recovery(file_recovery_new);
  if(buffer[0]==0xee)
    file_recovery_new->extension="cdl";	/* ConceptDraw PRO Library File */
  else if(buffer[0]==0xef)
    file_recovery_new->extension="cdd";	/* ConceptDraw PRO Document */
  else if(buffer[0]==0xf0)
    file_recovery_new->extension="cdt";	/* ConceptDraw PRO Template */
  else
    file_recovery_new->extension=file_hint_cdt.extension;
  return 1;
}

static void register_header_check_cdt(file_stat_t *file_stat)
{
  static const unsigned char cdt_header[7]=  {
    'C' , 'O' , 'N' , 'C' , 'E' , 'P' , 'T'
  };
  register_header_check(12, cdt_header, sizeof(cdt_header), &header_check_cdt, file_stat);
}
#endif
