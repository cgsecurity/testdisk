/*

    File: file_pnm.c

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

static void register_header_check_pnm(file_stat_t *file_stat);

const file_hint_t file_hint_pnm= {
  .extension="pnm",
  .description="Netpbm (PBM/PGM/PPM)",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_pnm
};

static int header_check_pbm(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(!isprint(buffer[5]) || !isprint(buffer[6]) || !isprint(buffer[7]))
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension="pbm";
  return 1;
}

static int header_check_pgm(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(!isprint(buffer[5]) || !isprint(buffer[6]) || !isprint(buffer[7]))
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension="pgm";
  return 1;
}

static int header_check_ppm(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(!isprint(buffer[5]) || !isprint(buffer[6]) || !isprint(buffer[7]))
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension="ppm";
  return 1;
}

static void register_header_check_pnm(file_stat_t *file_stat)
{
  /* See http://en.wikipedia.org/wiki/Netpbm_format */
  register_header_check(0, "P1\n# ", 5, &header_check_pbm, file_stat);
  register_header_check(0, "P2\n# ", 5, &header_check_pgm, file_stat);
  register_header_check(0, "P3\n# ", 5, &header_check_ppm, file_stat);
  register_header_check(0, "P4\n# ", 5, &header_check_pbm, file_stat);
  register_header_check(0, "P5\n# ", 5, &header_check_pgm, file_stat);
  register_header_check(0, "P6\n# ", 5, &header_check_ppm, file_stat);
}
