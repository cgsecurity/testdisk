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
#include "types.h"
#include "filegen.h"

static void register_header_check_pnm(file_stat_t *file_stat);
static int header_check_pnm(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_pnm= {
  .extension="pnm",
  .description="Netpbm (PBM/PGM/PPM)",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_pnm
};

static const unsigned char p1_header[5]=  { 'P', '1', '\n', '#', ' ' };
static const unsigned char p2_header[5]=  { 'P', '2', '\n', '#', ' ' };
static const unsigned char p3_header[5]=  { 'P', '3', '\n', '#', ' ' };
static const unsigned char p4_header[5]=  { 'P', '4', '\n', '#', ' ' };
static const unsigned char p5_header[5]=  { 'P', '5', '\n', '#', ' ' };
static const unsigned char p6_header[5]=  { 'P', '6', '\n', '#', ' ' };

static void register_header_check_pnm(file_stat_t *file_stat)
{
  register_header_check(0, p1_header, sizeof(p1_header), &header_check_pnm, file_stat);
  register_header_check(0, p2_header, sizeof(p2_header), &header_check_pnm, file_stat);
  register_header_check(0, p3_header, sizeof(p3_header), &header_check_pnm, file_stat);
  register_header_check(0, p4_header, sizeof(p4_header), &header_check_pnm, file_stat);
  register_header_check(0, p5_header, sizeof(p5_header), &header_check_pnm, file_stat);
  register_header_check(0, p6_header, sizeof(p6_header), &header_check_pnm, file_stat);
}

static int header_check_pnm(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /* See http://en.wikipedia.org/wiki/Netpbm_format */
  if(memcmp(buffer, p1_header, sizeof(p1_header))==0 ||
      memcmp(buffer, p4_header, sizeof(p4_header))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension="pbm";
    return 1;
  }
  if(memcmp(buffer, p2_header, sizeof(p2_header))==0 ||
      memcmp(buffer, p5_header, sizeof(p5_header))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension="pgm";
    return 1;
  }
  if(memcmp(buffer, p3_header, sizeof(p3_header))==0 ||
      memcmp(buffer, p6_header, sizeof(p6_header))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension="ppm";
    return 1;
  }
  return 0;
}
