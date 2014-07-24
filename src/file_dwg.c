/*

    File: file_dwg.c

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

static void register_header_check_dwg(file_stat_t *file_stat);

const file_hint_t file_hint_dwg= {
  .extension="dwg",
  .description="AutoCAD",
  .min_header_distance=0,
  .max_filesize=20*1024*1024,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_dwg
};

static int header_check_dwg(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_dwg.extension;
  return 1;
}

static void register_header_check_dwg(file_stat_t *file_stat)
{
  static const unsigned char dwg_header_12[11]= {'A', 'C', '1', '0', '1', '2', 0x00, 0x00, 0x00, 0x00, 0x00};
  static const unsigned char dwg_header_13[11]= {'A', 'C', '1', '0', '1', '3', 0x00, 0x00, 0x00, 0x00, 0x00};
  static const unsigned char dwg_header_14[11]= {'A', 'C', '1', '0', '1', '4', 0x00, 0x00, 0x00, 0x00, 0x00};
  static const unsigned char dwg_header_15[11]= {'A', 'C', '1', '0', '1', '5', 0x00, 0x00, 0x00, 0x00, 0x00};
  static const unsigned char dwg_header_18[11]= {'A', 'C', '1', '0', '1', '8', 0x00, 0x00, 0x00, 0x00, 0x00};
  static const unsigned char dwg_header_21[11]= {'A', 'C', '1', '0', '2', '1', 0x00, 0x00, 0x00, 0x00, 0x00};
  static const unsigned char dwg_header_23[11]= {'A', 'C', '1', '0', '2', '3', 0x00, 0x00, 0x00, 0x00, 0x00};
  static const unsigned char dwg_header_24[11]= {'A', 'C', '1', '0', '2', '4', 0x00, 0x00, 0x00, 0x00, 0x00};
  register_header_check(0, dwg_header_12,sizeof(dwg_header_12), &header_check_dwg, file_stat);
  register_header_check(0, dwg_header_13,sizeof(dwg_header_13), &header_check_dwg, file_stat);
  register_header_check(0, dwg_header_14,sizeof(dwg_header_14), &header_check_dwg, file_stat);
  register_header_check(0, dwg_header_15,sizeof(dwg_header_15), &header_check_dwg, file_stat);
  register_header_check(0, dwg_header_18,sizeof(dwg_header_18), &header_check_dwg, file_stat);
  register_header_check(0, dwg_header_21,sizeof(dwg_header_21), &header_check_dwg, file_stat);
  register_header_check(0, dwg_header_23,sizeof(dwg_header_23), &header_check_dwg, file_stat);
  register_header_check(0, dwg_header_24,sizeof(dwg_header_24), &header_check_dwg, file_stat);
}
