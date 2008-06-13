/*

    File: file_wks.c

    Copyright (C) 2008 Christophe GRENIER <grenier@cgsecurity.org>
  
    This software is free software; you can redistribute it and/or modify
    it under the teras of the GNU General Public License as published by
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


static void register_header_check_wks(file_stat_t *file_stat);
static int header_check_wks(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);
static int header_check_wk4(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_wks= {
  .extension="wks",
  .description="Lotus 1-2-3",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_wks
};

static const unsigned char wks_header[10]  = { 0x00, 0x00, 0x02, 0x00, 0x04, 0x04,
  0x06, 0x00, 0x08, 0x00};
/*
 * record type=0	BOF=Beginning of file
 * record length=2
 * 0x0404 = 1-2-3
 * 0x0405 = Symphony
 *
 * record type=6	RANGE=Active worksheet range
 * See
 * http://www.schnarff.com/file-formats/lotus-1-2-3/WSFF1.TXT
 * http://www.schnarff.com/file-formats/lotus-1-2-3/WSFF2.TXT
 */
static const unsigned char wk4_header[8]  = { 0x00, 0x00, 0x1a, 0x00, 0x02, 0x10, 0x04, 0x00};

static void register_header_check_wks(file_stat_t *file_stat)
{
  register_header_check(0, wks_header,sizeof(wks_header), &header_check_wks, file_stat);
  register_header_check(0, wk4_header,sizeof(wk4_header), &header_check_wk4, file_stat);
}

static int header_check_wks(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(buffer,wks_header,sizeof(wks_header))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_wks.extension;
    return 1;
  }
  return 0;
}

static int header_check_wk4(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(buffer,wk4_header,sizeof(wk4_header))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension="wk4";
    return 1;
  }
  return 0;
}

