/*

    File: file_it.c

    Copyright (C) 2011 Christophe GRENIER <grenier@cgsecurity.org>
  
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

static void register_header_check_it(file_stat_t *file_stat);

const file_hint_t file_hint_it= {
  .extension="it",
  .description="Impulse Tracker",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_it
};

/* http://schismtracker.org/wiki/ITTECH.TXT */
struct impulse_header
{
  uint32_t magic;
  char	   song_name[26];
  uint16_t PHiligt;
  uint16_t OrdNum;
  uint16_t InsNum;
  uint16_t SmpNum;
  uint16_t PatNum;
  uint16_t Cwtv;
  uint16_t Cmwt;
  uint16_t Flags;
  uint16_t Special;
  uint8_t  GV;
  uint8_t  MV;
  uint8_t  IS;
  uint8_t  IT;
  uint8_t  Sep;
  uint8_t  PWD;
  uint16_t MsgLgth;
  uint16_t MsgOff;
  uint32_t Reserved;
  char     Chnl_Pan[64];
  char     Chnl_Vol[64];
} __attribute__ ((__packed__));

static int header_check_it(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct impulse_header *header=(const struct impulse_header *)buffer;
  if(header->Reserved!=0)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_it.extension;
  return 1;
}

static void register_header_check_it(file_stat_t *file_stat)
{
  register_header_check(0, "IMPM", 4, &header_check_it, file_stat);
}
