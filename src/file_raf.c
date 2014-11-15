/*

    File: file_raf.c

    Copyright (C) 1998-2005,2007-2011 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include "common.h"
#include "filegen.h"


static void register_header_check_raf(file_stat_t *file_stat);

const file_hint_t file_hint_raf= {
  .extension="raf",
  .description="Raw Fujifilm picture",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_raf
};

/* Documentation source: http://libopenraw.freedesktop.org/wiki/Fuji_RAF/ */
struct header_raf
{
  char magic[16];
  char unk1[4];		/* 0201 */
  char unk2[8];		/* FF393103 */
  char model[32];	/* ie. FinePix E900 */
  char dir_version[4];	/* 0100 or 0159 */
  char unk3[20];
  uint32_t jpg_offset;
  uint32_t jpg_size;
  uint32_t cfa_header_offset;
  uint32_t cfa_header_size;
  uint32_t cfa_offset;
  uint32_t cfa_size;
} __attribute__ ((__packed__));

static int header_check_raf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /* Fuji */
  uint64_t tmp;
  const struct header_raf *raf=(const struct header_raf *)buffer;
  uint64_t size;
  if((const uint32_t)be32(raf->jpg_offset)!=0 && (const uint32_t)be32(raf->jpg_offset)<sizeof(struct header_raf))
    return 0;
  if((const uint32_t)be32(raf->cfa_offset)!=0 && (const uint32_t)be32(raf->cfa_offset)<sizeof(struct header_raf))
    return 0;
  if((const uint32_t)be32(raf->cfa_header_offset)!=0 && (const uint32_t)be32(raf->cfa_header_offset)<sizeof(struct header_raf))
    return 0;
  size=(uint64_t)be32(raf->jpg_offset)+be32(raf->jpg_size);
  tmp=(uint64_t)be32(raf->cfa_offset)+be32(raf->cfa_size);
  if(size < tmp)
    size=tmp;
  tmp=(uint64_t)be32(raf->cfa_header_offset)+be32(raf->cfa_header_size);
  if(size < tmp)
    size=tmp;
  if(size < sizeof(struct header_raf))
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_raf.extension;
  file_recovery_new->calculated_file_size=size;
  if(raf->dir_version[0]=='0' && raf->dir_version[0]=='1')
  {
    file_recovery_new->data_check=&data_check_size;
    file_recovery_new->file_check=&file_check_size;
  }
  else
  {
    /* The size is bigger than calculated_file_size */
    file_recovery_new->file_check=&file_check_size_lax;
  }
  return 1;
}

static void register_header_check_raf(file_stat_t *file_stat)
{
  register_header_check(0, "FUJIFILMCCD-RAW ", 16, &header_check_raf, file_stat);
}
