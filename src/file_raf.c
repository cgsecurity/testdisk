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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_raf)
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

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_raf(file_stat_t *file_stat);

const file_hint_t file_hint_raf= {
  .extension="raf",
  .description="Raw Fujifilm picture",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_raf
};

/* Documentation source: https://libopenraw.pages.freedesktop.org/formats/raf/ */
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
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires buffer_size >= sizeof(struct header_raf);
  @ requires separation: \separated(&file_hint_raf, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_raf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct header_raf *raf=(const struct header_raf *)buffer;
  /*@ assert \valid_read(raf); */
  /* Fuji */
  const unsigned int cfa_header_offset=be32(raf->cfa_header_offset);
  const unsigned int cfa_header_size=be32(raf->cfa_header_size);
  const unsigned int cfa_offset=be32(raf->cfa_offset);
  const unsigned int cfa_size=be32(raf->cfa_size);
  const unsigned int jpg_offset=be32(raf->jpg_offset);
  const unsigned int jpg_size=be32(raf->jpg_size);
  uint64_t size=0;
  if(jpg_size > 0)
  {
    const uint64_t tmp=(uint64_t)jpg_offset + jpg_size;
    if(jpg_offset<sizeof(struct header_raf))
      return 0;
    if(tmp > size)
      size=tmp;
  }
  if(cfa_size > 0)
  {
    const uint64_t tmp=(uint64_t)cfa_offset + cfa_size;
    if(cfa_offset<sizeof(struct header_raf))
      return 0;
    if(size < tmp)
      size=tmp;
  }
  if(cfa_header_size > 0)
  {
    const uint64_t tmp=(uint64_t)cfa_header_offset + cfa_header_size;
    if(cfa_header_offset<sizeof(struct header_raf))
      return 0;
    if(size < tmp)
      size=tmp;
  }
  if(size < sizeof(struct header_raf))
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_raf.extension;
  file_recovery_new->calculated_file_size=size;
  /* The size is bigger than calculated_file_size */
  file_recovery_new->file_check=&file_check_size_min;
  return 1;
}

static void register_header_check_raf(file_stat_t *file_stat)
{
  register_header_check(0, "FUJIFILMCCD-RAW ", 16, &header_check_raf, file_stat);
}
#endif
