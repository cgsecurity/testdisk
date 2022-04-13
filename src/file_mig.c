/*

    File: file_mig.c

    Copyright (C) 2012 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mig)
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
#ifdef DEBUG_MIG
#include "log.h"
#endif

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_mig(file_stat_t *file_stat);

const file_hint_t file_hint_mig= {
  .extension="mig",
  .description="Windows Migration Backup",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_mig
};

struct MIG_HDR
{
  uint32_t magic;
  uint32_t fn_size;
  uint32_t s_size;
  uint32_t unk1;
  uint32_t unk2;
  uint32_t unk3;
#ifndef DISABLED_FOR_FRAMAC
  unsigned char fn[0];
#endif
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires file_recovery->file_check == &file_check_mig;
  @ requires \separated(file_recovery, file_recovery->handle, file_recovery->extension, &errno, &Frama_C_entropy_source);
  @ requires valid_file_check_param(file_recovery);
  @ ensures  valid_file_check_result(file_recovery);
  @ assigns *file_recovery->handle, errno, file_recovery->file_size;
  @ assigns Frama_C_entropy_source;
  @*/
static void file_check_mig(file_recovery_t *file_recovery)
{
  uint64_t offset=0x34;
  file_recovery->file_size=0;
  /*@
    @ loop assigns *file_recovery->handle, errno, file_recovery->file_size;
    @ loop assigns Frama_C_entropy_source;
    @ loop assigns offset;
    @*/
  while(1)
  {
    char buffer[sizeof(struct MIG_HDR)];
    const struct MIG_HDR *h=(const struct MIG_HDR *)&buffer;
    size_t res;
    if(my_fseek(file_recovery->handle, offset, SEEK_SET) < 0)
    {
#ifdef DEBUG_MIG
      log_info("0x%lx fseek failed\n", (long unsigned)offset);
#endif
      return ;
    }
    res=fread(&buffer, 1, sizeof(buffer), file_recovery->handle);
    if(res < 8)
    {
#ifdef DEBUG_MIG
      log_info("0x%lx not enough data\n", (long unsigned)offset);
#endif
      return ;
    }
    /* STRM=stream */
    if(res < sizeof(buffer) || le32(h->magic)!=0x5354524d || offset >= PHOTOREC_MAX_FILE_SIZE)
    {
#ifdef DEBUG_MIG
      log_info("0x%lx no magic %x\n", (long unsigned)offset, le32(h->magic));
#endif
      file_recovery->file_size=offset+8;
      return ;
    }
#ifdef DEBUG_MIG
    log_info("0x%lx magic s_size=0x%u\n", (long unsigned)offset, le32(h->s_size));
#endif
    offset+=sizeof(buffer)+le32(h->s_size);
  }
}

/*@
  @ requires buffer_size > 0x38;
  @ requires separation: \separated(&file_hint_mig, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_mig(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(&buffer[0x34], "MRTS", 4)!=0)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_mig.extension;
  file_recovery_new->file_check=&file_check_mig;
  return 1;
}

static void register_header_check_mig(file_stat_t *file_stat)
{
  static const unsigned char mig_header[8]=  {
    '1' , 'g' , 'i' , 'M' , 0x02, 0x00, 0x00, 0x00
  };
  register_header_check(0, mig_header, sizeof(mig_header), &header_check_mig, file_stat);
}
#endif
