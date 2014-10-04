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

static void register_header_check_mig(file_stat_t *file_stat);

const file_hint_t file_hint_mig= {
  .extension="mig",
  .description="Windows Migration Backup",
  .min_header_distance=0,
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
  unsigned char fn[0];
} __attribute__ ((__packed__));

static void file_check_mig(file_recovery_t *file_recovery)
{
  struct MIG_HDR h;
  uint64_t offset=0x34;
  file_recovery->file_size=0;
  while(1)
  {
    size_t res;
#ifdef HAVE_FSEEKO
    if(fseeko(file_recovery->handle, offset, SEEK_SET) < 0)
#else
    if(fseek(file_recovery->handle, offset, SEEK_SET) < 0)
#endif
    {
#ifdef DEBUG_MIG
      log_info("0x%lx fseek failed\n", (long unsigned)offset);
#endif
      return ;
    }
    res=fread(&h, 1, sizeof(h), file_recovery->handle);
    if(res < 8)
    {
#ifdef DEBUG_MIG
      log_info("0x%lx not enough data\n", (long unsigned)offset);
#endif
      return ;
    }
    if(res < sizeof(h) || le32(h.magic)!=0x5354524d)	/* STRM=stream */
    {
#ifdef DEBUG_MIG
      log_info("0x%lx no magic %x\n", (long unsigned)offset, le32(h.magic));
#endif
      file_recovery->file_size=offset+8;
      return ;
    }
#ifdef DEBUG_MIG
    log_info("0x%lx magic s_size=0x%u\n", (long unsigned)offset, le32(h.s_size));
#endif
    offset+=sizeof(h)+le32(h.s_size);
  }
}

static const unsigned char mig_header[8]=  {
  '1' , 'g' , 'i' , 'M' , 0x02, 0x00, 0x00, 0x00
};

static int header_check_mig(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(&buffer[0], mig_header, sizeof(mig_header))==0 &&
      memcmp(&buffer[0x34], "MRTS", 4)==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_mig.extension;
    file_recovery_new->file_check=&file_check_mig;
    return 1;
  }
  return 0;
}

static void register_header_check_mig(file_stat_t *file_stat)
{
  register_header_check(0, mig_header, sizeof(mig_header), &header_check_mig, file_stat);
}
