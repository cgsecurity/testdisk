/*

    File: file_che.c

    Copyright (C) 2016 Christophe GRENIER <grenier@cgsecurity.org>

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_che)
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
#include "log.h"

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_che(file_stat_t *file_stat);

const file_hint_t file_hint_che= {
  .extension="che",
  .description="Compucon EOS Design File",
  .max_filesize=100*1024*1024,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_che
};

struct che_block
{
  char name[0x10];
  uint32_t size;
  uint32_t unk1;
  uint32_t unk2;
} __attribute__ ((gcc_struct, __packed__));


/*@
  @ requires file_recovery->file_check == &file_check_che;
  @ requires valid_file_check_param(file_recovery);
  @ ensures  valid_file_check_result(file_recovery);
  @ assigns *file_recovery->handle, errno, file_recovery->file_size;
  @ assigns Frama_C_entropy_source;
  @
  @*/
static void file_check_che(file_recovery_t *file_recovery)
{
  struct che_block block;
  uint64_t offset;
  uint64_t new_offset=0x19;
  const uint64_t file_size_org=file_recovery->file_size;
  file_recovery->file_size=0;
  /*@
    @ loop assigns *file_recovery->handle, errno, file_recovery->file_size;
    @ loop assigns Frama_C_entropy_source;
    @ loop assigns new_offset;
    @ loop variant file_size_org - new_offset;
    @*/
  do
  {
    offset=new_offset;
#ifdef DEBUG_CHE
    log_info("offset=0x%llx\n", (long long unsigned)offset);
#endif
    if(my_fseek(file_recovery->handle, offset, SEEK_SET) < 0 ||
	fread(&block, sizeof(struct che_block), 1, file_recovery->handle) != 1)
    {
      file_recovery->file_size=offset;
      return ;
    }
#ifdef DEBUG_CHE
    log_info("  sizeof=0x%x, size=%x, name=%s\n", sizeof(struct che_block),le32(block.size), block.name);
#endif
    new_offset=offset+sizeof(struct che_block)+le32(block.size);
    if(memcmp(block.name,"ConnectionInfo",14)==0)
    {
      file_recovery->file_size=new_offset;
      return ;
    }
  } while(new_offset <= file_size_org && le32(block.size)!=0);
  file_recovery->file_size=offset;
}

/*@
  @ requires separation: \separated(&file_hint_che, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_che(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_che.extension;
  file_recovery_new->min_filesize=0x19;
  file_recovery_new->file_check=&file_check_che;
  return 1;
}

static void register_header_check_che(file_stat_t *file_stat)
{
  register_header_check(0, "Compucon EOS Design File", 24, &header_check_che, file_stat);
}
#endif
