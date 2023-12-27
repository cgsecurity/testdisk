/*

    File: file_addressbook.c

    Copyright (C) 2007-2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_addressbook)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include "types.h"
#include "common.h"
#include "filegen.h"
#include "log.h"

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_ab(file_stat_t *file_stat);

const file_hint_t file_hint_addressbook= {
  .extension="ab",
  .description="MAC Address Book",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_ab
};

struct ab_header
{
  char magic[4];
  uint32_t size;
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires file_recovery->data_check==&data_check_addressbook;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ terminates \true;
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ assigns  file_recovery->calculated_file_size;
  @*/
static data_check_t data_check_addressbook(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@
    @ loop assigns file_recovery->calculated_file_size;
    @ loop variant file_recovery->file_size + buffer_size/2 - (file_recovery->calculated_file_size + 8);
    @*/
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 8 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size + buffer_size/2 - file_recovery->file_size;
    /*@ assert 0 <= i < buffer_size - 8; */
    const struct ab_header *ab=(const struct ab_header *)&buffer[i];
    const unsigned int length=be32(ab->size);
#ifdef DEBUG_AB
    log_debug("data_check_addressbook i=0x%x buffer_size=0x%x calculated_file_size=%lu file_size=%lu\n",
        i, buffer_size,
        (long unsigned)file_recovery->calculated_file_size,
        (long unsigned)file_recovery->file_size);
    dump_log(buffer+i,8);
#endif
    if(ab->magic[0]!='L' || ab->magic[1]!='J' || ab->magic[3]!=0x00 || length<8)
      return DC_STOP;
    file_recovery->calculated_file_size+=length;
  }
  return DC_CONTINUE;
}

/*@
  @ requires buffer_size >= sizeof(struct ab_header);
  @ requires separation: \separated(&file_hint_addressbook, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_addressbook(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct ab_header *ab=(const struct ab_header *)buffer;
  const unsigned int length=be32(ab->size);
  if(ab->magic[0]!='L' || ab->magic[1]!='J' || ab->magic[3]!=0x00 || length<8)
    return 0;
  if(ab->magic[2]!=0x1a && ab->magic[2]!=0x0a)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_addressbook.extension;
  if(file_recovery_new->blocksize >= 8)
  {
    file_recovery_new->calculated_file_size=length;
    file_recovery_new->data_check=&data_check_addressbook;
    file_recovery_new->file_check=&file_check_size;
  }
  return 1;
}

static void register_header_check_ab(file_stat_t *file_stat)
{
  static const unsigned char ab_header[2]={ 'L', 'J' };
  register_header_check(0, ab_header,sizeof(ab_header), &header_check_addressbook, file_stat);
}
#endif
