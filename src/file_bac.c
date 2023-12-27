/*

    File: file_bac.c

    Copyright (C) 2009 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_bac)
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

/*@
  @ requires valid_register_header_check(file_stat);
  @*/
static void register_header_check_bac(file_stat_t *file_stat);

const file_hint_t file_hint_bac= {
  .extension="bac",
  .description="Bacula backup",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_bac
};

struct block_header
{
  uint32_t CheckSum;                /* Block check sum */
  uint32_t BlockSize;               /* Block byte size including the header */
  uint32_t BlockNumber;             /* Block number */
  char ID[4];              	    /* Identification and block level */
  uint32_t VolSessionId;            /* Session Id for Job */
  uint32_t VolSessionTime;          /* Session Time for Job */
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires buffer_size >= 2*0x18;
  @ requires file_recovery->data_check==&data_check_bac;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ assigns file_recovery->calculated_file_size;
  @*/
static data_check_t data_check_bac(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /*@ assert buffer_size >= 2*0x18; */
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@
    @ loop assigns file_recovery->calculated_file_size;
    @ loop variant file_recovery->file_size + buffer_size/2 - (file_recovery->calculated_file_size + 0x18);
    @*/
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 0x18 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size + buffer_size/2 - file_recovery->file_size;
    /*@ assert 0 <= i < buffer_size - 0x18 ; */
    const struct block_header *hdr=(const struct block_header *)&buffer[i];
    const unsigned int block_size=be32(hdr->BlockSize);
#ifdef DEBUG_BACULA
    const unsigned int block_nbr=be32(hdr->BlockNumber);
    log_trace("file_bac.c: block %u size %u, calculated_file_size %llu\n",
	block_nbr, block_size,
	(long long unsigned)file_recovery->calculated_file_size);
#endif
    if(memcmp(hdr->ID, "BB02", 4)!=0 || block_size<0x18)
    {
#ifndef DISABLED_FOR_FRAMAC
      log_error("file_bac.c: invalid block at %llu\n",
	  (long long unsigned)file_recovery->calculated_file_size);
#endif
      return DC_STOP;
    }
    file_recovery->calculated_file_size+=(uint64_t)block_size;
  }
#ifdef DEBUG_BACULA
  log_trace("file_bac.c: new calculated_file_size %llu\n",
      (long long unsigned)file_recovery->calculated_file_size);
#endif
  return DC_CONTINUE;
}

/*@
  @ requires buffer_size >= sizeof(struct block_header);
  @ requires separation: \separated(&file_hint_bac, buffer, file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ ensures (\result == 1) ==> (file_recovery_new->time == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->calculated_file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->data_check == \null || file_recovery_new->data_check == &data_check_bac);
  @ ensures (\result == 1) ==> (file_recovery_new->file_check == \null || file_recovery_new->file_check == &file_check_size);
  @ ensures (\result == 1) ==> (file_recovery_new->extension == file_hint_bac.extension);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_bac(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct block_header *hdr=(const struct block_header *)buffer;
  if(be32(hdr->BlockSize) < 0x18)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_bac.extension;
  file_recovery_new->min_filesize=be32(hdr->BlockSize);
  file_recovery_new->calculated_file_size=0;
  if(file_recovery_new->blocksize >= 0x18)
  {
    file_recovery_new->data_check=&data_check_bac;
    file_recovery_new->file_check=&file_check_size;
  }
  return 1;
}

static void register_header_check_bac(file_stat_t *file_stat)
{
  static const unsigned char bac_header[8]={ 0, 0, 0, 0, 'B', 'B', '0', '2' };
  register_header_check(8, bac_header, sizeof(bac_header), &header_check_bac, file_stat);
}
#endif
