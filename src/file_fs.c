/*

    File: file_fs.c

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fs)
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
#include "common.h"
#include "log.h"

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_fs(file_stat_t *file_stat);

const file_hint_t file_hint_fs= {
  .extension="fs",
  .description="Zope",
  .max_filesize=200*1024*1024,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_fs
};

/* See http://www.linkitsolutions.org/uploader/dilu/lib/python2.6/site-packages/ZODB/FileStorage/FileStorage.py for more information */
struct transaction_header
{
  uint64_t id;
  uint64_t len;
  char     status;
  uint16_t len_username;
  uint16_t len_descr;
  uint16_t len_ext;
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires file_recovery->data_check==&data_check_fs;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ terminates \true;
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ assigns file_recovery->calculated_file_size;
  @*/
static data_check_t data_check_fs(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@
    @ loop assigns file_recovery->calculated_file_size;
    @ loop variant file_recovery->file_size + buffer_size/2 - (file_recovery->calculated_file_size + 0x11);
    @*/
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 0x11 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size + buffer_size/2 - file_recovery->file_size;
    /*@ assert 0 <= i < buffer_size - 0x11; */
    const struct transaction_header *hdr=(const struct transaction_header *)&buffer[i];
    const uint64_t len=be64(hdr->len);
    if(len < sizeof(struct transaction_header)-8)
      return DC_STOP;
    if(hdr->status!=' ' && hdr->status!='p' && hdr->status!='c' &&  hdr->status!='u')
      return DC_STOP;
    if(len > PHOTOREC_MAX_FILE_SIZE)
      return DC_STOP;
#ifdef DEBUG_FS
    log_info("0x%08llx len=%llu status=%c\n", (long long unsigned)file_recovery->calculated_file_size, (long long unsigned)len, hdr->status);
#endif
    file_recovery->calculated_file_size+=(uint64_t)8+len;
#ifdef DEBUG_FS
    log_info("0x%08llx\n", (long long unsigned)file_recovery->calculated_file_size);
#endif
  }
  return DC_CONTINUE;
}

/*@
  @ requires buffer_size >= sizeof(struct transaction_header);
  @ requires separation: \separated(&file_hint_fs, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_fs(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct transaction_header *hdr=(const struct transaction_header *)&buffer[4];
  const uint64_t len=be64(hdr->len);
  if(len < sizeof(struct transaction_header)-8)
    return 0;
  if(hdr->status!=' ' && hdr->status!='p' && hdr->status!='c' &&  hdr->status!='u')
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_fs.extension;
  if(file_recovery_new->blocksize < 0x11)
    return 1;
  file_recovery_new->data_check=&data_check_fs;
  file_recovery_new->file_check=&file_check_size;
  file_recovery_new->calculated_file_size=4;
  return 1;
}

static void register_header_check_fs(file_stat_t *file_stat)
{
  static const unsigned char fs_header[4]={ 'F', 'S','2','1' };
  register_header_check(0, fs_header,sizeof(fs_header), &header_check_fs, file_stat);
}
#endif
