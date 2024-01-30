/*

    File: file_tar.c

    Copyright (C) 1998-2005,2007 Christophe GRENIER <grenier@cgsecurity.org>

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_tar)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include <ctype.h>
#include "types.h"
#include "filegen.h"
#include "file_tar.h"

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_tar(file_stat_t *file_stat);
static const unsigned char tar_header_gnu[6] = { 'u', 's', 't', 'a', 'r', 0x00 };
static const unsigned char tar_header_posix[8] = { 'u', 's', 't', 'a', 'r', ' ', ' ', 0x00 };

const file_hint_t file_hint_tar = {
  .extension = "tar",
  .description = "tar archive",
  .max_filesize = PHOTOREC_MAX_FILE_SIZE,
  .recover = 1,
  .enable_by_default = 1,
  .register_header_check = &register_header_check_tar
};

/*@
  @ requires \valid_read(h);
  @ terminates \true;
  @ assigns \nothing;
  @*/
static int is_valid_checksum_format(const struct tar_posix_header *h)
{
  unsigned int i;
  int space_allowed = 1;
  int all_null = 1;
  /* No checksum ? */
  /*@
    @ loop assigns i,all_null;
    @ loop variant 8 - i;
    @*/
  for(i = 0; i < 8; i++)
    if(h->chksum[i] != 0)
      all_null = 0;
  if(all_null != 0)
    return 1;
  /*
   * Checksum should be stored as a six digit octal number with leading zeroes followed by a NUL and then a space.
   * Various implementations do not adhere to this format, try to handle them
   */
  /*@
    @ loop assigns i,space_allowed;
    @ loop variant 6 - i;
    @*/
  for(i = 0; i < 6; i++)
  {
    if(h->chksum[i] >= '0' || h->chksum[i] <= '7')
    {
      space_allowed = 0;
      continue;
    }
    if(h->chksum[i] == ' ')
    {
      if(space_allowed == 0)
        return 0;
    }
    else
      return 0;
  }
  if(h->chksum[6] == 0 || h->chksum[7] == ' ')
    return 1;
  if((h->chksum[6] >= '0' || h->chksum[6] <= '7') && h->chksum[7] == ' ')
    return 1;
  return 0;
}

int is_valid_tar_header(const struct tar_posix_header *h)
{
  /* Do not remove this check. */
  if(memcmp(&h->magic, tar_header_gnu, sizeof(tar_header_gnu)) != 0 && memcmp(&h->magic, tar_header_posix, sizeof(tar_header_posix)) != 0)
    return 0;
  if(is_valid_checksum_format(h) == 0)
    return 0;
  return 1;
}

/*@
  @ requires buffer_size >= sizeof(struct tar_posix_header);
  @ requires separation: \separated(&file_hint_tar, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_tar(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /*@ assert valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new); */
  const struct tar_posix_header *h = (const struct tar_posix_header *)buffer;
  if(is_valid_tar_header(h) == 0)
    return 0;
  /*@ assert \valid_read(file_recovery); */
  if(file_recovery->file_stat != NULL && file_recovery->file_stat->file_hint == &file_hint_tar)
  {
    /* header_ignored(file_recovery_new); is useless as there is no file check */
    return 0;
  }
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension = file_hint_tar.extension;
  file_recovery_new->min_filesize = 512;
  /*@ assert valid_file_recovery(file_recovery_new); */
  return 1;
}

/*@
  @ requires valid_register_header_check(file_stat);
  @*/
static void register_header_check_tar(file_stat_t *file_stat)
{
  register_header_check(0x101, tar_header_gnu, sizeof(tar_header_gnu), &header_check_tar, file_stat);
#ifndef DISABLED_FOR_FRAMAC
  register_header_check(0x101, tar_header_posix, sizeof(tar_header_posix), &header_check_tar, file_stat);
#endif
}
#endif
