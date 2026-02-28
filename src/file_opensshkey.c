/*

    File: file_opensshkey.c

    Copyright (C) 2024 Christophe GRENIER <grenier@cgsecurity.org>

    OpenSSH private key format (new-format):
    https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_opensshkey)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "filegen.h"

#define MAX_OPENSSHKEY_SIZE (16*1024)

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_opensshkey(file_stat_t *file_stat);

const file_hint_t file_hint_opensshkey= {
  .extension="key",
  .description="OpenSSH private key",
  .max_filesize=MAX_OPENSSHKEY_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_opensshkey
};

/*@
  @ requires buffer_size >= 35;
  @ requires separation: \separated(&file_hint_opensshkey, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_opensshkey(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /* PEM header "-----BEGIN OPENSSH PRIVATE KEY-----" (35 bytes) */
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_opensshkey.extension;
  file_recovery_new->min_filesize=35;
  return 1;
}

static void register_header_check_opensshkey(file_stat_t *file_stat)
{
  /* "-----BEGIN OPENSSH PRIVATE KEY-----" */
  static const unsigned char openssh_magic[35]= {
    '-','-','-','-','-',
    'B','E','G','I','N',' ',
    'O','P','E','N','S','S','H',' ',
    'P','R','I','V','A','T','E',' ',
    'K','E','Y',
    '-','-','-','-','-'
  };
  register_header_check(0, openssh_magic, sizeof(openssh_magic), &header_check_opensshkey, file_stat);
}
#endif
