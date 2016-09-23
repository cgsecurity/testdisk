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

static void register_header_check_tar(file_stat_t *file_stat);

const file_hint_t file_hint_tar= {
  .extension="tar",
  .description="tar archive",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_tar
};

struct posix_header
{				/* byte offset */
  char name[100];		/*   0 */
  char mode[8];			/* 100 */
  char uid[8];			/* 108 */
  char gid[8];			/* 116 */
  char size[12];		/* 124 */
  char mtime[12];		/* 136 */
  char chksum[8];		/* 148 */
  char typeflag;		/* 156 */
  char linkname[100];		/* 157 */
  char magic[6];		/* 257 */
  char version[2];		/* 263 */
  char uname[32];		/* 265 */
  char gname[32];		/* 297 */
  char devmajor[8];		/* 329 */
  char devminor[8];		/* 337 */
  char prefix[155];		/* 345 */
				/* 500 */
};

int header_check_tar(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct posix_header *h=(const struct posix_header *)buffer;
  if(!isspace(h->chksum[0]) && !((unsigned) (h->chksum[0]) - '0' <= 7))
    return 0;
  if(file_recovery->file_stat!=NULL && file_recovery->file_stat->file_hint==&file_hint_tar)
  {
    /* header_ignored(file_recovery_new); is useless as there is no file check */
    return 0;
  }
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_tar.extension;
  file_recovery_new->min_filesize=512;
  return 1;
}

static void register_header_check_tar(file_stat_t *file_stat)
{
  static const unsigned char tar_header_gnu[6]	= { 'u','s','t','a','r',0x00};
  static const unsigned char tar_header_posix[8]  = { 'u','s','t','a','r',' ',' ',0x00};
  register_header_check(0x101, tar_header_gnu,sizeof(tar_header_gnu), &header_check_tar, file_stat);
  register_header_check(0x101, tar_header_posix,sizeof(tar_header_posix), &header_check_tar, file_stat);
}
