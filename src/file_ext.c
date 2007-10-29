/*

    File: file_ext2_sb.c

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
#include "types.h"
#include "common.h"
#include "ext2.h"
#include "filegen.h"

static void register_header_check_ext2_sb(file_stat_t *file_stat);
static int header_check_ext2_sb(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_ext2_sb= {
  .extension="",
  .description="EXT2/EXT3 Superblock",
  .min_header_distance=0,
  .max_filesize=1,
  .recover=0,
  .header_check=&header_check_ext2_sb,
  .register_header_check=&register_header_check_ext2_sb
};

static const unsigned char ext2_sb_header[2]= {0x53, 0xEF};

static void register_header_check_ext2_sb(file_stat_t *file_stat)
{
  register_header_check(0x38, ext2_sb_header,sizeof(ext2_sb_header), &header_check_ext2_sb, file_stat);
}

static int header_check_ext2_sb(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(recover_EXT2(NULL,(const struct ext2_super_block *)buffer,NULL,0,0)==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_ext2_sb.extension;
    return 1;
  }
  return 0;
}

