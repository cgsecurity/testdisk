/*

    File: file_gm6.c

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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "filegen.h"

static void register_header_check_gm6(file_stat_t *file_stat);

const file_hint_t file_hint_gm6= {
  .extension="gm*",
  .description="Game Maker (4.3 - 8.1)",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_gm6
};

//Version 8.1 file (.gm81)
static int header_check_gm81(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension="gm81";
  return 1;
}

//Version 7.0-8.0 file (.gmk)
static int header_check_gmk(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension="gmk";
  return 1;
}

//Version 6.0-6.1 file (.gm6)
static int header_check_gm6(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension="gm6";
  return 1;
}

//Version 4.3-5.3A file (.gmd)
static int header_check_gmd(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension="gmd";
  return 1;
}

static void register_header_check_gm6(file_stat_t *file_stat)
{
  /*
  These are the headers that identify Game Maker files for 8.1 and earlier.
  First set of 4 bytes: Little-endian, constant 1234321 (decimal)
  Second set of 4 bytes: Little-endian, Version identifier
  Source: "Binary Format of GameMaker Save Files (gmd, gm6, gmk)" by IsmAvatar
  URL: http://ismavatar.com/lgm/formats/gmformat7.txt
  */
  //Version 8.1 (.gm81)
  static const unsigned char gm81_header[8] = {
    0x91, 0xd5, 0x12, 0x00, 0x2a, 0x03, 0x00, 0x00
  };
  //Version 8.0 (.gmk)
  static const unsigned char gm80_header[8] = {
    0x91, 0xd5, 0x12, 0x00, 0x20, 0x03, 0x00, 0x00
  };
  //Version 7.0 variant 2 (.gmk)
  static const unsigned char gm72_header[8] = {
    0x91, 0xd5, 0x12, 0x00, 0xbe, 0x02, 0x00, 0x00
  };
  //Version 7.0 variant 1 (.gmk)
  static const unsigned char gm71_header[8] = {
    0x91, 0xd5, 0x12, 0x00, 0xbd, 0x02, 0x00, 0x00
  };
  //Version 7.0 early variant (.gmk)
  static const unsigned char gm62_header[8] = {
    0x91, 0xd5, 0x12, 0x00, 0x6c, 0x02, 0x00, 0x00
  };
  //Version 6.0-6.1 (.gm6)
  static const unsigned char gm60_header[8] = {
    0x91, 0xd5, 0x12, 0x00, 0x58, 0x02, 0x00, 0x00
  };
  //Version 5.3 (.gmd)
  static const unsigned char gm53_header[8] = {
    0x91, 0xd5, 0x12, 0x00, 0x12, 0x02, 0x00, 0x00
  };
  //Version 5.2 (.gmd)
  static const unsigned char gm52_header[8] = {
    0x91, 0xd5, 0x12, 0x00, 0x08, 0x02, 0x00, 0x00
  };
  //Version 5.1 (.gmd)
  static const unsigned char gm51_header[8] = {
    0x91, 0xd5, 0x12, 0x00, 0xfe, 0x01, 0x00, 0x00
  };
  //Version 5.0 (.gmd)
  static const unsigned char gm50_header[8] = {
    0x91, 0xd5, 0x12, 0x00, 0xf4, 0x01, 0x00, 0x00
  };
  //Version 4.3 (.gmd)
  static const unsigned char gm43_header[8] = {
    0x91, 0xd5, 0x12, 0x00, 0xae, 0x01, 0x00, 0x00
  };

  //Register all variant header signatures with respective extensions
  register_header_check(0, gm81_header, sizeof(gm81_header), &header_check_gm81, file_stat);
  register_header_check(0, gm80_header, sizeof(gm80_header), &header_check_gmk, file_stat);
  register_header_check(0, gm72_header, sizeof(gm72_header), &header_check_gmk, file_stat);
  register_header_check(0, gm71_header, sizeof(gm71_header), &header_check_gmk, file_stat);
  register_header_check(0, gm62_header, sizeof(gm62_header), &header_check_gmk, file_stat);
  register_header_check(0, gm60_header, sizeof(gm60_header), &header_check_gm6, file_stat);
  register_header_check(0, gm53_header, sizeof(gm53_header), &header_check_gmd, file_stat);
  register_header_check(0, gm52_header, sizeof(gm52_header), &header_check_gmd, file_stat);
  register_header_check(0, gm51_header, sizeof(gm51_header), &header_check_gmd, file_stat);
  register_header_check(0, gm50_header, sizeof(gm50_header), &header_check_gmd, file_stat);
  register_header_check(0, gm43_header, sizeof(gm43_header), &header_check_gmd, file_stat);
}
