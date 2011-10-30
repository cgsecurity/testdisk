/*

    File: file_pyc.c

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
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#include <stdio.h>
#include "types.h"
#include "common.h"
#include "filegen.h"

static void register_header_check_pyc(file_stat_t *file_stat);
static int header_check_pyc(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_pyc= {
  .extension="pyc",
  .description="Python Compiled Script",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_pyc
};

static const unsigned char pyc_15_magic[4]= { 0x99, 0x4e, '\r', '\n'};
static const unsigned char pyc_20_magic[4]= { 0x87, 0xc6, '\r', '\n'};
static const unsigned char pyc_21_magic[4]= { 0x2a, 0xeb, '\r', '\n'};
static const unsigned char pyc_22_magic[4]= { 0x2d, 0xed, '\r', '\n'};
static const unsigned char pyc_23_magic[4]= { 0x3b, 0xf2, '\r', '\n'};
static const unsigned char pyc_24_magic[4]= { 0x6d, 0xf2, '\r', '\n'};
static const unsigned char pyc_25_magic[4]= { 0xb3, 0xf2, '\r', '\n'};
static const unsigned char pyc_26_magic[4]= { 0xd1, 0xf2, '\r', '\n'};
static const unsigned char pyc_27_magic[4]= { 0x03, 0xf3, '\r', '\n'};
static const unsigned char pyc_30_magic[4]= { 0x3b, 0x0c, '\r', '\n'};
static const unsigned char pyc_31_magic[4]= { 0x4f, 0x0c, '\r', '\n'};
static const unsigned char pyc_32_magic[4]= { 0x6c, 0x0c, '\r', '\n'};

struct pyc_header {
  uint32_t magic_number;
  uint32_t modtime;
};

static void register_header_check_pyc(file_stat_t *file_stat)
{
  register_header_check(0, pyc_15_magic, sizeof(pyc_15_magic), &header_check_pyc, file_stat);
  register_header_check(0, pyc_20_magic, sizeof(pyc_20_magic), &header_check_pyc, file_stat);
  register_header_check(0, pyc_21_magic, sizeof(pyc_21_magic), &header_check_pyc, file_stat);
  register_header_check(0, pyc_22_magic, sizeof(pyc_22_magic), &header_check_pyc, file_stat);
  register_header_check(0, pyc_23_magic, sizeof(pyc_23_magic), &header_check_pyc, file_stat);
  register_header_check(0, pyc_24_magic, sizeof(pyc_24_magic), &header_check_pyc, file_stat);
  register_header_check(0, pyc_25_magic, sizeof(pyc_25_magic), &header_check_pyc, file_stat);
  register_header_check(0, pyc_26_magic, sizeof(pyc_26_magic), &header_check_pyc, file_stat);
  register_header_check(0, pyc_27_magic, sizeof(pyc_27_magic), &header_check_pyc, file_stat);
  register_header_check(0, pyc_30_magic, sizeof(pyc_30_magic), &header_check_pyc, file_stat);
  register_header_check(0, pyc_31_magic, sizeof(pyc_31_magic), &header_check_pyc, file_stat);
  register_header_check(0, pyc_32_magic, sizeof(pyc_32_magic), &header_check_pyc, file_stat);
}

static int header_check_pyc(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct pyc_header *pyc=(const struct pyc_header *)buffer;
  /* marshalled code object must be of of type TYPE_CODE and argcount < 256 */
  if(buffer[8]!='c' || buffer[9]!=0 || buffer[10]!=0 || buffer[11]!=0)
    return 0;
  switch(be32(pyc->magic_number))
  {
    case 0x994e0d0a:	/* 1.5 */
    case 0x87c60d0a:	/* 2.0 */
    case 0x2aeb0d0a:	/* 2.1 */
    case 0x2ded0d0a:	/* 2.2 */
    case 0x3bf20d0a:	/* 2.3 */
    case 0x6df20d0a:	/* 2.4 */
    case 0xb3f20d0a:	/* 2.5 */
    case 0xd1f20d0a:	/* 2.6 */
    case 0x03f30d0a:  	/* 2.7 */
    case 0x3b0c0d0a:	/* 3.0 */
    case 0x4f0c0d0a:	/* 3.1 */
    case 0x6c0c0d0a:	/* 3.2 */
      reset_file_recovery(file_recovery_new);
      file_recovery_new->extension=file_hint_pyc.extension;
      file_recovery_new->time=le32(pyc->modtime);
      return 1;
  }
  return 0;
}
