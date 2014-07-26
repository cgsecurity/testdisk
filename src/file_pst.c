/*

    File: file_pst.c

    Copyright (C) 2006-2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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


static void register_header_check_pst(file_stat_t *file_stat);
static int header_check_pst(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_pst= {
  .extension="pst",
  .description="Outlook (pst/wab/dbx)",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_pst
};

#define INDEX_TYPE_OFFSET 	0x0A
#define FILE_SIZE_POINTER 	0xA8
#define FILE_SIZE_POINTER_64 	0xB8
#define DBX_SIZE_POINTER	0x7C

static int header_check_dbx(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const uint64_t size=(uint64_t)buffer[DBX_SIZE_POINTER] +
    (((uint64_t)buffer[DBX_SIZE_POINTER+1])<<8) +
    (((uint64_t)buffer[DBX_SIZE_POINTER+2])<<16) +
    (((uint64_t)buffer[DBX_SIZE_POINTER+3])<<24);
  if(size < DBX_SIZE_POINTER + 4)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension="dbx";
  file_recovery_new->calculated_file_size=size;
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

/*
   Outlook 2000
   0x0000 uchar signature[4];
   0x000a uchar indexType;
   0x00a8 uint32_t total_file_size;
   0x00b8 uint32_t backPointer2;
   0x00bc uint32_t offsetIndex2;
   0x00c0 uint32_t backPointer1;
   0x00c4 uint32_t offsetIndex1;
   0x01cd uchar encryptionType;

   Outlook 2003
   0x0000 uchar signature[4];
   0x000a uchar indexType;
   0x00b8 uint64_t total_file_size;
   0x00d8 uint64_t backPointer2;
   0x00e0 uint64_t offsetIndex2;
   0x00e8 uint64_t backPointer1;
   0x00f0 uint64_t offsetIndex1;
   0x0201 uchar encryptionType;

   More information about the file structure can be found at
   http://www.ﬁve-ten-sg.com/libpst/
*/

static int header_check_wab(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension="wab";	/* Adresse Book */
  return 1;
}

static int header_check_pst(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(buffer[INDEX_TYPE_OFFSET]==0x0e ||
      buffer[INDEX_TYPE_OFFSET]==0x0f)
  {
    const uint64_t size=(uint64_t)buffer[FILE_SIZE_POINTER] +
      (((uint64_t)buffer[FILE_SIZE_POINTER+1])<<8) +
      (((uint64_t)buffer[FILE_SIZE_POINTER+2])<<16) +
      (((uint64_t)buffer[FILE_SIZE_POINTER+3])<<24);
    if(size < 0x1cd)
      return 0;
    /* Outlook 2000 and older versions */
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_pst.extension;
    file_recovery_new->calculated_file_size=size;
    file_recovery_new->data_check=&data_check_size;
    file_recovery_new->file_check=&file_check_size;
    return 1;
  }
  else
    //      if(buffer[INDEX_TYPE_OFFSET]==0x15 || buffer[INDEX_TYPE_OFFSET]==0x17)
  { /* Outlook 2003 */
    const uint64_t size=(uint64_t)buffer[FILE_SIZE_POINTER_64] +
      (((uint64_t)buffer[FILE_SIZE_POINTER_64+1])<<8) +
      (((uint64_t)buffer[FILE_SIZE_POINTER_64+2])<<16) +
      (((uint64_t)buffer[FILE_SIZE_POINTER_64+3])<<24) +
      (((uint64_t)buffer[FILE_SIZE_POINTER_64+4])<<32) +
      (((uint64_t)buffer[FILE_SIZE_POINTER_64+5])<<40) +
      (((uint64_t)buffer[FILE_SIZE_POINTER_64+6])<<48) +
      (((uint64_t)buffer[FILE_SIZE_POINTER_64+7])<<56);
    if(size < 0x201)
      return 0;
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_pst.extension;
    file_recovery_new->calculated_file_size=size;
    file_recovery_new->data_check=&data_check_size;
    file_recovery_new->file_check=&file_check_size;
    return 1;
  }
}

static void register_header_check_pst(file_stat_t *file_stat)
{
  static  const unsigned char dbx_header[4]= { 0xCF, 0xAD, 0x12, 0xFE };
  static  const unsigned char wab_header[16] = { 0x9c, 0xcb, 0xcb, 0x8d, 0x13, 0x75, 0xd2, 0x11,
    0x91, 0x58, 0x00, 0xc0, 0x4f, 0x79, 0x56, 0xa4 };
  register_header_check(0, "!BDN", 4, &header_check_pst, file_stat);
  register_header_check(0, dbx_header,sizeof(dbx_header), &header_check_dbx, file_stat);
  register_header_check(0, wab_header,sizeof(wab_header), &header_check_wab, file_stat);
}
