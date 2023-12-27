/*

    File: file_bld.c

    Copyright (C) 2006-2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_blend)
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
#include "log.h"

/*@
  @ requires valid_register_header_check(file_stat);
  @*/
static void register_header_check_blend(file_stat_t *file_stat);

const file_hint_t file_hint_blend= {
  .extension="blend",
  .description="blender",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_blend
};

static const unsigned char blend_header_footer[4]  = { 'E', 'N', 'D', 'B'};

struct blend4_block
{
  char		code[4];
  uint32_t	size;
  uint32_t	old_address;
  uint32_t	SDNA_index;
  uint32_t	count;
} __attribute__ ((gcc_struct, __packed__));

struct blend8_block
{
  char		code[4];
  uint32_t	size;
  uint64_t	old_address;
  uint32_t	SDNA_index;
  uint32_t	count;
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires file_recovery->data_check==&data_check_blend4le;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ assigns  file_recovery->calculated_file_size;
  @*/
static data_check_t data_check_blend4le(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@
    @ loop assigns file_recovery->calculated_file_size;
    @ loop variant file_recovery->file_size + buffer_size/2 - (file_recovery->calculated_file_size + 0x14);
    @*/
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 0x14 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size + buffer_size/2 - file_recovery->file_size;
    /*@ assert 0 <= i < buffer_size - 0x14; */
    const struct blend4_block *blk=(const struct blend4_block *)&buffer[i];
    const unsigned int len=le32(blk->size);
#ifdef DEBUG_BLEND
    log_debug("file_mov.c: atom %c%c%c%c (0x%02x%02x%02x%02x) size %u, calculated_file_size %llu\n",
        buffer[i+0],buffer[i+1],buffer[i+2],buffer[i+3],
        buffer[i+0],buffer[i+1],buffer[i+2],buffer[i+3],
        len,
        (long long unsigned)file_recovery->calculated_file_size);
#endif
    if(memcmp(&buffer[i],blend_header_footer,sizeof(blend_header_footer))==0)
    {
      file_recovery->calculated_file_size+=0x14;
      return DC_STOP;
    }
    file_recovery->calculated_file_size+=(uint64_t)0x14+len;
  }
  return DC_CONTINUE;
}

/*@
  @ requires file_recovery->data_check==&data_check_blend8le;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ assigns file_recovery->calculated_file_size;
  @*/
static data_check_t data_check_blend8le(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
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
    /*@ assert 0 <= i < buffer_size - 0x18; */
    const struct blend8_block *blk=(const struct blend8_block *)&buffer[i];
    const unsigned int len=le32(blk->size);
#ifdef DEBUG_BLEND
    log_debug("file_mov.c: atom %c%c%c%c (0x%02x%02x%02x%02x) size %u, calculated_file_size %llu\n",
        buffer[i+0],buffer[i+1],buffer[i+2],buffer[i+3],
        buffer[i+0],buffer[i+1],buffer[i+2],buffer[i+3],
        len,
        (long long unsigned)file_recovery->calculated_file_size);
#endif
    if(memcmp(&buffer[i],blend_header_footer,sizeof(blend_header_footer))==0)
    {
      file_recovery->calculated_file_size+=0x18;
      return DC_STOP;
    }
    file_recovery->calculated_file_size+=(uint64_t)0x18+len;
  }
  return DC_CONTINUE;
}

/*@
  @ requires file_recovery->data_check==&data_check_blend4be;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ assigns file_recovery->calculated_file_size;
  @*/
static data_check_t data_check_blend4be(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@
    @ loop assigns file_recovery->calculated_file_size;
    @ loop variant file_recovery->file_size + buffer_size/2 -(file_recovery->calculated_file_size + 0x14);
    @*/
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 0x14 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size + buffer_size/2 - file_recovery->file_size;
    /*@ assert 0 <= i < buffer_size - 0x14; */
    const struct blend4_block *blk=(const struct blend4_block *)&buffer[i];
    const unsigned int len=be32(blk->size);
    /*@ assert len <= 0xffffffff; */
#ifdef DEBUG_BLEND
    log_debug("file_mov.c: atom %c%c%c%c (0x%02x%02x%02x%02x) size %u, calculated_file_size %llu\n",
        buffer[i+0],buffer[i+1],buffer[i+2],buffer[i+3],
        buffer[i+0],buffer[i+1],buffer[i+2],buffer[i+3],
        len,
        (long long unsigned)file_recovery->calculated_file_size);
#endif
    if(memcmp(&buffer[i],blend_header_footer,sizeof(blend_header_footer))==0)
    {
      file_recovery->calculated_file_size+=0x14;
      return DC_STOP;
    }
    file_recovery->calculated_file_size+=(uint64_t)0x14+len;
  }
  return DC_CONTINUE;
}

/*@
  @ requires file_recovery->data_check==&data_check_blend8be;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ assigns file_recovery->calculated_file_size;
  @*/
static data_check_t data_check_blend8be(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@
    @ loop assigns file_recovery->calculated_file_size;
    @ loop variant file_recovery->file_size + buffer_size/2 - (file_recovery->calculated_file_size + 0x18);
    @ */
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 0x18 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size + buffer_size/2 - file_recovery->file_size;
    /*@ assert 0 <= i < buffer_size - 0x18; */
    const struct blend8_block *blk=(const struct blend8_block *)&buffer[i];
    const unsigned int len=be32(blk->size);
    /*@ assert len <= 0xffffffff; */
#ifdef DEBUG_BLEND
    log_debug("file_mov.c: atom %c%c%c%c (0x%02x%02x%02x%02x) size %u, calculated_file_size %llu\n",
        buffer[i+0],buffer[i+1],buffer[i+2],buffer[i+3],
        buffer[i+0],buffer[i+1],buffer[i+2],buffer[i+3],
        len,
        (long long unsigned)file_recovery->calculated_file_size);
#endif
    if(memcmp(&buffer[i],blend_header_footer,sizeof(blend_header_footer))==0)
    {
      file_recovery->calculated_file_size+=0x18;
      return DC_STOP;
    }
    file_recovery->calculated_file_size+=(uint64_t)0x18+len;
  }
  return DC_CONTINUE;
}

/*@
  @ requires buffer_size >= 8;
  @ requires separation: \separated(&file_hint_blend, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ ensures (\result == 1) ==> file_recovery_new->file_size == 0;
  @ ensures (\result == 1) ==> (file_recovery_new->time == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->calculated_file_size == 12);
  @ ensures (\result == 1) ==> (file_recovery_new->extension == file_hint_blend.extension);
  @ ensures (\result == 1) ==> (file_recovery_new->data_check == &data_check_blend4be ||
    file_recovery_new->data_check == &data_check_blend4le ||
    file_recovery_new->data_check == &data_check_blend8be ||
    file_recovery_new->data_check == &data_check_blend8le
  );
  @ ensures (\result == 1) ==> (file_recovery_new->file_check == &file_check_size);
  @ ensures (\result == 1) ==> (file_recovery_new->file_rename == \null);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_blend(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(buffer[7]!='_' && buffer[7]!='-')
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_blend.extension;
  if(file_recovery_new->blocksize < 0x14)
    return 1;
  file_recovery_new->calculated_file_size=12;
  if(buffer[8]=='v')
  { /* Little endian */
    if(buffer[7]=='_')
      file_recovery_new->data_check=&data_check_blend4le;
    else
      file_recovery_new->data_check=&data_check_blend8le;
  }
  else
  { /* Big endian */
    if(buffer[7]=='_')
      file_recovery_new->data_check=&data_check_blend4be;
    else
      file_recovery_new->data_check=&data_check_blend8be;
  }
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static void register_header_check_blend(file_stat_t *file_stat)
{
  static const unsigned char blend_header[7]  = { 'B', 'L', 'E', 'N', 'D', 'E', 'R'};
  register_header_check(0, blend_header,sizeof(blend_header), &header_check_blend, file_stat);
}
#endif
