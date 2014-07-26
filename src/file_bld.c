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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "filegen.h"
#include "log.h"

static void register_header_check_blend(file_stat_t *file_stat);
static int header_check_blend(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);
static data_check_t data_check_blend4le(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery);
static data_check_t data_check_blend8le(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery);
static data_check_t data_check_blend4be(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery);
static data_check_t data_check_blend8be(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery);

const file_hint_t file_hint_blend= {
  .extension="blend",
  .description="blender",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_blend
};

static const unsigned char blend_header[7]  = { 'B', 'L', 'E', 'N', 'D', 'E', 'R'};
static const unsigned char blend_header_footer[4]  = { 'E', 'N', 'D', 'B'};

static void register_header_check_blend(file_stat_t *file_stat)
{
  register_header_check(0, blend_header,sizeof(blend_header), &header_check_blend, file_stat);
}

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

static data_check_t data_check_blend4le(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 0x14 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size - file_recovery->file_size + buffer_size/2;
    const unsigned int len=buffer[i+4]+ ((buffer[i+5])<<8)+ ((buffer[i+6])<<16)+ ((buffer[i+7])<<24);
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
    file_recovery->calculated_file_size+=0x14+len;
  }
  return DC_CONTINUE;
}

static data_check_t data_check_blend8le(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  while(file_recovery->calculated_file_size + 0x18 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size - file_recovery->file_size + buffer_size/2;
    const unsigned int len=buffer[i+4]+ ((buffer[i+5])<<8)+ ((buffer[i+6])<<16)+ ((buffer[i+7])<<24);
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
    file_recovery->calculated_file_size+=0x18+len;
  }
  return DC_CONTINUE;
}

static data_check_t data_check_blend4be(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  while(file_recovery->calculated_file_size + 0x14 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size - file_recovery->file_size + buffer_size/2;
    const unsigned int len=(buffer[i+4]<<24)+ ((buffer[i+5])<<16)+ ((buffer[i+6])<<8)+ buffer[i+7];
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
    file_recovery->calculated_file_size+=0x14+len;
  }
  return DC_CONTINUE;
}

static data_check_t data_check_blend8be(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  while(file_recovery->calculated_file_size + 0x18 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size - file_recovery->file_size + buffer_size/2;
    const unsigned int len=(buffer[i+4]<<24)+ ((buffer[i+5])<<16)+ ((buffer[i+6])<<8)+ buffer[i+7];
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
    file_recovery->calculated_file_size+=0x18+len;
  }
  return DC_CONTINUE;
}
