/*

    File: file_psd.c

    Copyright (C) 2006-2009 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include "common.h"

#ifdef DEBUG_PSD
#include "log.h"
#endif

static void register_header_check_psd(file_stat_t *file_stat);
static int header_check_psd(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);
static int psd_skip_color_mode(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery);
static void file_check_psd(file_recovery_t *file_recovery);

const file_hint_t file_hint_psd= {
  .extension="psd",
  .description="Adobe Photoshop Image",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_psd
};

static const unsigned char psd_header[6]={'8', 'B', 'P', 'S', 0x00, 0x01};
static uint64_t psd_image_data_size_max=0;

static void register_header_check_psd(file_stat_t *file_stat)
{
  register_header_check(0, psd_header,sizeof(psd_header), &header_check_psd, file_stat);
}

static int header_check_psd(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(buffer,psd_header,sizeof(psd_header))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->min_filesize=70;
    file_recovery_new->extension=file_hint_psd.extension;
    /* File header */
    file_recovery_new->calculated_file_size=0x1a;
    file_recovery_new->data_check=&psd_skip_color_mode;
    file_recovery_new->file_check=&file_check_psd;
    return 1;
  }
  return 0;
}

static uint32_t get_be32(const void *buffer, const unsigned int offset)
{
  const uint32_t *val=(const uint32_t *)((const unsigned char *)buffer+offset);
  return be32(*val);
}

static int psd_skip_image_data(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  file_recovery->file_check=NULL;
  return 1;
}

static int psd_skip_layer_info(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 16 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size - file_recovery->file_size + buffer_size/2;
    const unsigned int l=get_be32(buffer, i)+4;
#ifdef DEBUG_PSD
    log_info("Image data at 0x%lx\n", (long unsigned)(l + file_recovery->calculated_file_size));
#endif
    if(l<4)
      return 2;
    file_recovery->calculated_file_size+=l;
    file_recovery->data_check=&psd_skip_image_data;
    return psd_skip_image_data(buffer, buffer_size, file_recovery);
  }
  return 1;
}

static int psd_skip_image_resources(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 16 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size - file_recovery->file_size + buffer_size/2;
    const unsigned int l=get_be32(buffer, i)+4;
#ifdef DEBUG_PSD
    log_info("Layer info at 0x%lx\n", (long unsigned)(l + file_recovery->calculated_file_size));
#endif
    if(l<4)
      return 2;
    file_recovery->calculated_file_size+=l;
    file_recovery->data_check=&psd_skip_layer_info;
    return psd_skip_layer_info(buffer, buffer_size, file_recovery);
  }
  return 1;
}

static int psd_skip_color_mode(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  psd_image_data_size_max=(buffer[buffer_size/2+12]<<8 | buffer[buffer_size/2+13]) *
    (buffer[buffer_size/2+14]<<24 | buffer[buffer_size/2+15] <<16 | buffer[buffer_size/2+16]<<8 | buffer[buffer_size/2+17]) *
    (buffer[buffer_size/2+18]<<24 | buffer[buffer_size/2+19] <<16 | buffer[buffer_size/2+20]<<8 | buffer[buffer_size/2+21]) *
    buffer[buffer_size/2+23] / 8;
#ifdef DEBUG_PSD
  log_info("psd_image_data_size_max %lu\n", (long unsigned)psd_image_data_size_max);
#endif
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 16 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size - file_recovery->file_size + buffer_size/2;
    const unsigned int l=get_be32(buffer, i)+4;
#ifdef DEBUG_PSD
    log_info("Color mode at 0x%lx\n", (long unsigned)(l + file_recovery->calculated_file_size));
#endif
    if(l<4)
      return 2;
    file_recovery->calculated_file_size+=l;
    file_recovery->data_check=&psd_skip_image_resources;
    return psd_skip_image_resources(buffer, buffer_size, file_recovery);
  }
  return 1;
}

static void file_check_psd(file_recovery_t *file_recovery)
{
  if(file_recovery->file_size < file_recovery->calculated_file_size)
    file_recovery->file_size=0;
  else if(file_recovery->file_size > file_recovery->calculated_file_size + psd_image_data_size_max)
    file_recovery->file_size=file_recovery->calculated_file_size + psd_image_data_size_max;
}
