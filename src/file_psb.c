/*

    File: file_psb.c

    Copyright (C) 2006-2009,2013,2021 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_psb)
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

#ifdef DEBUG_PHOTOSHOP
#include "log.h"
#endif

/* https://www.adobe.com/devnet-apps/photoshop/fileformatashtml/ */

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_psb(file_stat_t *file_stat);

const file_hint_t file_hint_psb= {
  .extension="psb",
  .description="Adobe Photoshop Image",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_psb
};

struct psb_file_header
{
  char signature[4];
  uint16_t version;	/* must be 2 */
  char reserved[6];	/* must be 0 */
  uint16_t channels;	/* between 1 and 56 */
  uint32_t height;	/* max of 300,000 */
  uint32_t width;	/* max of 300,000 */
  uint16_t depth;	/* 1, 8, 16 or 32 */
  uint16_t color_mode;	/* Bitmap = 0; Grayscale = 1; Indexed = 2; RGB = 3; CMYK = 4; Multichannel = 7; Duotone = 8; Lab = 9 */
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires \valid_read((char *)buffer + (offset .. offset + 3));
  @ assigns  \nothing;
  @*/
static uint32_t get_be32(const void *buffer, const unsigned int offset)
{
  const uint32_t *val=(const uint32_t *)((const unsigned char *)buffer+offset);
  return be32(*val);
}

/*@
  @ requires \valid_read((char *)buffer + (offset .. offset + 7));
  @ assigns  \nothing;
  @*/
static uint64_t get_be64(const void *buffer, const unsigned int offset)
{
  const uint64_t *val=(const uint64_t *)((const unsigned char *)buffer+offset);
  return be64(*val);
}

/*@
  @ requires file_recovery->data_check==&psb_skip_image_data;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ ensures  file_recovery->data_check==\null;
  @ ensures  \result == DC_CONTINUE;
  @ assigns  file_recovery->data_check, file_recovery->calculated_file_size;
  @*/
static data_check_t psb_skip_image_data(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert buffer_size <= 2 * PHOTOREC_MAX_BLOCKSIZE; */
  file_recovery->calculated_file_size+=2;
  file_recovery->data_check=NULL;
  return DC_CONTINUE;
}

/*@
  @ requires file_recovery->data_check==&psb_skip_layer_info;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ ensures file_recovery->data_check==&psb_skip_layer_info || file_recovery->data_check==\null;
  @ ensures  \result == DC_CONTINUE || \result == DC_STOP;
  @ assigns file_recovery->data_check, file_recovery->calculated_file_size;
  @*/
static data_check_t psb_skip_layer_info(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert buffer_size <= 2 * PHOTOREC_MAX_BLOCKSIZE; */
  if(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 8 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size + buffer_size/2 - file_recovery->file_size;
    /*@ assert 0 <= i < buffer_size - 8 ; */
    const uint64_t l=get_be64(buffer, i);
#ifdef DEBUG_PHOTOSHOP
    log_info("Layer info at 0x%lx, l=0x%lx\n", (long unsigned)file_recovery->calculated_file_size, (long unsigned)l);
#endif
    if(l> PHOTOREC_MAX_FILE_SIZE)
      return DC_STOP;
    file_recovery->calculated_file_size+=l+8;
#ifdef DEBUG_PHOTOSHOP
    log_info("Image data at 0x%lx\n", (long unsigned)file_recovery->calculated_file_size);
#endif
    file_recovery->data_check=&psb_skip_image_data;
    return psb_skip_image_data(buffer, buffer_size, file_recovery);
  }
  return DC_CONTINUE;
}

/*@
  @ requires file_recovery->data_check==&psb_skip_image_resources;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ ensures file_recovery->data_check==&psb_skip_image_resources || file_recovery->data_check==&psb_skip_layer_info || file_recovery->data_check==\null;
  @ assigns file_recovery->data_check, file_recovery->calculated_file_size;
  @*/
static data_check_t psb_skip_image_resources(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert buffer_size <= 2 * PHOTOREC_MAX_BLOCKSIZE; */
  if(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 4 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size + buffer_size/2 - file_recovery->file_size;
    /*@ assert 0 <= i < buffer_size - 4 ; */
    const unsigned int l=get_be32(buffer, i);
#ifdef DEBUG_PHOTOSHOP
    log_info("Image resource at 0x%lx, l=0x%x\n", (long unsigned)file_recovery->calculated_file_size, l);
#endif
    file_recovery->calculated_file_size+=(uint64_t)l+4;
#ifdef DEBUG_PHOTOSHOP
    log_info("Layer info at 0x%lx\n", (long unsigned)file_recovery->calculated_file_size);
#endif
    file_recovery->data_check=&psb_skip_layer_info;
    return psb_skip_layer_info(buffer, buffer_size, file_recovery);
  }
  return DC_CONTINUE;
}

/*@
  @ requires buffer_size >= 32;
  @ requires file_recovery->data_check==&psb_skip_color_mode;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ ensures file_recovery->data_check==&psb_skip_color_mode || file_recovery->data_check==&psb_skip_image_resources || file_recovery->data_check==&psb_skip_layer_info || file_recovery->data_check==\null;
  @ assigns file_recovery->data_check, file_recovery->calculated_file_size;
  @*/
static data_check_t psb_skip_color_mode(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  const struct psb_file_header *hdr=(const struct psb_file_header *)&buffer[buffer_size/2];
  const unsigned int channels=be16(hdr->channels);
  const unsigned int depth=be16(hdr->depth);
  const unsigned int height=be32(hdr->height);
  const unsigned int width=be32(hdr->width);
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert buffer_size <= 2 * PHOTOREC_MAX_BLOCKSIZE; */
  if(channels==0 || channels>56 ||
      height==0 || height>300000 ||
      width==0 || width>300000 ||
      (depth!=1 && depth!=8 && depth!=16 && depth!=32))
    return DC_ERROR;
  if(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 4 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size + buffer_size/2 - file_recovery->file_size;
    /*@ assert 0 <= i < buffer_size - 4 ; */
    const unsigned int l=get_be32(buffer, i);
#ifdef DEBUG_PHOTOSHOP
    log_info("Color mode at 0x%lx, l=0x%x\n", (long unsigned)file_recovery->calculated_file_size, l);
#endif
    if(l!=0 && l<4)
      return DC_ERROR;
    file_recovery->calculated_file_size+=(uint64_t)l+4;
    file_recovery->data_check=&psb_skip_image_resources;
    return psb_skip_image_resources(buffer, buffer_size, file_recovery);
  }
  return DC_CONTINUE;
}

/*@
  @ requires buffer_size >= sizeof(struct psb_file_header);
  @ requires separation: \separated(&file_hint_psb, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_psb(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct psb_file_header *hdr=(const struct psb_file_header *)buffer;
  const unsigned int channels=be16(hdr->channels);
  const unsigned int depth=be16(hdr->depth);
  const unsigned int height=be32(hdr->height);
  const unsigned int width=be32(hdr->width);
#ifdef DEBUG_PHOTOSHOP
  log_info("channels %u\n", channels);
  log_info("height %u\n", height);
  log_info("width  %u\n", width);
  log_info("depth  %u\n", depth);
  log_info("color_mode %u\n", be16(hdr->color_mode));
#endif
  if(channels==0 || channels>56 ||
      height==0 || height>300000 ||
      width==0 || width>300000 ||
      (depth!=1 && depth!=8 && depth!=16 && depth!=32))
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->min_filesize=70;
  file_recovery_new->extension=file_hint_psb.extension;
  if(file_recovery_new->blocksize < 16)
    return 1;
  /* File header */
  file_recovery_new->calculated_file_size=0x1a;
  file_recovery_new->data_check=&psb_skip_color_mode;
  file_recovery_new->file_check=&file_check_size_min;
  return 1;
}

static void register_header_check_psb(file_stat_t *file_stat)
{
  static const unsigned char psb_header[6]={'8', 'B', 'P', 'S', 0x00, 0x02};
  register_header_check(0, psb_header,sizeof(psb_header), &header_check_psb, file_stat);
}
#endif
