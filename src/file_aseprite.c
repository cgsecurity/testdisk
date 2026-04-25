/*

    File: file_aseprite.c

    Copyright (C) 2006-2009,2021 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_aseprite)
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

#ifdef DEBUG_ASEPRITE
#include "log.h"
#endif

/* file format spec: https://github.com/aseprite/aseprite/blob/main/docs/ase-file-specs.md */

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_aseprite(file_stat_t *file_stat);

const file_hint_t file_hint_aseprite= {
  .extension="aseprite",
  .description="LibreSprite/Aseprite .ase/.aseprite Files.",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_aseprite
};

struct aseprite_file_header
{
  uint32_t file_size;
  uint16_t magic;	/* must be 0xA5E0 */
  uint16_t frames;	/* number of frames */
  uint16_t width;	/* Width in pixels */
  uint16_t height;	/* Height in pixels */
  uint16_t color_depth;	/* Bits per pixel (32 bpp = RGBA; 16 bpp GRAYSCALE; 8 bpp INDEXED;) */
  uint32_t flags; /* flags */
  uint16_t speed; /* speed (miliseconds between frames) 
    DEPRECATED: frame's frame duration field used instead. */
  uint32_t reserved1; /* must be 0 */
  uint32_t reserved2; /* must be 0 */
  uint8_t pallete; /* Pallete entry (index). Only for indexed sprites. */
  uint8_t reserved3[3]; /* must be 0 */
  uint16_t ncolors; /* Number of colors (0 means 256 for old sprites) */
  uint8_t pixel_width; /* Pixel ratio = pixel_width/pixel_height; 
    If this or pixel_height equals to 0, pixel ratio = 1:1 */
  uint8_t pixel_height; /* Pixel Height */
  int16_t x_grid; /* X position on grid. */
  int16_t y_grid; /* Y position on grid. */
  uint16_t grid_w; /* Grid width. Zero if no grid. */
  uint16_t grid_h; /* Grid Height. Zero if no grid. */
  uint8_t reserved4[84]; /* For future. Set to zero (0). */
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires buffer_size >= sizeof(struct aseprite_file_header);
  @ requires separation: \separated(&file_hint_aseprite, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
*/
static int header_check_aseprite(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct aseprite_file_header *hdr= (const struct aseprite_file_header *)buffer;

  const unsigned int file_size = le32(hdr->file_size);
  const unsigned int frames = le16(hdr->frames);
  const unsigned int width = le16(hdr->width);
  const unsigned int height = le16(hdr->height);
  const unsigned int reserved1 = le32(hdr->reserved1);
  const unsigned int reserved2 = le32(hdr->reserved2);
  const unsigned int color_depth = le16(hdr->color_depth);

#ifdef DEBUG_ASEPRITE
  log_info("file size %u\n", file_size);
  log_info("frames %u\n", frames);
  log_info("height %u\n", height);
  log_info("width  %u\n", width);
  log_info("depth  %u\n", color_depth);
#endif

  if (file_size < sizeof(struct aseprite_file_header) || 
      frames==0 || frames > 65535 || 
      width==0 || width > 65535 || 
      height==0 || height > 65535 || 
      reserved1!=0 || reserved2!=0 || 
      (color_depth!=8 && color_depth!=16 && color_depth!=32)  
  ) 
    return 0;

  reset_file_recovery(file_recovery_new);
  file_recovery_new->min_filesize=sizeof(struct aseprite_file_header);
  file_recovery_new->extension=file_hint_aseprite.extension;
  if (file_recovery_new->blocksize < 16) 
    return 1;
  file_recovery_new->calculated_file_size=file_size;
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size_min;
  return 1;
}

/*
    Will register specific file header check function.
*/
static void register_header_check_aseprite(file_stat_t *file_stat)
{
  static const unsigned char aseprite_header[2]={ 0xE0, 0xA5 };
  register_header_check(4, aseprite_header,sizeof(aseprite_header), &header_check_aseprite, file_stat);
}

#endif
