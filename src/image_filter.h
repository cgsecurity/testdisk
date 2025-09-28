/*

    File: image_filter.h

    Copyright (C) 2024 Christophe GRENIER <grenier@cgsecurity.org>

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

#ifndef _IMAGE_FILTER_H
#define _IMAGE_FILTER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "types.h"

/* Forward declaration to avoid circular dependencies */
typedef struct image_size_filter_struct image_size_filter_t;

/* Global image filter - extern pattern following PhotoRec convention */
extern const image_size_filter_t *current_image_filter;
extern int global_filter_active;

/*@
  @ requires \valid_read(filter);
  @ ensures \result == 0 || \result == 1;
  @ assigns \nothing;
  @*/
int check_image_dimensions(uint32_t width, uint32_t height, const image_size_filter_t *filter);

int has_any_filters(const image_size_filter_t *filter);
int has_dimension_filters(void);
int should_skip_image_by_dimensions(uint32_t width, uint32_t height);
int should_skip_image_by_filesize(uint64_t file_size);

/*@
  @ assigns current_image_filter;
  @*/
void set_current_image_filter(const image_size_filter_t *filter);

/*@
  @ requires \valid_read(filter);
  @ ensures \result == 0 || \result == 1;
  @ assigns \nothing;
  @*/
int check_image_filesize(uint64_t file_size, const image_size_filter_t *filter);

/*@
  @ requires \valid(cmd);
  @ requires \valid(filter);
  @ assigns *cmd, *filter;
  @*/
void parse_imagesize_command(char **cmd, image_size_filter_t *filter);

/*@
  @ requires \valid_read(filter);
  @ ensures \result == 0 || \result == 1;
  @ assigns \nothing;
  @*/
int validate_image_filter(const image_size_filter_t *filter);

/*@
  @ requires \valid(cmd);
  @ ensures \result >= 0;
  @ assigns *cmd;
  @*/
uint64_t parse_size_with_units(char **cmd);

/*@
  @ requires \valid(cmd);
  @ ensures \result >= 0;
  @ assigns *cmd;
  @*/
uint64_t parse_pixels_value(char **cmd);

/*@
  @ requires \valid(cmd);
  @ requires \valid(min_pixels);
  @ requires \valid(max_pixels);
  @ assigns *cmd, *min_pixels, *max_pixels;
  @*/
void parse_pixels_range(char **cmd, uint64_t *min_pixels, uint64_t *max_pixels);

#ifdef __cplusplus
}
#endif
#endif