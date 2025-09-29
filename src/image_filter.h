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
#include "photorec.h"


int has_any_image_size_filter(const image_size_filter_t *filter);
int should_skip_image_by_dimensions(const image_size_filter_t *filter, uint32_t width, uint32_t height);
int should_skip_image_by_filesize(const image_size_filter_t *filter, uint64_t file_size);

void change_imagesize_cli(char **cmd, image_size_filter_t *filter);

int validate_image_filter(const image_size_filter_t *filter);

uint64_t parse_size_with_units(char **cmd);

uint64_t parse_pixels_value(char **cmd);

void print_image_filter(const image_size_filter_t *filter);

void parse_pixels_range(char **cmd, uint64_t *min_pixels, uint64_t *max_pixels);

void format_file_size_string(uint64_t size, char *buffer, size_t buffer_size);

#ifdef __cplusplus
}
#endif
#endif