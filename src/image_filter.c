/*

    File: image_filter.c

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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "types.h"
#include "common.h"
#include "filegen.h"
#include "photorec.h"
#include "image_filter.h"
#include "log.h"

/* Global image filter following PhotoRec's extern pattern */
const image_size_filter_t *current_image_filter = NULL;

/*@
  @ requires \valid_read(filter);
  @ ensures \result == 0 || \result == 1;
  @ assigns \nothing;
  @*/
int check_image_dimensions(uint32_t width, uint32_t height, const image_size_filter_t *filter)
{
  if (!filter->enabled)
    return 1;

  /* Check pixels first (has priority over width/height) */
  if (filter->min_pixels > 0 || filter->max_pixels > 0) {
    uint64_t pixels = (uint64_t)width * height;
    if (filter->min_pixels > 0 && pixels < filter->min_pixels)
      return 0;
    if (filter->max_pixels > 0 && pixels > filter->max_pixels)
      return 0;
  }
  /* Check width/height only if pixels is not set */
  else {
    if (filter->min_width > 0 && width < filter->min_width)
      return 0;
    if (filter->max_width > 0 && width > filter->max_width)
      return 0;
    if (filter->min_height > 0 && height < filter->min_height)
      return 0;
    if (filter->max_height > 0 && height > filter->max_height)
      return 0;
  }
  return 1;
}

/*@
  @ requires \valid_read(filter);
  @ ensures \result == 0 || \result == 1;
  @ assigns \nothing;
  @*/
int check_image_filesize(uint64_t file_size, const image_size_filter_t *filter)
{
  if (!filter->enabled)
    return 1;

  if (filter->min_file_size > 0 && file_size < filter->min_file_size)
    return 0;
  if (filter->max_file_size > 0 && file_size > filter->max_file_size)
    return 0;
  return 1;
}

/*@
  @ requires \valid(cmd);
  @ ensures \result >= 0;
  @ assigns *cmd;
  @*/
uint64_t parse_size_with_units(char **cmd)
{
  uint64_t val = 0;
  char *ptr = *cmd;

  /* Parse number */
  while(*ptr && isdigit(*ptr))
  {
    val = val * 10 + (*ptr - '0');
    ptr++;
  }

  /* Parse unit suffix */
  if(*ptr == 'k' || *ptr == 'K')
  {
    val *= 1024;
    ptr++;
  }
  else if(*ptr == 'm' || *ptr == 'M')
  {
    val *= 1024 * 1024;
    ptr++;
  }
  else if(*ptr == 'g' || *ptr == 'G')
  {
    val *= 1024 * 1024 * 1024;
    ptr++;
  }

  *cmd = ptr;
  return val;
}

/*@
  @ requires \valid(cmd);
  @ ensures \result >= 0;
  @ assigns *cmd;
  @*/
uint64_t parse_pixels_value(char **cmd)
{
  char *ptr = *cmd;
  uint64_t val = 0;

  /* Check if it's WIDTHxHEIGHT format */
  if(strchr(ptr, 'x') != NULL)
  {
    uint32_t width = 0, height = 0;

    /* Parse width */
    while(*ptr && isdigit(*ptr))
    {
      width = width * 10 + (*ptr - '0');
      ptr++;
    }

    /* Skip 'x' */
    if(*ptr == 'x')
      ptr++;

    /* Parse height */
    while(*ptr && isdigit(*ptr))
    {
      height = height * 10 + (*ptr - '0');
      ptr++;
    }

    val = (uint64_t)width * height;
  }
  else
  {
    /* Direct number format */
    while(*ptr && isdigit(*ptr))
    {
      val = val * 10 + (*ptr - '0');
      ptr++;
    }
  }

  *cmd = ptr;
  return val;
}

/*@
  @ requires \valid(cmd);
  @ requires \valid(min_pixels);
  @ requires \valid(max_pixels);
  @ assigns *cmd, *min_pixels, *max_pixels;
  @*/
void parse_pixels_range(char **cmd, uint64_t *min_pixels, uint64_t *max_pixels)
{
  char *ptr = *cmd;

  *min_pixels = 0;
  *max_pixels = 0;

  /* Check for leading dash (only max) */
  if(*ptr == '-')
  {
    ptr++;
    *max_pixels = parse_pixels_value(&ptr);
  }
  else
  {
    /* Parse min value */
    *min_pixels = parse_pixels_value(&ptr);

    /* Check for range separator */
    if(*ptr == '-')
    {
      ptr++;
      /* Check if there's a max value after dash */
      if(*ptr && *ptr != ',' && *ptr != '\0')
      {
        *max_pixels = parse_pixels_value(&ptr);
      }
    }
  }

  *cmd = ptr;
}

/*@
  @ requires \valid_read(filter);
  @ ensures \result == 0 || \result == 1;
  @ assigns \nothing;
  @*/
int validate_image_filter(const image_size_filter_t *filter)
{
  /* Check for conflicting parameters: pixels vs width/height */
  int has_pixels = (filter->min_pixels > 0 || filter->max_pixels > 0);
  int has_dimensions = (filter->min_width > 0 || filter->max_width > 0 ||
                       filter->min_height > 0 || filter->max_height > 0);

  if(has_pixels && has_dimensions)
  {
    log_error("Cannot combine 'pixels' parameter with 'width' or 'height' parameters.\n");
    log_error("Use either:\n");
    log_error("  - pixels:WIDTHxHEIGHT-WIDTHxHEIGHT (direct pixel control)\n");
    log_error("  - width:MIN-MAX,height:MIN-MAX (dimension control)\n");
    return 0;
  }

  return 1;
}

/*@
  @ requires \valid(cmd);
  @ requires \valid(filter);
  @ assigns *cmd, *filter;
  @*/
void parse_imagesize_command(char **cmd, image_size_filter_t *filter)
{
  char *ptr = *cmd;

  /* Initialize filter */
  memset(filter, 0, sizeof(*filter));
  filter->enabled = 1;

  /* Note: "imagesize," prefix already consumed by check_command */

  /* Parse parameters in format: param,value,param,value */
  while(*ptr)
  {
    if(strncmp(ptr, "filesize,", 9) == 0)
    {
      ptr += 9;
      if(*ptr == '-')
      {
        ptr++;
        filter->max_file_size = parse_size_with_units(&ptr);
      }
      else
      {
        filter->min_file_size = parse_size_with_units(&ptr);
        if(*ptr == '-')
        {
          ptr++;
          if(*ptr && *ptr != ',' && *ptr != '\0')
            filter->max_file_size = parse_size_with_units(&ptr);
        }
      }
    }
    else if(strncmp(ptr, "width,", 6) == 0)
    {
      ptr += 6;
      if(*ptr == '-')
      {
        ptr++;
        filter->max_width = (uint32_t)get_int_from_command(&ptr);
      }
      else
      {
        filter->min_width = (uint32_t)get_int_from_command(&ptr);
        if(*ptr == '-')
        {
          ptr++;
          if(*ptr && *ptr != ',' && *ptr != '\0')
            filter->max_width = (uint32_t)get_int_from_command(&ptr);
        }
      }
    }
    else if(strncmp(ptr, "height,", 7) == 0)
    {
      ptr += 7;
      if(*ptr == '-')
      {
        ptr++;
        filter->max_height = (uint32_t)get_int_from_command(&ptr);
      }
      else
      {
        filter->min_height = (uint32_t)get_int_from_command(&ptr);
        if(*ptr == '-')
        {
          ptr++;
          if(*ptr && *ptr != ',' && *ptr != '\0')
            filter->max_height = (uint32_t)get_int_from_command(&ptr);
        }
      }
    }
    else if(strncmp(ptr, "pixels,", 7) == 0)
    {
      ptr += 7;
      parse_pixels_range(&ptr, &filter->min_pixels, &filter->max_pixels);
    }
    else
    {
      /* Unknown parameter - stop parsing and leave it for other parsers */
      break;
    }

    /* Skip to next parameter */
    if(*ptr == ',')
      ptr++;
  }

  *cmd = ptr;

  /* Validate configuration */
  if(!validate_image_filter(filter))
  {
    filter->enabled = 0;
  }
}

void set_current_image_filter(const image_size_filter_t *filter)
{
  current_image_filter = filter;
}

int should_skip_image_by_dimensions(uint32_t width, uint32_t height)
{
  if(!current_image_filter || !current_image_filter->enabled) {
    return 0; /* don't skip */
  }

  /* Check dimensions (pixels vs width/height) */
  if(!check_image_dimensions(width, height, current_image_filter)) {
    return 1; /* skip */
  }

  return 0; /* don't skip */
}

int should_skip_image_by_filesize(uint64_t file_size)
{
  if(!current_image_filter || !current_image_filter->enabled)
    return 0; /* don't skip */

  /* Check file size if provided */
  if(file_size > 0 && !check_image_filesize(file_size, current_image_filter))
    return 1; /* skip */

  return 0; /* don't skip */
}

