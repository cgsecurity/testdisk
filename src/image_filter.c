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

struct image_size_filter_struct
{
  uint64_t min_file_size;  /* 0 = no limit */
  uint64_t max_file_size;  /* 0 = no limit */
  uint32_t min_width;      /* 0 = no limit */
  uint32_t max_width;      /* 0 = no limit */
  uint32_t min_height;     /* 0 = no limit */
  uint32_t max_height;     /* 0 = no limit */
  uint64_t min_pixels;     /* 0 = no limit (width × height) */
  uint64_t max_pixels;     /* 0 = no limit (width × height) */
};



/*@
  @ requires \valid_read(filter);
  @ ensures \result == 0 || \result == 1;
  @ assigns \nothing;
  @*/
int check_image_filesize(uint64_t file_size, const image_size_filter_t *filter)
{
  if (!filter)
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
  char *ptr = *cmd;
  double val = 0.0;

  /* Parse number with decimal support */
  char *endptr;
  val = strtod(ptr, &endptr);

  if (endptr == ptr) {
    /* No valid number found */
    return 0;
  }

  ptr = endptr;

  /* Parse unit suffix and convert to bytes */
  uint64_t multiplier = 1;
  if(*ptr == 'k' || *ptr == 'K')
  {
    multiplier = 1024;
    ptr++;
  }
  else if(*ptr == 'm' || *ptr == 'M')
  {
    multiplier = 1024 * 1024;
    ptr++;
  }
  else if(*ptr == 'g' || *ptr == 'G')
  {
    multiplier = 1024 * 1024 * 1024;
    ptr++;
  }

  *cmd = ptr;
  return (uint64_t)(val * multiplier);
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
  validate_image_filter(filter);
}

/*@
  @ requires \valid_read(filter);
  @ ensures \result == 0 || \result == 1;
  @ assigns \nothing;
  @*/
int has_any_filters(const image_size_filter_t *filter)
{
  if (!filter)
    return 0;

  return (filter->min_file_size > 0 || filter->max_file_size > 0 ||
          filter->min_width > 0 || filter->max_width > 0 ||
          filter->min_height > 0 || filter->max_height > 0 ||
          filter->min_pixels > 0 || filter->max_pixels > 0);
}



void set_current_image_filter(const image_size_filter_t *filter)
{
  FILE *debug_file = fopen("/tmp/filter_debug.log", "a");
  if(debug_file) {
    if(filter) {
      fprintf(debug_file, "SET_FILTER: Copying filter with min_file_size=%llu, max_file_size=%llu to global storage\n",
              (long long unsigned)filter->min_file_size, (long long unsigned)filter->max_file_size);
      fprintf(debug_file, "SET_FILTER: Source address: %p, global address: %p\n", filter, &global_image_filter);
    } else {
      fprintf(debug_file, "SET_FILTER: Setting filter to NULL\n");
    }
    fclose(debug_file);
  }

  if(filter) {
    /* Copy filter to global storage to avoid stack pointer issues */
    global_image_filter = *filter;
    global_filter_active = 1;
    current_image_filter = &global_image_filter;

    /* Also save to environment variables for cross-process communication */
    char env_val[64];
    snprintf(env_val, sizeof(env_val), "%llu", (long long unsigned)filter->min_file_size);
    setenv("PHOTOREC_MIN_FILE_SIZE", env_val, 1);
    snprintf(env_val, sizeof(env_val), "%llu", (long long unsigned)filter->max_file_size);
    setenv("PHOTOREC_MAX_FILE_SIZE", env_val, 1);
    snprintf(env_val, sizeof(env_val), "%u", filter->min_width);
    setenv("PHOTOREC_MIN_WIDTH", env_val, 1);
    snprintf(env_val, sizeof(env_val), "%u", filter->max_width);
    setenv("PHOTOREC_MAX_WIDTH", env_val, 1);
    snprintf(env_val, sizeof(env_val), "%u", filter->min_height);
    setenv("PHOTOREC_MIN_HEIGHT", env_val, 1);
    snprintf(env_val, sizeof(env_val), "%u", filter->max_height);
    setenv("PHOTOREC_MAX_HEIGHT", env_val, 1);
    snprintf(env_val, sizeof(env_val), "%llu", (long long unsigned)filter->min_pixels);
    setenv("PHOTOREC_MIN_PIXELS", env_val, 1);
    snprintf(env_val, sizeof(env_val), "%llu", (long long unsigned)filter->max_pixels);
    setenv("PHOTOREC_MAX_PIXELS", env_val, 1);
    setenv("PHOTOREC_FILTER_ACTIVE", "1", 1);
  } else {
    global_filter_active = 0;
    current_image_filter = NULL;
    unsetenv("PHOTOREC_FILTER_ACTIVE");
  }

}

int should_skip_image_by_dimensions(const image_size_filter_t *filter, uint32_t width, uint32_t height)
{
  if(!filter) {
    return 0; /* don't skip */
  }

  static unsigned long dim_calls = 0;
  static unsigned long dim_skips = 0;
  dim_calls++;

  if(dim_calls % 5000 == 0) {
    fprintf(stderr, "DIM_DEBUG: %lu calls, %lu skips\n", dim_calls, dim_skips);
  }

  /* Check pixels first (has priority over width/height) */
  if (filter->min_pixels > 0 || filter->max_pixels > 0) {
    uint64_t pixels = (uint64_t)width * height;
    if (filter->min_pixels > 0 && pixels < filter->min_pixels) {
      dim_skips++;
      return 1; /* skip */
    }
    if (filter->max_pixels > 0 && pixels > filter->max_pixels) {
      dim_skips++;
      return 1; /* skip */
    }
  }
  /* Check width/height only if pixels is not set */
  else {
    if (filter->min_width > 0 && width < filter->min_width) {
      dim_skips++;
      return 1; /* skip */
    }
    if (filter->max_width > 0 && width > filter->max_width) {
      dim_skips++;
      return 1; /* skip */
    }
    if (filter->min_height > 0 && height < filter->min_height) {
      dim_skips++;
      return 1; /* skip */
    }
    if (filter->max_height > 0 && height > filter->max_height) {
      dim_skips++;
      return 1; /* skip */
    }
  }

  return 0; /* don't skip */
}

int has_dimension_filters(void)
{
  if(!current_image_filter) {
    return 0;
  }
  return (current_image_filter->min_width > 0 ||
          current_image_filter->max_width > 0 ||
          current_image_filter->min_height > 0 ||
          current_image_filter->max_height > 0 ||
          current_image_filter->min_pixels > 0 ||
          current_image_filter->max_pixels > 0);
}

int should_skip_image_by_filesize(uint64_t file_size)
{
  if(!current_image_filter)
    return 0; /* don't skip */

  /* Check file size if provided */
  if(file_size > 0 && !check_image_filesize(file_size, current_image_filter)) {
    return 1; /* skip */
  }

  return 0; /* don't skip */
}

