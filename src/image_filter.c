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
#include <sys/time.h>
#include "types.h"
#include "common.h"
#include "filegen.h"
#include "photorec.h"
#include "image_filter.h"
#include "log.h"


void print_image_filter(const image_size_filter_t *filter)
{
  if(!filter) {
    printf("Image filter: NULL (no filtering)\n");
    return;
  }

  printf("=== Image Filter Settings ===\n");

  /* File size filters */
  if(filter->min_file_size > 0 || filter->max_file_size > 0) {
    printf("File size: ");
    if(filter->min_file_size > 0) {
      if(filter->min_file_size >= 1024*1024*1024) {
        printf("min=%.1fGB", (double)filter->min_file_size / (1024*1024*1024));
      } else if(filter->min_file_size >= 1024*1024) {
        printf("min=%.1fMB", (double)filter->min_file_size / (1024*1024));
      } else if(filter->min_file_size >= 1024) {
        printf("min=%.1fKB", (double)filter->min_file_size / 1024);
      } else {
        printf("min=%llu bytes", (unsigned long long)filter->min_file_size);
      }
    } else {
      printf("min=none");
    }

    printf(", ");

    if(filter->max_file_size > 0) {
      if(filter->max_file_size >= 1024*1024*1024) {
        printf("max=%.1fGB", (double)filter->max_file_size / (1024*1024*1024));
      } else if(filter->max_file_size >= 1024*1024) {
        printf("max=%.1fMB", (double)filter->max_file_size / (1024*1024));
      } else if(filter->max_file_size >= 1024) {
        printf("max=%.1fKB", (double)filter->max_file_size / 1024);
      } else {
        printf("max=%llu bytes", (unsigned long long)filter->max_file_size);
      }
    } else {
      printf("max=none");
    }
    printf("\n");
  } else {
    printf("File size: no limits\n");
  }

  /* Width filters */
  if(filter->min_width > 0 || filter->max_width > 0) {
    printf("Width: ");
    if(filter->min_width > 0) {
      printf("min=%u", filter->min_width);
    } else {
      printf("min=none");
    }
    printf(", ");
    if(filter->max_width > 0) {
      printf("max=%u", filter->max_width);
    } else {
      printf("max=none");
    }
    printf(" pixels\n");
  } else {
    printf("Width: no limits\n");
  }

  /* Height filters */
  if(filter->min_height > 0 || filter->max_height > 0) {
    printf("Height: ");
    if(filter->min_height > 0) {
      printf("min=%u", filter->min_height);
    } else {
      printf("min=none");
    }
    printf(", ");
    if(filter->max_height > 0) {
      printf("max=%u", filter->max_height);
    } else {
      printf("max=none");
    }
    printf(" pixels\n");
  } else {
    printf("Height: no limits\n");
  }

  /* Pixel count filters */
  if(filter->min_pixels > 0 || filter->max_pixels > 0) {
    printf("Total pixels: ");
    if(filter->min_pixels > 0) {
      if(filter->min_pixels >= 1000000) {
        printf("min=%.1fM", (double)filter->min_pixels / 1000000);
      } else if(filter->min_pixels >= 1000) {
        printf("min=%.1fK", (double)filter->min_pixels / 1000);
      } else {
        printf("min=%llu", (unsigned long long)filter->min_pixels);
      }
    } else {
      printf("min=none");
    }
    printf(", ");
    if(filter->max_pixels > 0) {
      if(filter->max_pixels >= 1000000) {
        printf("max=%.1fM", (double)filter->max_pixels / 1000000);
      } else if(filter->max_pixels >= 1000) {
        printf("max=%.1fK", (double)filter->max_pixels / 1000);
      } else {
        printf("max=%llu", (unsigned long long)filter->max_pixels);
      }
    } else {
      printf("max=none");
    }
    printf(" pixels\n");
  } else {
    printf("Total pixels: no limits\n");
  }

  printf("=============================\n");
}

int should_skip_image_by_dimensions(const image_size_filter_t *filter, uint32_t width, uint32_t height)
{
  if(!filter)
    return 0;

  if(filter->min_pixels > 0 || filter->max_pixels > 0)
  {
    uint64_t pixels = (uint64_t)width * height;
    if(filter->min_pixels > 0 && pixels < filter->min_pixels)
      return 1;
    if(filter->max_pixels > 0 && pixels > filter->max_pixels)
      return 1;

    return 0;
  }

  if(filter->min_width > 0 && width < filter->min_width)
    return 1;
  if(filter->max_width > 0 && width > filter->max_width)
    return 1;
  if(filter->min_height > 0 && height < filter->min_height)
    return 1;
  if(filter->max_height > 0 && height > filter->max_height)
    return 1;

  return 0;
}

int should_skip_image_by_filesize(const image_size_filter_t *filter, uint64_t file_size)
{
  if(!filter)
    return 0;

  if(filter->min_file_size > 0 && file_size < filter->min_file_size)
    return 1;
  if(filter->max_file_size > 0 && file_size > filter->max_file_size)
    return 1;

  return 0;
}

int has_any_image_size_filter(const image_size_filter_t *filter)
{
  return (filter->min_file_size | filter->max_file_size |
          filter->min_width | filter->max_width |
          filter->min_height | filter->max_height |
          filter->min_pixels | filter->max_pixels) > 0;
}

/* Parse file size with unit suffixes. Valid formats:
 * - "1000"    : exact size in bytes (1000)
 * - "10k"     : size in kilobytes (10240 bytes)
 * - "1.5m"    : size in megabytes with decimal (1572864 bytes)
 * - "2g"      : size in gigabytes (2147483648 bytes)
 * - Units: k/K (kilobytes), m/M (megabytes), g/G (gigabytes)
 * - Decimal values supported (e.g., "1.5k", "0.5m")
 */
uint64_t parse_size_with_units(char **cmd)
{
  char *ptr = *cmd;
  double val = 0.0;

  /* Parse number with decimal support */
  char *endptr;
  val = strtod(ptr, &endptr);

  if(endptr == ptr)
    return 0;

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

/* Parse pixel value in numeric or WIDTHxHEIGHT format. Valid formats:
 * - "1000"     : exact pixel count (1000)
 * - "800x600"  : resolution format (calculates 800*600 = 480000 pixels)
 * - "1920x1080": HD resolution (calculates 1920*1080 = 2073600 pixels)
 * - Width and height must be positive integers
 */
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

/* Parse pixel range specification. Valid formats:
 * - "1000"       : exact pixel count (1000)
 * - "800x600"    : exact resolution (480000 pixels)
 * - "1000-"      : minimum 1000 pixels, no maximum
 * - "-5000"      : maximum 5000 pixels, no minimum
 * - "1000-5000"  : range from 1000 to 5000 pixels
 * - "800x600-1920x1080" : resolution range (480000 to 2073600 pixels)
 * - "800x600-"   : minimum 800x600 resolution, no maximum
 * - "-1920x1080" : maximum 1920x1080 resolution, no minimum
 */
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

void change_imagesize_cli(char **cmd, image_size_filter_t *filter)
{
  char *ptr = *cmd;
  memset(filter, 0, sizeof(*filter));

  while(*ptr)
  {
    if(strncmp(ptr, "size,", 5) == 0)
    {
      ptr += 5;
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

/* Format file size for display in user interface.
 * Converts bytes to human-readable format:
 * - Values < 1024: shows exact bytes (e.g., "55", "1023")
 * - Values >= 1024 < 1MB: shows with 'k' suffix (e.g., "1k", "500k")
 * - Values >= 1MB: shows with 'm' suffix (e.g., "1m", "10m")
 * - Size 0: returns empty string
 */
void format_file_size_string(uint64_t size, char *buffer, size_t buffer_size)
{
  if (size == 0) {
    buffer[0] = '\0';
    return;
  }

  if (size >= 1024*1024*1024) {
    double gb = (double)size / (1024*1024*1024);
    snprintf(buffer, buffer_size, "%.2fg", gb);
  } else if (size >= 1024*1024) {
    double mb = (double)size / (1024*1024);
    snprintf(buffer, buffer_size, "%.2fm", mb);
  } else if (size >= 1024) {
    double kb = (double)size / 1024.0;
    snprintf(buffer, buffer_size, "%.2fk", kb);
  } else {
    snprintf(buffer, buffer_size, "%lu", (unsigned long)size);
  }
}

/* Convert image_size_filter_t to CLI format string for session saving */
void image_size_2_cli(const image_size_filter_t *filter, char *buffer, size_t buffer_size)
{
  int written = 0;

  if (!has_any_image_size_filter(filter)) {
    buffer[0] = '\0';
    return;
  }

  written += snprintf(buffer + written, buffer_size - written, "imagesize,");

  /* File size filters */
  if (filter->min_file_size > 0 && filter->max_file_size > 0) {
    written += snprintf(buffer + written, buffer_size - written, "size,%luk-%luk,",
                       (unsigned long)(filter->min_file_size / 1024),
                       (unsigned long)(filter->max_file_size / 1024));
  } else if (filter->min_file_size > 0) {
    written += snprintf(buffer + written, buffer_size - written, "size,%luk-,",
                       (unsigned long)(filter->min_file_size / 1024));
  } else if (filter->max_file_size > 0) {
    written += snprintf(buffer + written, buffer_size - written, "size,-%luk,",
                       (unsigned long)(filter->max_file_size / 1024));
  }

  /* Width filters */
  if (filter->min_width > 0 && filter->max_width > 0) {
    written += snprintf(buffer + written, buffer_size - written, "width,%u-%u,",
                       filter->min_width, filter->max_width);
  } else if (filter->min_width > 0) {
    written += snprintf(buffer + written, buffer_size - written, "width,%u-,",
                       filter->min_width);
  } else if (filter->max_width > 0) {
    written += snprintf(buffer + written, buffer_size - written, "width,-%u,",
                       filter->max_width);
  }

  /* Height filters */
  if (filter->min_height > 0 && filter->max_height > 0) {
    written += snprintf(buffer + written, buffer_size - written, "height,%u-%u,",
                       filter->min_height, filter->max_height);
  } else if (filter->min_height > 0) {
    written += snprintf(buffer + written, buffer_size - written, "height,%u-,",
                       filter->min_height);
  } else if (filter->max_height > 0) {
    written += snprintf(buffer + written, buffer_size - written, "height,-%u,",
                       filter->max_height);
  }

  /* Pixels filters */
  if (filter->min_pixels > 0 && filter->max_pixels > 0) {
    written += snprintf(buffer + written, buffer_size - written, "pixels,%llu-%llu,",
                       (unsigned long long)filter->min_pixels, (unsigned long long)filter->max_pixels);
  } else if (filter->min_pixels > 0) {
    written += snprintf(buffer + written, buffer_size - written, "pixels,%llu-,",
                       (unsigned long long)filter->min_pixels);
  } else if (filter->max_pixels > 0) {
    written += snprintf(buffer + written, buffer_size - written, "pixels,-%llu,",
                       (unsigned long long)filter->max_pixels);
  }
}
