/*

    File: json_log.c

    Copyright (C) 2025 JSON logging for PhotoRec progress information

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

#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <errno.h>
#include "types.h"
#include "common.h"
#include "filegen.h"
#include "photorec.h"
#include "json_log.h"

static FILE *json_log_file = NULL;

static void json_write_timestamp(FILE *file)
{
  if (!file)
    return;

  time_t now;
  struct tm *tm_info;
  char buffer[64];

  time(&now);
  tm_info = localtime(&now);
  if (!tm_info) {
    fprintf(file, "\"timestamp\": \"1970-01-01T00:00:00+0000\"");
    return;
  }

  if (strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S%z", tm_info) == 0) {
    fprintf(file, "\"timestamp\": \"1970-01-01T00:00:00+0000\"");
    return;
  }

  fprintf(file, "\"timestamp\": \"%s\"", buffer);
}

static void json_escape_string(FILE *file, const char *str)
{
  if (!str) {
    fprintf(file, "null");
    return;
  }

  fprintf(file, "\"");
  while (*str) {
    switch (*str) {
      case '"':
        fprintf(file, "\\\"");
        break;
      case '\\':
        fprintf(file, "\\\\");
        break;
      case '\b':
        fprintf(file, "\\b");
        break;
      case '\f':
        fprintf(file, "\\f");
        break;
      case '\n':
        fprintf(file, "\\n");
        break;
      case '\r':
        fprintf(file, "\\r");
        break;
      case '\t':
        fprintf(file, "\\t");
        break;
      default:
        if ((unsigned char)*str < 0x20) {
          fprintf(file, "\\u%04x", (unsigned char)*str);
        } else {
          fputc(*str, file);
        }
        break;
    }
    str++;
  }
  fprintf(file, "\"");
}

int json_log_open(const char *filename)
{
  if (!filename || json_log_file != NULL)
    return 0;

  json_log_file = fopen(filename, "w");
  if (!json_log_file) {
    return -1;
  }

  return 0;
}

void json_log_session_start(const struct ph_param *params, const char **argv, int argc)
{
  if (!json_log_file)
    return;

  fprintf(json_log_file, "{");
  json_write_timestamp(json_log_file);
  fprintf(json_log_file, ", \"type\": \"session_start\"");
  fprintf(json_log_file, "}\n");
  fflush(json_log_file);
}

void json_log_disk_info(const struct ph_param *params)
{
  if (!json_log_file)
    return;

  fprintf(json_log_file, "{");
  json_write_timestamp(json_log_file);
  fprintf(json_log_file, ", \"type\": \"disk_info\"");

  if (params->disk && params->disk->device) {
    fprintf(json_log_file, ", \"path\": ");
    json_escape_string(json_log_file, params->disk->device);
    fprintf(json_log_file, ", \"size_bytes\": %llu", (unsigned long long)params->disk->disk_size);
    fprintf(json_log_file, ", \"sector_size\": %u", params->disk->sector_size);
    fprintf(json_log_file, ", \"readonly\": %s", (params->disk->access_mode & TESTDISK_O_RDWR) ? "false" : "true");
  }

  fprintf(json_log_file, "}\n");
  fflush(json_log_file);
}

void json_log_partition_info(const struct ph_param *params)
{
  if (!json_log_file || !params || !params->partition)
    return;

  fprintf(json_log_file, "{");
  json_write_timestamp(json_log_file);
  fprintf(json_log_file, ", \"type\": \"partition_info\"");
  fprintf(json_log_file, ", \"part_offset\": %llu", (unsigned long long)params->partition->part_offset);
  fprintf(json_log_file, ", \"part_size\": %llu", (unsigned long long)params->partition->part_size);
  if (params->disk && params->disk->sector_size > 0) {
    fprintf(json_log_file, ", \"sectors\": %llu", (unsigned long long)(params->partition->part_size / params->disk->sector_size));
  }
  fprintf(json_log_file, "}\n");
  fflush(json_log_file);
}

void json_log_cli_params(const struct ph_param *params, const char **argv, int argc)
{
  if (!json_log_file)
    return;

  fprintf(json_log_file, "{");
  json_write_timestamp(json_log_file);
  fprintf(json_log_file, ", \"type\": \"cli_params\"");
  fprintf(json_log_file, ", \"params\": [");

  for (int i = 0; i < argc; i++) {
    if (i > 0) fprintf(json_log_file, ",");
    json_escape_string(json_log_file, argv[i]);
  }

  fprintf(json_log_file, "]");
  fprintf(json_log_file, "}\n");
  fflush(json_log_file);
}

void json_log_session_resume(const struct ph_param *params, const char *saved_device, const char *saved_cmd, int search_space_regions)
{
  if (!json_log_file)
    return;

  fprintf(json_log_file, "{");
  json_write_timestamp(json_log_file);
  fprintf(json_log_file, ", \"type\": \"session_resume\"");
  fprintf(json_log_file, ", \"loaded_params\": {");
  fprintf(json_log_file, "\"device\": ");
  json_escape_string(json_log_file, saved_device);
  fprintf(json_log_file, ", \"cmd\": ");
  json_escape_string(json_log_file, saved_cmd);
  fprintf(json_log_file, ", \"search_space_regions\": %d", search_space_regions);
  fprintf(json_log_file, "}");
  fprintf(json_log_file, ", \"resume_from\": {");
  fprintf(json_log_file, "\"offset\": %llu", (unsigned long long)params->offset);
  fprintf(json_log_file, ", \"files_already_found\": %u", params->file_nbr);
  fprintf(json_log_file, "}");
  fprintf(json_log_file, "}\n");
  fflush(json_log_file);
}

void json_log_progress(const struct ph_param *params, const unsigned int pass, const uint64_t offset, const time_t current_time)
{
  if (!json_log_file || !params || !params->partition || !params->disk || params->disk->sector_size == 0)
    return;

  fprintf(json_log_file, "{");
  json_write_timestamp(json_log_file);
  fprintf(json_log_file, ", \"type\": \"progress\"");
  fprintf(json_log_file, ", \"pass\": %u", pass);
  fprintf(json_log_file, ", \"current_sector\": %llu", (unsigned long long)((offset - params->partition->part_offset) / params->disk->sector_size));
  fprintf(json_log_file, ", \"total_sectors\": %llu", (unsigned long long)(params->partition->part_size / params->disk->sector_size));
  fprintf(json_log_file, ", \"files_found\": %u", params->file_nbr);

  if (current_time > params->real_start_time) {
    const time_t elapsed_time = current_time - params->real_start_time;
    fprintf(json_log_file, ", \"elapsed_time\": \"%uh%02um%02us\"",
        (unsigned)(elapsed_time/60/60),
        (unsigned)(elapsed_time/60%60),
        (unsigned)(elapsed_time%60));

    if (offset > params->partition->part_offset && params->status != STATUS_EXT2_ON_BF && params->status != STATUS_EXT2_OFF_BF) {
      const time_t eta = (params->partition->part_offset + params->partition->part_size - 1 - offset) * elapsed_time / (offset - params->partition->part_offset);
      fprintf(json_log_file, ", \"estimated_time\": \"%uh%02um%02u\"",
          (unsigned)(eta/3600),
          (unsigned)((eta/60)%60),
          (unsigned)(eta%60));
    }
  }

  if (params->file_stats) {
    fprintf(json_log_file, ", \"file_stats\": {");
    int first = 1;
    for (unsigned int i = 0; params->file_stats[i].file_hint != NULL; i++) {
      if (params->file_stats[i].recovered > 0) {
        if (!first) fprintf(json_log_file, ",");
        first = 0;
        fprintf(json_log_file, "\"%s\": %u",
            params->file_stats[i].file_hint->extension ? params->file_stats[i].file_hint->extension : "unknown",
            params->file_stats[i].recovered);
      }
    }
    fprintf(json_log_file, "}");
  }

  fprintf(json_log_file, "}\n");
  fflush(json_log_file);
}

void json_log_completion(const struct ph_param *params, const time_t final_time, const char *completion_message)
{
  if (!json_log_file)
    return;

  fprintf(json_log_file, "{");
  json_write_timestamp(json_log_file);
  fprintf(json_log_file, ", \"type\": \"completion\"");

  if (final_time > params->real_start_time) {
    const time_t elapsed_time = final_time - params->real_start_time;
    fprintf(json_log_file, ", \"elapsed_time\": \"%uh%02um%02us\"",
        (unsigned)(elapsed_time/60/60),
        (unsigned)(elapsed_time/60%60),
        (unsigned)(elapsed_time%60));
  }

  fprintf(json_log_file, ", \"total_files\": %u", params->file_nbr);

  if (params->file_stats) {
    fprintf(json_log_file, ", \"final_stats\": {");
    int first = 1;
    for (unsigned int i = 0; params->file_stats[i].file_hint != NULL; i++) {
      if (params->file_stats[i].recovered > 0) {
        if (!first) fprintf(json_log_file, ",");
        first = 0;
        fprintf(json_log_file, "\"%s\": %u",
            params->file_stats[i].file_hint->extension ? params->file_stats[i].file_hint->extension : "unknown",
            params->file_stats[i].recovered);
      }
    }
    fprintf(json_log_file, "}");
  }

  fprintf(json_log_file, ", \"status\": ");
  json_escape_string(json_log_file, completion_message);
  fprintf(json_log_file, "}\n");
  fflush(json_log_file);
}

void json_log_cleanup(const struct ph_param *params)
{
  if (json_log_file) {
    fclose(json_log_file);
    json_log_file = NULL;
  }
}