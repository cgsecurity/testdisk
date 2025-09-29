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
#include "types.h"
#include "common.h"
#include "filegen.h"
#include "photorec.h"
#include "json_log.h"
#include "log.h"

#define JSON_LOG_BUFFER_SIZE 2048

static FILE *json_log_handle = NULL;

static void json_write_timestamp(FILE *file)
{
  time_t now;
  struct tm *tm_info;
  char buffer[64];
  if (!file)
    return;

  time(&now);
  tm_info = localtime(&now);
  if (!tm_info) {
    fprintf(file, "\"timestamp\":\"1970-01-01T00:00:00+0000\"");
    return;
  }

  if (strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S%z", tm_info) == 0) {
    fprintf(file, "\"timestamp\":\"1970-01-01T00:00:00+0000\"");
    return;
  }

  fprintf(file, "\"timestamp\":\"%s\"", buffer);
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
  if (!filename)
    return -1;

  if (json_log_handle != NULL)
    return -1;

  json_log_handle = fopen(filename, "w");
  if (!json_log_handle) {
    return -1;
  }

  return 0;
}

void json_log_session_start(const struct ph_param *params, const char **argv, int argc)
{
  if (!json_log_handle)
    return;

  fprintf(json_log_handle, "{");
  json_write_timestamp(json_log_handle);
  fprintf(json_log_handle, ",\"type\":\"session_start\"");
  fprintf(json_log_handle, "}\n");
  fflush(json_log_handle);
}

void json_log_disk_info(const struct ph_param *params)
{
  if (!json_log_handle)
    return;

  fprintf(json_log_handle, "{");
  json_write_timestamp(json_log_handle);
  fprintf(json_log_handle, ",\"type\":\"disk_info\"");

  if (params->disk && params->disk->device) {
    fprintf(json_log_handle, ",\"path\":");
    json_escape_string(json_log_handle, params->disk->device);
    fprintf(json_log_handle, ",\"size_bytes\":%llu", (unsigned long long)params->disk->disk_size);
    fprintf(json_log_handle, ",\"sector_size\":%u", params->disk->sector_size);
    fprintf(json_log_handle, ",\"readonly\":%s", (params->disk->access_mode & TESTDISK_O_RDWR) ? "false" : "true");
  }

  fprintf(json_log_handle, "}\n");
  fflush(json_log_handle);
}

void json_log_partition_info(const struct ph_param *params)
{
  if (!json_log_handle || !params || !params->partition)
    return;

  fprintf(json_log_handle, "{");
  json_write_timestamp(json_log_handle);
  fprintf(json_log_handle, ",\"type\":\"partition_info\"");
  fprintf(json_log_handle, ",\"part_offset\":%llu", (unsigned long long)params->partition->part_offset);
  fprintf(json_log_handle, ",\"part_size\":%llu", (unsigned long long)params->partition->part_size);
  if (params->disk && params->disk->sector_size > 0) {
    fprintf(json_log_handle, ",\"sectors\":%llu", (unsigned long long)(params->partition->part_size / params->disk->sector_size));
  }
  fprintf(json_log_handle, "}\n");
  fflush(json_log_handle);
}

void json_log_cli_params(const struct ph_param *params, char *const*argv, int argc)
{
  if (!json_log_handle)
    return;

  fprintf(json_log_handle, "{");
  json_write_timestamp(json_log_handle);
  fprintf(json_log_handle, ",\"type\":\"cli_params\"");
  fprintf(json_log_handle, ",\"params\":[");

  for (int i = 0; i < argc; i++) {
    if (i > 0) fprintf(json_log_handle, ",");
    json_escape_string(json_log_handle, argv[i]);
  }

  fprintf(json_log_handle, "]");
  fprintf(json_log_handle, "}\n");
  fflush(json_log_handle);
}

void json_log_session_resume(const struct ph_param *params, const char *saved_device, const char *saved_cmd, int search_space_regions)
{
  if (!json_log_handle)
    return;

  fprintf(json_log_handle, "{");
  json_write_timestamp(json_log_handle);
  fprintf(json_log_handle, ",\"type\":\"session_resume\"");
  fprintf(json_log_handle, ",\"loaded_params\":{");
  fprintf(json_log_handle, "\"device\":");
  json_escape_string(json_log_handle, saved_device);
  fprintf(json_log_handle, ",\"cmd\":");
  json_escape_string(json_log_handle, saved_cmd);
  fprintf(json_log_handle, ",\"search_space_regions\":%d", search_space_regions);
  fprintf(json_log_handle, "}");
  fprintf(json_log_handle, ",\"resume_from\":{");
  fprintf(json_log_handle, "\"offset\":%llu", (unsigned long long)params->offset);
  fprintf(json_log_handle, ",\"files_already_found\":%u", params->file_nbr);
  fprintf(json_log_handle, "}");
  fprintf(json_log_handle, "}\n");
  fflush(json_log_handle);
}

void json_log_progress(const struct ph_param *params, const unsigned int pass, const uint64_t offset)
{
  const time_t current_time = time(NULL);
  if (!json_log_handle || !params || !params->partition || !params->disk || params->disk->sector_size == 0)
    return;

  fprintf(json_log_handle, "{");
  json_write_timestamp(json_log_handle);
  fprintf(json_log_handle, ",\"type\":\"progress\"");
  fprintf(json_log_handle, ",\"pass\":%u", pass);
  fprintf(json_log_handle, ",\"current_sector\":%llu", (unsigned long long)((offset - params->partition->part_offset) / params->disk->sector_size));
  fprintf(json_log_handle, ",\"total_sectors\":%llu", (unsigned long long)(params->partition->part_size / params->disk->sector_size));
  fprintf(json_log_handle, ",\"files_found\":%u", params->file_nbr);

  if (current_time > params->real_start_time) {
    const time_t elapsed_time = current_time - params->real_start_time;
    fprintf(json_log_handle, ",\"elapsed_time\":\"%uh%02um%02us\"",
        (unsigned)(elapsed_time/3600),
        (unsigned)(elapsed_time/60%60),
        (unsigned)(elapsed_time%60));

    if (offset > params->partition->part_offset && params->status != STATUS_EXT2_ON_BF && params->status != STATUS_EXT2_OFF_BF) {
      const time_t eta = (params->partition->part_offset + params->partition->part_size - 1 - offset) * elapsed_time / (offset - params->partition->part_offset);
      fprintf(json_log_handle, ",\"estimated_time\":\"%uh%02um%02us\"",
          (unsigned)(eta/3600),
          (unsigned)((eta/60)%60),
          (unsigned)(eta%60));
    }
  }

  if (params->file_stats) {
    int first = 1;
    fprintf(json_log_handle, ",\"file_stats\":{");
    for (unsigned int i = 0; params->file_stats[i].file_hint != NULL; i++) {
      if (params->file_stats[i].recovered > 0) {
        if (!first) fprintf(json_log_handle, ",");
        first = 0;
        fprintf(json_log_handle, "\"%s\":%u",
            params->file_stats[i].file_hint->extension ? params->file_stats[i].file_hint->extension : "unknown",
            params->file_stats[i].recovered);
      }
    }
    fprintf(json_log_handle, "}");
  }

  fprintf(json_log_handle, "}\n");
  fflush(json_log_handle);
}

void json_log_completion(const struct ph_param *params, const char *completion_message)
{
  const time_t final_time = time(NULL);
  if (!json_log_handle)
    return;

  fprintf(json_log_handle, "{");
  json_write_timestamp(json_log_handle);
  fprintf(json_log_handle, ",\"type\":\"completion\"");

  if (final_time > params->real_start_time) {
    const time_t elapsed_time = final_time - params->real_start_time;
    fprintf(json_log_handle, ",\"elapsed_time\":\"%uh%02um%02us\"",
        (unsigned)(elapsed_time/3600),
        (unsigned)(elapsed_time/60%60),
        (unsigned)(elapsed_time%60));
  }

  fprintf(json_log_handle, ",\"total_files\":%u", params->file_nbr);

  if (params->file_stats) {
    int first = 1;
    fprintf(json_log_handle, ",\"final_stats\":{");
    for (unsigned int i = 0; params->file_stats[i].file_hint != NULL; i++) {
      if (params->file_stats[i].recovered > 0) {
        if (!first) fprintf(json_log_handle, ",");
        first = 0;
        fprintf(json_log_handle, "\"%s\":%u",
            params->file_stats[i].file_hint->extension ? params->file_stats[i].file_hint->extension : "unknown",
            params->file_stats[i].recovered);
      }
    }
    fprintf(json_log_handle, "}");
  }

  fprintf(json_log_handle, ",\"status\":");
  json_escape_string(json_log_handle, completion_message);
  fprintf(json_log_handle, "}\n");
  fflush(json_log_handle);
}

static const char* log_level_to_string(const unsigned int level)
{
  switch(level) {
    case LOG_LEVEL_DEBUG:    return "debug";
    case LOG_LEVEL_TRACE:    return "trace";
    case LOG_LEVEL_QUIET:    return "quiet";
    case LOG_LEVEL_INFO:     return "info";
    case LOG_LEVEL_VERBOSE:  return "verbose";
    case LOG_LEVEL_PROGRESS: return "progress";
    case LOG_LEVEL_WARNING:  return "warning";
    case LOG_LEVEL_ERROR:    return "error";
    case LOG_LEVEL_PERROR:   return "perror";
    case LOG_LEVEL_CRITICAL: return "critical";
    default:                 return "unknown";
  }
}

static void clean_log_message(char *message)
{
  char *src;
  char *dst;
  if (!message)
    return;

  src = message;
  dst = message;

  while (*src == ' ' || *src == '\t')
    src++;

  while (*src) {
    if (*src != '\n' && *src != '\t') {
      *dst++ = *src;
    }
    src++;
  }
  *dst = '\0';

  dst--;
  while (dst >= message && (*dst == ' ' || *dst == '\t')) {
    *dst = '\0';
    dst--;
  }
}

static void json_write_log_entry(const char *level_str, const char *message)
{
  char cleaned_message[JSON_LOG_BUFFER_SIZE];
  if (!json_log_handle || !level_str || !message)
    return;

  strncpy(cleaned_message, message, sizeof(cleaned_message) - 1);
  cleaned_message[sizeof(cleaned_message) - 1] = '\0';
  clean_log_message(cleaned_message);

  if (cleaned_message[0] == '\0')
    return;

  fprintf(json_log_handle, "{");
  json_write_timestamp(json_log_handle);
  fprintf(json_log_handle, ",\"type\":\"log\"");
  fprintf(json_log_handle, ",\"level\":\"%s\"", level_str);
  fprintf(json_log_handle, ",\"message\":");
  json_escape_string(json_log_handle, cleaned_message);
  fprintf(json_log_handle, "}\n");
  fflush(json_log_handle);
}

void json_log_handler(const unsigned int level, const char *format, va_list ap)
{
  char message[JSON_LOG_BUFFER_SIZE];
  const unsigned int clean_level = level;
  const char *level_str;
  if (!json_log_handle || !format)
    return;

  level_str = log_level_to_string(clean_level);

  vsnprintf(message, sizeof(message), format, ap);

  json_write_log_entry(level_str, message);
}

void json_log_cleanup(const struct ph_param *params)
{
  if (json_log_handle) {
    fclose(json_log_handle);
    json_log_handle = NULL;
  }
}
