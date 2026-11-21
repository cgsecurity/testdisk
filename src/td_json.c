/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include "types.h"
#include "common.h"
#include "intrf.h"
#include "td_json.h"

static FILE *json_log;

int td_json_open(const char *filename)
{
  int flags=O_WRONLY|O_CREAT|O_EXCL;
  int fd;
#ifdef O_BINARY
  flags|=O_BINARY;
#endif
  /* The output path may be the image being searched. */
  fd=open(filename, flags, 0600);
  if(fd<0)
    return -1;
  json_log=fdopen(fd, "wb");
  if(json_log==NULL)
  {
    const int error=errno;
    close(fd);
    errno=error;
    return -1;
  }
  return 0;
}

/* The names passed here come from TestDisk's partition type tables. */
static void json_write_string(FILE *out, const char *value)
{
  if(value==NULL)
  {
    fputs("null", out);
    return;
  }
  fputc('"', out);
  for(; *value!='\0'; value++)
  {
    const unsigned char c=(unsigned char)*value;
    if(c<' ')
      fprintf(out, "\\u%04x", (unsigned int)c);
    else
    {
      if(c=='"' || c=='\\')
	fputc('\\', out);
      fputc(c, out);
    }
  }
  fputc('"', out);
}

void td_json_search(const disk_t *disk, const list_part_t *partitions, const int deeper, const int aborted)
{
  const list_part_t *entry;
  if(json_log==NULL)
    return;
  fprintf(json_log, "{\"search\":\"%s\",\"aborted\":%s,\"sector_size_bytes\":%u,\"disk_size_bytes\":%llu,\"partition_table\":",
      deeper ? "deeper" : "quick", aborted ? "true" : "false", disk->sector_size,
      (long long unsigned)disk->disk_size);
  json_write_string(json_log, disk->arch->part_name_option);
  fputs(",\"partitions\":[", json_log);
  for(entry=partitions; entry!=NULL; entry=entry->next)
  {
    const partition_t *partition=entry->part;
    if(entry!=partitions)
      fputc(',', json_log);
    fprintf(json_log, "{\"offset_bytes\":%llu,\"size_bytes\":%llu,\"status\":\"%c\",\"type\":",
        (long long unsigned)partition->part_offset, (long long unsigned)partition->part_size,
        get_partition_status(partition));
    json_write_string(json_log, partition->arch->get_partition_typename(partition));
    fputc('}', json_log);
  }
  fputs("]}\n", json_log);
  fflush(json_log);
}

int td_json_close(void)
{
  int error;
  if(json_log==NULL)
    return 0;
  error=ferror(json_log);
  if(fclose(json_log)!=0)
    error=1;
  json_log=NULL;
  return error;
}
