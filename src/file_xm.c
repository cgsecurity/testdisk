/*

    File: file_xm.c

    Copyright (C) 2007 Christophe GRENIER <grenier@cgsecurity.org>
    Copyright (C) 2007 Christophe GISQUET <christophe.gisquet@free.fr>

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
#include "types.h"
#include "common.h"
#include "filegen.h"
#include "log.h"

static void register_header_check_xm(file_stat_t *file_stat);
static int header_check_xm(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_xm= {
  .extension="xm",
  .description="FastTrackerII Extended Module",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_xm
};

static int parse_patterns(file_recovery_t *fr, uint16_t patterns)
{
  while (patterns--)
  {
    uint32_t header_size;
    uint16_t data_size;

    if (fread(&header_size, 4, 1, fr->handle) != 1)
      return -1;

    header_size = le32(header_size);
    log_debug("xm: pattern header of size %u\n", (unsigned int)header_size);
    /* Never seen any xm having anything but 9 here */
    if (header_size != 9)
      return -1;

    /* Packing type + row count skipped */
    if (fseek(fr->handle, 1+2, SEEK_CUR) == -1)
      return -1;

    if (fread(&data_size, 2, 1, fr->handle) != 1)
      return -1;
    data_size = le16(data_size);
    log_debug("xm: pattern data of size %u\n", data_size);

    if (fseek(fr->handle, data_size, SEEK_CUR) == -1)
      return -1;
    fr->file_size += header_size+data_size;
  }
  return 0;
}

static int parse_instruments(file_recovery_t *fr, uint16_t instrs)
{
  while (instrs--)
  {
    uint16_t samples;
    uint32_t size;

    if (fread(&size, 4, 1, fr->handle) != 1)
      return -1;

    size = le32(size);
    log_debug("xm: instrument header of size %u\n", (unsigned int)size);
    if (size < 29)
      return -1;

    /* Fixed string + type skipped               *
     * @todo Verify that fixed string is ASCII ? */
    if (fseek(fr->handle, 22+1, SEEK_CUR) == -1)
      return -1;

    if (fread(&samples, 2, 1, fr->handle) != 1)
      return -1;
    samples = le16(samples);
    log_debug("xm: instrument with %u samples\n", samples);

    fr->file_size += size;
    /* Never seen any xm having anything but 263 when there are samples */
    if (samples>0)
    {
      if (size!=263)
      {
        log_debug("xm: UNEXPECTED HEADER SIZE OF %u, "
                  " PLEASE REPORT THE FILE!\n", (unsigned int)size);
        return -1;
      }

      /* 2ndary header skipped */
      if (fseek(fr->handle, 234, SEEK_CUR) == -1)
        return -1;


      while (samples--)
      {
        if (fread(&size, 4, 1, fr->handle) != 1)
          return -1;

        size = le32(size);
        log_debug("xm: sample with length of %u\n", (unsigned int)size);

        /* Skip remaining of sample header            *
         * @todo Verify that last 22 bytes are ASCII? */
        if (fseek(fr->handle, 36+size, SEEK_CUR) == -1)
          return -1;

        fr->file_size += 40+size;
      }
    }
    /* No sample, account for garbage */
    else if (fseek(fr->handle, size-29, SEEK_CUR) == -1)
      return -1;
  }
  return 0;
}

static void file_check_xm(file_recovery_t *fr)
{
  uint16_t patterns, instrs;

  fr->file_size = 0;
  fr->offset_error=0;
  fr->offset_ok=0;

  if (fseek(fr->handle, 70, SEEK_SET) == -1)
    return;
  if (fread(&patterns, 2, 1, fr->handle) != 1)
    return;
  if (fread(&instrs, 2, 1, fr->handle) != 1)
    return;
  instrs   = le16(instrs);
  patterns = le16(patterns);

  log_debug("xm: %u patterns, %u instruments\n", patterns, instrs);

  /* Skip flags + tempo + bmp + table */
  if (fseek(fr->handle, 2+2+2+256, SEEK_CUR) == -1)
    return;
  fr->file_size = 336;

  /* Parse patterns and next instruments */
  if (parse_patterns(fr, patterns) < 0 ||
      parse_instruments(fr, instrs) < 0)
  {
    log_debug("xm: lost sync at pos %li\n", ftell(fr->handle));
    fr->offset_error = fr->file_size;
    fr->file_size = 0;
    return;
  }

  /* ModPlug may insert additional data but it is of little relevance */
}


static const unsigned char xm_header[17]  = { 'E','x','t','e','n','d','e','d',' ','M','o','d','u','l','e',':',' '};

static void register_header_check_xm(file_stat_t *file_stat)
{
  register_header_check(0, xm_header,sizeof(xm_header), &header_check_xm, file_stat);
}

static int header_check_xm(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(buffer,xm_header,sizeof(xm_header))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_xm.extension;
    file_recovery_new->min_filesize=336 + 29; /* Header + 1 instrument */
    file_recovery_new->file_check=&file_check_xm;
    return 1;
  }
  return 0;
}
