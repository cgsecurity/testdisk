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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_xm)
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

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_xm(file_stat_t *file_stat);

const file_hint_t file_hint_xm = {
  .extension = "xm",
  .description = "FastTrackerII Extended Module",
  .max_filesize = PHOTOREC_MAX_FILE_SIZE,
  .recover = 1,
  .enable_by_default = 1,
  .register_header_check = &register_header_check_xm
};

struct xm_hdr
{
  uint16_t patterns;
  uint16_t instrs;
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires \valid(fr);
  @ requires valid_file_recovery(fr);
  @ requires \separated(fr, fr->handle, fr->extension, &errno, &Frama_C_entropy_source);
  @ ensures \valid(fr->handle);
  @ assigns *fr->handle, errno, fr->file_size;
  @ assigns Frama_C_entropy_source;
  @*/
static int parse_patterns(file_recovery_t *fr, uint16_t patterns)
{
  /*@
    @ loop assigns *fr->handle, errno, fr->file_size;
    @ loop assigns Frama_C_entropy_source;
    @ loop assigns patterns;
    @ loop variant patterns;
    @*/
  for(; patterns != 0; patterns--)
  {
    char buffer[sizeof(uint32_t)];
    const uint16_t *p16 = (const uint16_t *)&buffer;
    const uint32_t *p32 = (const uint32_t *)&buffer;
    uint32_t header_size;
    uint16_t data_size;
    if(fread(&buffer, sizeof(uint32_t), 1, fr->handle) != 1)
      return -1;
#if defined(__FRAMAC__)
    Frama_C_make_unknown(&buffer, sizeof(uint32_t));
#endif
    header_size = le32(*p32);
#ifndef DISABLED_FOR_FRAMAC
    log_debug("xm: pattern header of size %u\n", (unsigned int)header_size);
#endif
    /* Never seen any xm having anything but 9 here */
    if(header_size != 9)
      return -1;

    /* Packing type + row count skipped */
    if(fseek(fr->handle, 1 + 2, SEEK_CUR) == -1)
      return -1;
    if(fread(&buffer, sizeof(uint16_t), 1, fr->handle) != 1)
      return -1;
#if defined(__FRAMAC__)
    Frama_C_make_unknown(&buffer, sizeof(uint16_t));
#endif
    data_size = le16(*p16);
#ifndef DISABLED_FOR_FRAMAC
    log_debug("xm: pattern data of size %u\n", data_size);
#endif

    if(fseek(fr->handle, data_size, SEEK_CUR) == -1)
      return -1;
    fr->file_size += (uint64_t)header_size + data_size;
    if(fr->file_size > PHOTOREC_MAX_FILE_SIZE)
      return -1;
  }
  return 0;
}

/*@
  @ requires \valid(fr);
  @ requires valid_file_recovery(fr);
  @ requires \separated(fr, fr->handle, fr->extension, &errno, &Frama_C_entropy_source);
  @ ensures \valid(fr->handle);
  @ assigns *fr->handle, errno, fr->file_size;
  @ assigns Frama_C_entropy_source;
  @*/
static int parse_instruments(file_recovery_t *fr, uint16_t instrs)
{
  /*@
    @ loop assigns *fr->handle, errno, fr->file_size;
    @ loop assigns Frama_C_entropy_source;
    @ loop assigns instrs;
    @ loop variant instrs;
    @*/
  for(; instrs != 0; instrs--)
  {
    char buffer[sizeof(uint32_t)];
    const uint16_t *p16 = (const uint16_t *)&buffer;
    const uint32_t *p32 = (const uint32_t *)&buffer;
    uint16_t samples;
    uint32_t size;

    if(fread(&buffer, sizeof(uint32_t), 1, fr->handle) != 1)
      return -1;
#if defined(__FRAMAC__)
    Frama_C_make_unknown(&buffer, sizeof(uint32_t));
#endif

    size = le32(*p32);
#ifndef DISABLED_FOR_FRAMAC
    log_debug("xm: instrument header of size %u\n", (unsigned int)size);
#endif
    if(size < 29)
      return -1;

    /* Fixed string + type skipped               *
     * @todo Verify that fixed string is ASCII ? */
    if(fseek(fr->handle, 22 + 1, SEEK_CUR) == -1)
      return -1;

    if(fread(&buffer, sizeof(uint16_t), 1, fr->handle) != 1)
      return -1;
#if defined(__FRAMAC__)
    Frama_C_make_unknown(&buffer, sizeof(uint16_t));
#endif
    samples = le16(*p16);
#ifndef DISABLED_FOR_FRAMAC
    log_debug("xm: instrument with %u samples\n", samples);
#endif

    fr->file_size += size;
    if(fr->file_size > PHOTOREC_MAX_FILE_SIZE)
      return -1;
    /* Never seen any xm having anything but 263 when there are samples */
    if(samples > 0)
    {
      if(size != 263)
      {
#ifndef DISABLED_FOR_FRAMAC
        log_debug("xm: UNEXPECTED HEADER SIZE OF %u, "
                  " PLEASE REPORT THE FILE!\n",
                  (unsigned int)size);
#endif
        return -1;
      }

      /* 2ndary header skipped */
      if(fseek(fr->handle, 234, SEEK_CUR) == -1)
        return -1;

      /*@
        @ loop assigns samples, size, *fr->handle, errno, Frama_C_entropy_source, fr->file_size, buffer[0..3];
	@ loop variant samples;
	@*/
      for(; samples != 0; samples--)
      {
        if(fread(&buffer, sizeof(uint32_t), 1, fr->handle) != 1)
          return -1;
#if defined(__FRAMAC__)
        Frama_C_make_unknown(&buffer, sizeof(uint32_t));
#endif
        size = le32(*p32);
#ifndef DISABLED_FOR_FRAMAC
        log_debug("xm: sample with length of %u\n", (unsigned int)size);
#endif

        /* Skip remaining of sample header            *
         * @todo Verify that last 22 bytes are ASCII? */
        if(fseek(fr->handle, (uint64_t)36 + size, SEEK_CUR) == -1)
          return -1;

        fr->file_size += (uint64_t)40 + size;
        if(fr->file_size > PHOTOREC_MAX_FILE_SIZE)
          return -1;
      }
    }
    /* No sample, account for garbage */
    else if(fseek(fr->handle, size - 29, SEEK_CUR) == -1)
      return -1;
  }
  return 0;
}

/*@
  @ requires fr->file_check == &file_check_xm;
  @ requires valid_file_check_param(fr);
  @ ensures  valid_file_check_result(fr);
  @ assigns *fr->handle, fr->file_size, fr->offset_error;
  @ assigns Frama_C_entropy_source, errno;
  @*/
static void file_check_xm(file_recovery_t *fr)
{
  char buffer[4];
  const struct xm_hdr *hdr=(const struct xm_hdr *)&buffer;
  uint16_t patterns, instrs;

  fr->file_size = 0;
  fr->offset_error = 0;

  if(fseek(fr->handle, 70, SEEK_SET) == -1)
    return;
  if(fread(&buffer, sizeof(buffer), 1, fr->handle) != 1)
    return;
#if defined(__FRAMAC__)
  Frama_C_make_unknown(&buffer, sizeof(buffer));
#endif
  instrs = le16(hdr->instrs);
  patterns = le16(hdr->patterns);

#ifndef DISABLED_FOR_FRAMAC
  log_debug("xm: %u patterns, %u instruments\n", patterns, instrs);
#endif

  /* Skip flags + tempo + bmp + table */
  if(fseek(fr->handle, 2 + 2 + 2 + 256, SEEK_CUR) == -1)
    return;
  fr->file_size = 336;

  /* Parse patterns and next instruments */
  if(parse_patterns(fr, patterns) < 0 || parse_instruments(fr, instrs) < 0)
  {
#ifndef DISABLED_FOR_FRAMAC
    log_debug("xm: lost sync at pos %li\n", ftell(fr->handle));
#endif
    fr->offset_error = fr->file_size;
    fr->file_size = 0;
    return;
  }
  /* ModPlug may insert additional data but it is of little relevance */
}

/*@
  @ requires separation: \separated(&file_hint_xm, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_xm(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension = file_hint_xm.extension;
  file_recovery_new->min_filesize = 336 + 29; /* Header + 1 instrument */
  file_recovery_new->file_check = &file_check_xm;
  return 1;
}

static void register_header_check_xm(file_stat_t *file_stat)
{
  static const unsigned char xm_header[17] = { 'E', 'x', 't', 'e', 'n', 'd', 'e', 'd', ' ', 'M', 'o', 'd', 'u', 'l', 'e', ':', ' ' };
  register_header_check(0, xm_header, sizeof(xm_header), &header_check_xm, file_stat);
}
#endif
