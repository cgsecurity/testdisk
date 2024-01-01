/*

    File: file_wv.c

    Copyright (C) 2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_wv)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "filegen.h"
#include "common.h"

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_wv(file_stat_t *file_stat);

const file_hint_t file_hint_wv = {
  .extension = "wv",
  .description = "WavPack, Hybrid Lossless Wavefile Compressor",
  .max_filesize = 100 * 1024 * 1024,
  .recover = 1,
  .enable_by_default = 1,
  .register_header_check = &register_header_check_wv
};

/* See http://www.wavpack.com/file_format.txt for file format description */

static const unsigned char wv_header[4] = { 'w', 'v', 'p', 'k' };
typedef struct
{
  char ckID[4];           // "wvpk"
  uint32_t ckSize;        // size of entire block (minus 8, of course)
  uint16_t version;       // 0x402 to 0x410 are currently valid for decode
  unsigned char track_no; // track number (0 if not used, like now)
  unsigned char index_no; // track sub-index (0 if not used, like now)
  uint32_t total_samples; // total samples for entire file, but this is
                          // only valid if block_index == 0 and a value of
                          // -1 indicates unknown length
  uint32_t block_index;   // index of first sample in block relative to
                          // beginning of file (normally this would start
                          // at 0 for the first block)
  uint32_t block_samples; // number of samples in this block (0 = no audio)
  uint32_t flags;         // various flags for id and decoding
  uint32_t crc;           // crc for actual decoded data
} WavpackHeader;

/*@
  @ requires file_recovery->data_check==&data_check_wv;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ assigns file_recovery->calculated_file_size;
  @*/
static data_check_t data_check_wv(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@
    @ loop assigns file_recovery->calculated_file_size;
    @ loop variant file_recovery->file_size + buffer_size / 2 - (file_recovery->calculated_file_size + 16);
    @*/
  while(file_recovery->calculated_file_size + buffer_size / 2 >= file_recovery->file_size && file_recovery->calculated_file_size + 16 <= file_recovery->file_size + buffer_size / 2)
  {
    const unsigned int i = file_recovery->calculated_file_size + buffer_size / 2 - file_recovery->file_size;
    /*@ assert 0 <= i <= buffer_size - 16; */
    const WavpackHeader *wv = (const WavpackHeader *)&buffer[i];
    if(memcmp(wv, wv_header, sizeof(wv_header)) == 0)
    {
      file_recovery->calculated_file_size += (uint64_t)8 + le32(wv->ckSize);
    }
    else if(buffer[i] == 'A' && buffer[i + 1] == 'P' && buffer[i + 2] == 'E' && buffer[i + 3] == 'T' && buffer[i + 4] == 'A' && buffer[i + 5] == 'G' && buffer[i + 6] == 'E' && buffer[i + 7] == 'X')
    { /* APE Tagv2 (APE Tagv1 has no header) http://wiki.hydrogenaudio.org/index.php?title=APE_Tags_Header */
      const uint64_t ape_tag_size = (buffer[i + 12] + (buffer[i + 13] << 8) + (buffer[i + 14] << 16) + ((uint64_t)buffer[i + 15] << 24)) + 32;
      /*@ assert ape_tag_size > 0; */
      file_recovery->calculated_file_size += ape_tag_size;
    }
    else if(buffer[i] == 'T' && buffer[i + 1] == 'A' && buffer[i + 2] == 'G')
    { /* http://www.id3.org/ID3v1 TAGv1 size = 128 bytes with header "TAG" */
      file_recovery->calculated_file_size += 128;
    }
    else if(file_recovery->calculated_file_size > file_recovery->file_size)
    {
      return DC_CONTINUE;
    }
    else
    {
      return DC_STOP;
    }
  }
  return DC_CONTINUE;
}

/*@
  @ requires buffer_size >= sizeof(WavpackHeader);
  @ requires separation: \separated(&file_hint_wv, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_wv(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const WavpackHeader *wv = (const WavpackHeader *)buffer;
  const uint32_t ckSize = le32(wv->ckSize);
  if(le32(wv->block_index) != 0)
    return 0;
  if(sizeof(WavpackHeader) > (uint64_t)ckSize + 8)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension = file_hint_wv.extension;
  file_recovery_new->min_filesize = (uint64_t)ckSize + 8;
  if(file_recovery_new->blocksize < 8)
    return 1;
  file_recovery_new->data_check = &data_check_wv;
  file_recovery_new->file_check = &file_check_size;
  return 1;
}

static void register_header_check_wv(file_stat_t *file_stat)
{
  register_header_check(0, wv_header, sizeof(wv_header), &header_check_wv, file_stat);
}
#endif
