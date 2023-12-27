/*

    File: file_mid.c

    Copyright (C) 1998-2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mid)
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
#include "log.h"

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_mid(file_stat_t *file_stat);

const file_hint_t file_hint_mid= {
  .extension="mid",
  .description="MIDI Musical Instrument Digital Interface",
  .max_filesize=50*1024*1024,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_mid
};

/* See http://www.sonicspot.com/guide/midifiles.html for more information about MIDI file format */

struct midi_header
{
  char magic[4];
  uint32_t len;		/* = 6 */
  uint16_t format;
  uint16_t tracks;
  int16_t time_division;
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires file_recovery->file_check == &file_check_midi;
  @ requires separation: \separated(file_recovery, file_recovery->handle, &errno, &Frama_C_entropy_source);
  @ requires valid_file_check_param(file_recovery);
  @ ensures  valid_file_check_result(file_recovery);
  @ assigns  errno;
  @ assigns  file_recovery->calculated_file_size;
  @ assigns  file_recovery->file_size;
  @ assigns  *file_recovery->handle;
  @ assigns  file_recovery->time;
  @ assigns  Frama_C_entropy_source;
  @*/
static void file_check_midi(file_recovery_t *file_recovery)
{
  const uint64_t fs_org=file_recovery->file_size;
  struct midi_header hdr;
  unsigned int i;
  unsigned int tracks;
  uint64_t fs=4+4+6;
  file_recovery->file_size=0;
  if(my_fseek(file_recovery->handle, 0, SEEK_SET) < 0 ||
      fread(&hdr, sizeof(hdr), 1, file_recovery->handle) != 1)
    return ;
  tracks=be16(hdr.tracks);
  /*@
    @ loop assigns i, *file_recovery->handle, fs;
    @ loop assigns errno, Frama_C_entropy_source;
    @ loop variant tracks - i;
    @*/
  for(i=0; i<tracks; i++)
  {
    struct midi_header track;
#ifdef DEBUG_MIDI
    log_info("file_check_midi 0x%08llx\n", (unsigned long long)fs);
#endif
    if(my_fseek(file_recovery->handle, fs, SEEK_SET) < 0 ||
	fread(&track, 8, 1, file_recovery->handle) != 1 ||
	memcmp(&track.magic[0], "MTrk", 4)!=0)
      return ;
    fs+=(uint64_t)8+be32(track.len);
  }
  if(fs_org < fs)
    return ;
  file_recovery->file_size=fs;
}

/*@
  @ requires buffer_size >= 2 && (buffer_size&1)==0;
  @ requires \valid(file_recovery);
  @ requires \valid_read(buffer + ( 0 .. buffer_size-1));
  @ requires file_recovery->data_check == &data_check_midi;
  @ requires separation: \separated(buffer+(..), file_recovery);
  @ ensures \result == DC_CONTINUE || \result == DC_STOP;
  @ assigns file_recovery->calculated_file_size;
  @*/
static data_check_t data_check_midi(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@
    @ loop assigns file_recovery->calculated_file_size;
    @ loop variant file_recovery->file_size + buffer_size/2 - (file_recovery->calculated_file_size + 8);
    @*/
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 8 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size + buffer_size/2 - file_recovery->file_size;
    /*@ assert 0 <= i < buffer_size - 8; */
    const struct midi_header *hdr=(const struct midi_header*)&buffer[i];
    const uint64_t len=be32(hdr->len);
#ifdef DEBUG_MIDI
    log_info("data_check_midi 0x%08llx len=%llu\n", (long long unsigned)file_recovery->calculated_file_size, (long long unsigned)len);
#endif
    if(memcmp(&hdr->magic[0], "MTrk", 4)!=0)
      return DC_STOP;
    file_recovery->calculated_file_size+=(uint64_t)8+len;
  }
  return DC_CONTINUE;
}

/*@
  @ requires buffer_size >= sizeof(struct midi_header);
  @ requires separation: \separated(&file_hint_mid, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_mid(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct midi_header *hdr=(const struct midi_header *)buffer;
  if(be16(hdr->format) > 2 || be16(hdr->tracks) == 0)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_mid.extension;
  file_recovery_new->file_check=&file_check_midi;
  if(file_recovery_new->blocksize < 8)
    return 1;
  file_recovery_new->calculated_file_size=4+4+6;
  file_recovery_new->data_check=&data_check_midi;
  return 1;
}

static void register_header_check_mid(file_stat_t *file_stat)
{
  static const unsigned char mid_header[8]  = { 'M','T','h','d', 0, 0, 0, 0x6};
  register_header_check(0, mid_header,sizeof(mid_header), &header_check_mid, file_stat);
}
#endif
