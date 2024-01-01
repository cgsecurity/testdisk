/*

    File: file_ttf.c

    Copyright (C) 2009 Christophe GRENIER <grenier@cgsecurity.org>

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ttf)
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

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_ttf(file_stat_t *file_stat);

const file_hint_t file_hint_ttf= {
  .extension="ttf",
  .description="TrueType Font",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_ttf
};

/*
 * https://docs.microsoft.com/en-us/typography/opentype/spec/otff
 */

struct ttf_offset_table
{
  int32_t 	sfnt_version;
  uint16_t	numTables;
  uint16_t	searchRange;
  uint16_t	entrySelector;
  uint16_t	rangeShift;
};

struct ttf_table_directory
{
  uint32_t 	tag;
  uint32_t 	checkSum;
  uint32_t 	offset; 	/* Offset from beginning of TrueType font file. */
  uint32_t 	length; 	/* Length of this table. */
};

/*@
  @ terminates \true;
  @ assigns \nothing;
  @*/
static unsigned int td_ilog2(unsigned int v)
{
  unsigned int l = 0;
  /*@
    @ loop assigns v,l;
    @ loop unroll 16;
    @ loop variant v;
    @*/
  while(v >>= 1)
    l++;
  return l;
}

/*@
  @ requires buffer_size >= sizeof(struct ttf_offset_table);
  @ requires separation: \separated(&file_hint_ttf, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_ttf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct ttf_offset_table *ttf=(const struct ttf_offset_table *)buffer;
  const unsigned int numTables=be16(ttf->numTables);
  const unsigned int entrySelector=be16(ttf->entrySelector);
  const unsigned int searchRange=be16(ttf->searchRange);
  const unsigned int rangeShift=be16(ttf->rangeShift);
  if(numTables == 0)
    return 0;
  /* searchRange 	(Maximum power of 2 <= numTables) x 16.
   * entrySelector 	Log2(maximum power of 2 <= numTables).
   * rangeShift 	NumTables x 16-searchRange.
   * */
  if(td_ilog2(numTables) != entrySelector)
    return 0;
  if((16<<entrySelector) != searchRange)
    return 0;
  if(numTables * 16 != rangeShift+searchRange)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_ttf.extension;
  if(sizeof(struct ttf_offset_table) + numTables * sizeof(struct ttf_table_directory)
      <= buffer_size)
  {
    /*@ assert sizeof(struct ttf_offset_table) + numTables * sizeof(struct ttf_table_directory) <= buffer_size; */
    /*@ assert numTables * sizeof(struct ttf_table_directory) <= buffer_size - sizeof(struct ttf_offset_table); */
    /*@ assert numTables <= (buffer_size - sizeof(struct ttf_offset_table)) / sizeof(struct ttf_table_directory); */
    /*@ assert \valid_read(buffer + (0 .. buffer_size - 1)); */
    /*@ assert \valid_read(buffer + (0 .. sizeof(struct ttf_offset_table) + numTables * sizeof(struct ttf_table_directory) - 1)); */
    uint64_t max_offset=0;
    unsigned int i;
    const struct ttf_table_directory*ttf_dir=(const struct ttf_table_directory*)&buffer[sizeof(struct ttf_offset_table)];
    /*@ assert \valid_read(ttf_dir + (0 .. numTables -1)); */
    /*@
      @ loop assigns i, max_offset;
      @ loop variant numTables - i;
      @*/
    for(i=0; i<numTables; i++)
    {
      /*@ assert 0 <= i < numTables; */
      /*@ assert \valid_read(&ttf_dir[i]); */
      /* Do not align the end of the table with "|0x3;"*/
      const uint64_t new_offset=((uint64_t)be32(ttf_dir[i].offset) + be32(ttf_dir[i].length));
      if(max_offset < new_offset)
	max_offset=new_offset;
    }
    file_recovery_new->calculated_file_size=max_offset;
    file_recovery_new->data_check=&data_check_size;
    file_recovery_new->file_check=&file_check_size;
  }
  return 1;
}

static void register_header_check_ttf(file_stat_t *file_stat)
{
  static const unsigned char header_ttf[5]= 	{0x00 , 0x01, 0x00, 0x00, 0x00};
  register_header_check(0, header_ttf, sizeof(header_ttf), &header_check_ttf, file_stat);
}
#endif
