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

static void register_header_check_ttf(file_stat_t *file_stat);
static int header_check_ttf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_ttf= {
  .extension="ttf",
  .description="TrueType Font",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_ttf
};

static const unsigned char header_ttf[5]= 	{0x00 , 0x01, 0x00, 0x00, 0x00};

static void register_header_check_ttf(file_stat_t *file_stat)
{
  register_header_check(0, header_ttf, sizeof(header_ttf), &header_check_ttf, file_stat);
}

/*
 * http://www.microsoft.com/typography/otspec/otff.htm
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

static unsigned int td_ilog2(unsigned int v)
{
  unsigned int l = 0;
  while(v >>= 1)
    l++;
  return l;
}

static int header_check_ttf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct ttf_offset_table *ttf=(const struct ttf_offset_table *)buffer;
  unsigned int numTables;
  if(memcmp(buffer, header_ttf, sizeof(header_ttf))!=0)
    return 0;
  numTables=be16(ttf->numTables);
  /* searchRange 	(Maximum power of 2 <= numTables) x 16.
   * entrySelector 	Log2(maximum power of 2 <= numTables).
   * rangeShift 	NumTables x 16-searchRange.
   * */
  if(td_ilog2(numTables) != (uint16_t)be16(ttf->entrySelector))
    return 0;
  if((16<<be16(ttf->entrySelector)) != be16(ttf->searchRange))
    return 0;
  if(numTables * 16 != (unsigned int)be16(ttf->rangeShift)+be16(ttf->searchRange))
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_ttf.extension;
  if(sizeof(struct ttf_offset_table) + numTables * sizeof(struct ttf_table_directory)
      <= buffer_size)
  {
    const struct ttf_table_directory*ttf_dir=(const struct ttf_table_directory*)(ttf+1);
    uint64_t max_offset=0;
    unsigned int i;
    for(i=0; i<numTables; i++,ttf_dir++)
    {
      /* | 0x3: align the end of the table */
      const uint64_t new_offset=(be32(ttf_dir->offset) + be32(ttf_dir->length))|0x3;
      if(max_offset < new_offset)
	max_offset=new_offset;
    }
    file_recovery_new->calculated_file_size=max_offset;
    file_recovery_new->data_check=&data_check_size;
    file_recovery_new->file_check=&file_check_size;
  }
  return 1;
}
