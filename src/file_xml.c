/*

    File: file_xml.c

    Copyright (C) 2016 Christophe GRENIER <grenier@cgsecurity.org>

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_xml)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "filegen.h"
#include "log.h"

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_xml(file_stat_t *file_stat);

const file_hint_t file_hint_xml = {
  .extension = "xml",
  .description = "Symantec encrypted xml files",
  .max_filesize = PHOTOREC_MAX_FILE_SIZE,
  .recover = 1,
  .enable_by_default = 1,
  .register_header_check = &register_header_check_xml
};

/*@
  @ requires valid_file_rename_param(file_recovery);
  @ requires \valid_read(title + (0 .. size-1));
  @ requires \initialized(title + (0 .. size-1));
  @ ensures  valid_file_rename_result(file_recovery);
  @*/
static void file_rename_xml_aux(file_recovery_t *file_recovery, const char *title, const unsigned int size)
{

  unsigned int j;
  if(size < 2)
    return;
  /*@
    @ loop invariant j <= size;
    @ loop assigns j;
    @ loop variant size - 1 - j;
    @*/
  for(j = 0; j < size-1; j += 2)
  {
      if((title[j] == 0 && title[j + 1] == 0) || (title[j] == '<' && title[j + 1] == 0))
      {
	file_rename_unicode(file_recovery, title, j, 0, NULL, 1);
	return ;
      }
  }
  file_rename_unicode(file_recovery, title, size, 0, NULL, 1);
}

/*@
  @ requires file_recovery->file_rename==&file_rename_xml;
  @ requires valid_file_rename_param(file_recovery);
  @ ensures  valid_file_rename_result(file_recovery);
  @*/
static void file_rename_xml(file_recovery_t *file_recovery)
{
  static const char fn[] = "<\0f\0i\0l\0e\0n\0a\0m\0e\0>\0";
  FILE *file;
  char buffer[4096];
  size_t lu;
  unsigned int i;
  if((file = fopen(file_recovery->filename, "rb")) == NULL)
    return;
  if((lu = fread(&buffer, 1, sizeof(buffer) - 2, file)) <= 0)
  {
    fclose(file);
    return;
  }
  fclose(file);
  if(lu <= 20)
    return ;
  /*@ assert 20 <= lu <= sizeof(buffer)-2; */
  /*@ assert \valid(buffer + (0 .. lu+1)); */
  buffer[lu] = '\0';
  buffer[lu + 1] = '\0';
  /*@
    @ loop invariant 0 <= i <= lu - 20 + 1;
    @ loop assigns i;
    @ loop variant lu - 20 - i;
    @*/
  for(i = 0; i < lu - 20 && !(buffer[i] == 0 && buffer[i + 1] == 0); i += 2)
  {
    if(memcmp(&buffer[i], fn, 20) == 0)
    {
      /*@ assert \valid_read(buffer + (0 .. lu+1)); */
      /*@ assert \valid_read(buffer + (20 + i.. lu+1)); */
      file_rename_xml_aux(file_recovery, &buffer[i+20], lu + 1 - 20 - i );
      return;
    }
  }
}

/*@
  @ requires separation: \separated(&file_hint_xml, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_xml(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension = file_hint_xml.extension;
  file_recovery_new->min_filesize = 512;
  file_recovery_new->file_rename = &file_rename_xml;
  return 1;
}

static void register_header_check_xml(file_stat_t *file_stat)
{
  static const unsigned char xml_header[142] = {
    0x3c, 0x00, 0x3f, 0x00, 'x', 0x00, 'm', 0x00,
    'l', 0x00, ' ', 0x00, 'v', 0x00, 'e', 0x00,
    'r', 0x00, 's', 0x00, 'i', 0x00, 'o', 0x00,
    'n', 0x00, 0x3d, 0x00, 0x22, 0x00, '1', 0x00,
    '.', 0x00, '0', 0x00, 0x22, 0x00, ' ', 0x00,
    'e', 0x00, 'n', 0x00, 'c', 0x00, 'o', 0x00,
    'd', 0x00, 'i', 0x00, 'n', 0x00, 'g', 0x00,
    0x3d, 0x00, 0x22, 0x00, 'U', 0x00, 'T', 0x00,
    'F', 0x00, 0x2d, 0x00, '1', 0x00, '6', 0x00,
    0x22, 0x00, 0x3f, 0x00, 0x3e, 0x00, 0x3c, 0x00,
    0x21, 0x00, 0x2d, 0x00, 0x2d, 0x00, 'G', 0x00,
    'E', 0x00, 'T', 0x00, 'R', 0x00, 'S', 0x00,
    'F', 0x00, 'i', 0x00, 'l', 0x00, 'e', 0x00,
    'H', 0x00, 'e', 0x00, 'a', 0x00, 'd', 0x00,
    'e', 0x00, 'r', 0x00, 'S', 0x00, 'i', 0x00,
    'z', 0x00, 'e', 0x00, 0x3d, 0x00, '0', 0x00,
    'x', 0x00, '0', 0x00, '0', 0x00, '0', 0x00,
    '0', 0x00, '0', 0x00, '8', 0x00
  };
  register_header_check(0, xml_header, sizeof(xml_header), &header_check_xml, file_stat);
}
#endif
