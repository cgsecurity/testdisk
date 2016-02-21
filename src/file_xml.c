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

static void register_header_check_xml(file_stat_t *file_stat);

const file_hint_t file_hint_xml= {
  .extension="xml",
  .description="Symantec encrypted xml files",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_xml
};

static void file_rename_xml(file_recovery_t *file_recovery)
{
  static const char fn[]="<\0f\0i\0l\0e\0n\0a\0m\0e\0>\0";
  FILE *file;
  char buffer[4096];
  size_t lu;
  unsigned int i;
  if((file=fopen(file_recovery->filename, "rb"))==NULL)
    return;
  if((lu=fread(&buffer, 1, sizeof(buffer)-1, file)) <= 0)
  {
    fclose(file);
    return ;
  }
  fclose(file);
  buffer[lu]='\0';
  buffer[lu+1]='\0';
  buffer[4096-21]='\0';
  buffer[4096-20]='\0';
  for(i=0; i+20<lu && !(buffer[i]==0 && buffer[i+1]==0); i+=2)
  {
    if(memcmp(&buffer[i], fn, 20)==0)
    {
      const char *title=&buffer[i+20];
      int j;
      for(j=0;
	  i+20+j+1<lu && !(title[j]==0 && title[j+1]==0) && !(title[j]=='<' && title[j+1]==0);
	  j+=2)
      {
      }
      file_rename_unicode(file_recovery, title, j, 0, NULL, 1);
      return ;
    }
  }
}

static int header_check_xml(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_xml.extension;
  file_recovery_new->min_filesize=512;
  file_recovery_new->file_rename=&file_rename_xml;
  return 1;
}

static void register_header_check_xml(file_stat_t *file_stat)
{
  static const unsigned char xml_header[142]=  {
    0x3c, 0x00, 0x3f, 0x00, 'x' , 0x00, 'm' , 0x00,
    'l' , 0x00, ' ' , 0x00, 'v' , 0x00, 'e' , 0x00,
    'r' , 0x00, 's' , 0x00, 'i' , 0x00, 'o' , 0x00,
    'n' , 0x00, 0x3d, 0x00, 0x22, 0x00, '1' , 0x00,
    '.' , 0x00, '0' , 0x00, 0x22, 0x00, ' ' , 0x00,
    'e' , 0x00, 'n' , 0x00, 'c' , 0x00, 'o' , 0x00,
    'd' , 0x00, 'i' , 0x00, 'n' , 0x00, 'g' , 0x00,
    0x3d, 0x00, 0x22, 0x00, 'U' , 0x00, 'T' , 0x00,
    'F' , 0x00, 0x2d, 0x00, '1' , 0x00, '6' , 0x00,
    0x22, 0x00, 0x3f, 0x00, 0x3e, 0x00, 0x3c, 0x00,
    0x21, 0x00, 0x2d, 0x00, 0x2d, 0x00, 'G' , 0x00,
    'E' , 0x00, 'T' , 0x00, 'R' , 0x00, 'S' , 0x00,
    'F' , 0x00, 'i' , 0x00, 'l' , 0x00, 'e' , 0x00,
    'H' , 0x00, 'e' , 0x00, 'a' , 0x00, 'd' , 0x00,
    'e' , 0x00, 'r' , 0x00, 'S' , 0x00, 'i' , 0x00,
    'z' , 0x00, 'e' , 0x00, 0x3d, 0x00, '0' , 0x00,
    'x' , 0x00, '0' , 0x00, '0' , 0x00, '0' , 0x00,
    '0' , 0x00, '0' , 0x00, '8' , 0x00
  };
  register_header_check(0, xml_header, sizeof(xml_header), &header_check_xml, file_stat);
}
