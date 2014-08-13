/*

    File: file_rpm.c

    Copyright (C) 2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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


static void register_header_check_rpm(file_stat_t *file_stat);
static int header_check_rpm(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_rpm= {
  .extension="rpm",
  .description="RPM package",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_rpm
};

struct rpmlead {
  unsigned char magic[4];
  unsigned char major, minor;
  uint16_t type;
  uint16_t archnum;
  char name[66];
  uint16_t osnum;
  uint16_t signature_type;
  char reserved[16];
} __attribute__ ((__packed__));

static void file_rename_rpm(const char *old_filename)
{
  FILE *file;
  struct rpmlead hdr;
  if((file=fopen(old_filename, "rb"))==NULL)
    return;
  if(fread(&hdr, sizeof(hdr), 1, file)!=1)
  {
    fclose(file);
    return ;
  }
  fclose(file);
  file_rename(old_filename, &hdr.name, 66, 0, "rpm", 0);
}

static int header_check_rpm(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct rpmlead *hdr=(const struct rpmlead *)buffer;
  if(be16(hdr->type)>1)	/* 0=bin 1=src */
    return 0;
  switch(be16(hdr->signature_type))
  {
    case 0:	/* RPMSIG_NONE */
    case 1:	/* RPMSIG_PGP262_1024 */
    case 5:	/* RPMSIG_HEADERSIG */
      break;
    default:
    return 0;
  }
  if(hdr->name[0]=='\0')
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->min_filesize=(96 + 16 + 16); /* file header + checksum + content header */
  file_recovery_new->extension=file_hint_rpm.extension;
  file_recovery_new->file_rename=&file_rename_rpm;
  return 1;
}

static void register_header_check_rpm(file_stat_t *file_stat)
{
  /* RPM v3 */
  static const unsigned char rpm_header[5]= {0xed, 0xab, 0xee, 0xdb, 0x3};
  register_header_check(0, rpm_header,sizeof(rpm_header), &header_check_rpm, file_stat);
}
