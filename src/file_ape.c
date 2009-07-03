/*

    File: file_ape.c

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

static void register_header_check_ape(file_stat_t *file_stat);
static int header_check_ape(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_ape= {
  .extension="ape",
  .description="Monkey's Audio compressed format",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_ape
};

static const unsigned char ape_header[4]= { 'M', 'A', 'C', ' '};

static void register_header_check_ape(file_stat_t *file_stat)
{
  register_header_check(0, ape_header,sizeof(ape_header), &header_check_ape, file_stat);
}

struct APE_COMMON_HEADER
{
  char cID[4];		/* should equal 'MAC ' */
  uint16_t nVersion;	/* version number * 1000 (3.81 = 3810) */
};

static int header_check_ape(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct APE_COMMON_HEADER *ape=(const struct APE_COMMON_HEADER*)buffer;
  /* Version 3.96 released April 7, 2002, Version 4.06 March 17, 2009 */
  if(memcmp(buffer,ape_header,sizeof(ape_header))==0 &&
      le16(ape->nVersion)>3000 && le16(ape->nVersion)<6000)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_ape.extension;
    return 1;
  }
  return 0;
}
