/*

    File: file_tiff.c

    Copyright (C) 1998-2005,2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include "memmem.h"

static void register_header_check_tiff(file_stat_t *file_stat);
static int header_check_tiff(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);
/*
static int64_t test_tiff(FILE *infile);
static void file_check_tiff(file_recovery_t *file_recovery);
*/

const file_hint_t file_hint_tiff= {
  .extension="tif",
  .description="Tag Image File Format and some raw file formats (pef/nef/dcr/sr2/cr2)",
  .min_header_distance=0,
  .max_filesize=200*1024*1024,
  .recover=1,
  .header_check=&header_check_tiff,
  .register_header_check=&register_header_check_tiff
};

static const unsigned char tiff_header_be[4]= { 'M','M',0x00, 0x2a};
static const unsigned char tiff_header_le[4]= { 'I','I',0x2a, 0x00};

static void register_header_check_tiff(file_stat_t *file_stat)
{
  register_header_check(0, tiff_header_be,sizeof(tiff_header_be), &header_check_tiff, file_stat);
  register_header_check(0, tiff_header_le,sizeof(tiff_header_le), &header_check_tiff, file_stat);
}

static int header_check_tiff(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const unsigned char pentax_sig[18]= { 'P', 'E', 'N', 'T', 'A', 'X', ' ', 'C', 'o', 'r', 'p', 'o', 'r', 'a', 't', 'i', 'o', 'n'};
  const unsigned char nikon_sig[17]= { 'N', 'I', 'K', 'O', 'N', ' ', 'C', 'O', 'R', 'P', 'O', 'R', 'A', 'T', 'I', 'O', 'N'};
  const unsigned char dcr_sig[5]= { '.', 'D', 'C', 'R', 0x00};
  const unsigned char sony_sig[5]= { 'S', 'O', 'N', 'Y', 0x00};
  if(memcmp(buffer,tiff_header_be,sizeof(tiff_header_be))==0 ||
      memcmp(buffer,tiff_header_le,sizeof(tiff_header_le))==0)
  {
    reset_file_recovery(file_recovery_new);
    /* Canon RAW */
    if(buffer[8]=='C' && buffer[9]=='R' && buffer[10]==2)
      file_recovery_new->extension="cr2";
    /* Pentax RAW */
    else if(td_memmem(buffer, buffer_size, pentax_sig, sizeof(pentax_sig))!=NULL)
      file_recovery_new->extension="pef";
    /* Nikon RAW */
    else if(td_memmem(buffer, buffer_size, nikon_sig, sizeof(nikon_sig))!=NULL)
      file_recovery_new->extension="nef";
    /* Kodak RAW */
    else if(td_memmem(buffer, buffer_size, dcr_sig, sizeof(dcr_sig))!=NULL)
      file_recovery_new->extension="dcr";
    /* Sony RAW */
    else if(td_memmem(buffer, buffer_size, sony_sig, sizeof(sony_sig))!=NULL)
      file_recovery_new->extension="sr2";
    else
      file_recovery_new->extension=file_hint_tiff.extension;
    return 1;
  }
  return 0;
}

/*
// Seems to be wrong
static void file_check_tiff(file_recovery_t *file_recovery)
{
  const unsigned char tiff_footer[2]= {0xff, 0xd9};
  file_search_footer(file_recovery, tiff_footer,sizeof(tiff_footer));

}
*/
