/*

    File: file_ndf.c

    Copyright (C) 2026 Christophe GRENIER <grenier@cgsecurity.org>

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ndf)
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
static void register_header_check_ndf(file_stat_t *file_stat);

const file_hint_t file_hint_ndf= {
  .extension="ndf",
  .description="Microsoft SQL Server Secondary Data File",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_ndf
};

/* SQL Server page header (same format as MDF, inline copy for KISS) */
struct mssql_page_hdr_ndf {
  uint8_t   m_headerVersion;  /* 0x01 */
  uint8_t   m_type;           /* page type: 0x0F = file header */
  uint8_t   m_typeFlagBits;
  uint8_t   m_level;
  uint16_t  m_flagBits;
  uint16_t  m_indexId;
  uint32_t  m_pageId;         /* page number (0 for header page) */
  uint16_t  m_fileId;         /* file ID: >=2 for NDF */
  uint16_t  m_reservedInt;
  uint32_t  m_prevPage;
  uint16_t  m_pminlen;        /* low byte: 0x01 = data file */
} __attribute__ ((gcc_struct, __packed__));

#define MSSQL_PAGE_SIZE 8192

/*@
  @ requires file_recovery->data_check==&data_check_ndf;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ terminates \true;
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ assigns  file_recovery->calculated_file_size;
  @*/
static data_check_t data_check_ndf(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@
    @ loop assigns file_recovery->calculated_file_size;
    @ loop variant file_recovery->file_size + buffer_size/2 - (file_recovery->calculated_file_size + MSSQL_PAGE_SIZE);
    @*/
  while(file_recovery->calculated_file_size + buffer_size/2 >= file_recovery->file_size &&
      file_recovery->calculated_file_size + MSSQL_PAGE_SIZE <= file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size + buffer_size/2 - file_recovery->file_size;
    /*@ assert 0 <= i <= buffer_size - MSSQL_PAGE_SIZE; */
    /* Validate page header version byte at each 8KB boundary */
    if(buffer[i] != 0x01)
      return DC_STOP;
    file_recovery->calculated_file_size += MSSQL_PAGE_SIZE;
  }
  return DC_CONTINUE;
}

/*@
  @ requires buffer_size >= sizeof(struct mssql_page_hdr_ndf);
  @ requires separation: \separated(&file_hint_ndf, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_ndf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct mssql_page_hdr_ndf *hdr=(const struct mssql_page_hdr_ndf *)buffer;
  if(hdr->m_headerVersion != 0x01 || hdr->m_type != 0x0F)
    return 0;
  if(le32(hdr->m_pageId) != 0)
    return 0;
  if(le16(hdr->m_prevPage) != 0 || le16(hdr->m_reservedInt) != 0)
    return 0;
  /* Data file type: m_pminlen low byte must be 0x01 */
  if((le16(hdr->m_pminlen) & 0xFF) != 0x01)
    return 0;
  /* Secondary data file only: file_id must be >= 2 */
  if(le16(hdr->m_fileId) < 2)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_ndf.extension;
  file_recovery_new->min_filesize=2 * MSSQL_PAGE_SIZE;
  file_recovery_new->data_check=&data_check_ndf;
  return 1;
}

static void register_header_check_ndf(file_stat_t *file_stat)
{
  static const unsigned char ndf_header[4]= { 0x01, 0x0f, 0x00, 0x00 };
  register_header_check(0, ndf_header,sizeof(ndf_header), &header_check_ndf, file_stat);
}
#endif
