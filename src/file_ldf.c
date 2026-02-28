/*

    File: file_ldf.c

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ldf)
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
static void register_header_check_ldf(file_stat_t *file_stat);

const file_hint_t file_hint_ldf= {
  .extension="ldf",
  .description="Microsoft SQL Server Log Data File",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_ldf
};

/* SQL Server file header page (first 22 bytes) */
struct mssql_file_hdr {
  uint8_t   m_headerVersion;  /* must be 0x01 */
  uint8_t   m_type;           /* must be 0x0F for file header */
  uint8_t   m_typeFlagBits;
  uint8_t   m_level;
  uint16_t  m_flagBits;
  uint16_t  m_indexId;
  uint32_t  m_pageId;         /* must be 0 for page 0 */
  uint16_t  m_fileId;
  uint16_t  m_reservedInt;
  uint32_t  m_prevPage;
  uint16_t  m_pminlen;        /* low byte: 0x02 for log file */
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires buffer_size >= sizeof(struct mssql_file_hdr);
  @ requires separation: \separated(&file_hint_ldf, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_ldf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct mssql_file_hdr *hdr=(const struct mssql_file_hdr *)buffer;
  if(hdr->m_headerVersion != 0x01 || hdr->m_type != 0x0F)
    return 0;
  if(le32(hdr->m_pageId) != 0)
    return 0;
  if(le16(hdr->m_prevPage) != 0 || le16(hdr->m_reservedInt) != 0)
    return 0;
  /* Log file type: m_pminlen low byte must be 0x02 */
  if((le16(hdr->m_pminlen) & 0xFF) != 0x02)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_ldf.extension;
  file_recovery_new->min_filesize=2 * 8192;
  /* No data_check: LDF VLF boundaries are irregular, not fixed 8KB pages */
  return 1;
}

static void register_header_check_ldf(file_stat_t *file_stat)
{
  static const unsigned char ldf_header[4]= { 0x01, 0x0f, 0x00, 0x00 };
  register_header_check(0, ldf_header,sizeof(ldf_header), &header_check_ldf, file_stat);
}
#endif
