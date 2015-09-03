/*

    File: file_xar.c

    Copyright (C) 2015 Christophe GRENIER <grenier@cgsecurity.org>

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

static void register_header_check_xar(file_stat_t *file_stat);

const file_hint_t file_hint_xar= {
  .extension="xar",
  .description="xar archive",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_xar
};

struct xar_header
{
  uint32_t magic;
  uint16_t size;
  uint16_t version;
  uint64_t toc_length_compressed;
  uint64_t toc_length_uncompressed;
  uint32_t cksum_alg;
  /* A nul-terminated, zero-padded to multiple of 4, message digest name
   * appears here if cksum_alg is 3 which must not be empty ("") or "none".
   */
};

static int header_check_xar(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct xar_header *hdr=(const struct xar_header *)buffer;
  if(be16(hdr->version) > 1)
    return 0;
  if(be16(hdr->size) < 28)
    return 0;
  if(be16(hdr->cksum_alg)==3 && (be16(hdr->size) <32 ||be16(hdr->size)%4!=0))
    return 0;
  if(be16(hdr->cksum_alg)>3)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_xar.extension;
  file_recovery_new->min_filesize=be16(hdr->size) + be64(hdr->toc_length_compressed);
  return 1;
}

static void register_header_check_xar(file_stat_t *file_stat)
{
  register_header_check(0, "xar!", 4, &header_check_xar, file_stat);
}
