/*

    File: file_pfx.c

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

static void register_header_check_pfx(file_stat_t *file_stat);

const file_hint_t file_hint_pfx= {
  .extension="pfx",
  .description="PKCS#12 keys",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_pfx
};

/* A pfx file are PKCS#12 data encoded following ASN.1 DER
 *
 * PKCS #12: Personal Information Exchange Syntax Standard
 * ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-12/pkcs-12v1.pdf
 *
 * For the recovery PhotoRec assumes
 * - the file is smaller than 65535+4 bytes
 * - PKCS #7 ContentInfo contentType=data
 *
 *  0:d=0  hl=4 l=XXXX cons: SEQUENCE
 *    30 82 XX XX	XXXX + 4 = filesize
 *  4:d=1  hl=2 l=   1 prim: INTEGER
 *    02 01 03		version 3
 *  7:d=1  hl=4 l=XXXX cons: SEQUENCE          
 *    30 82 XX XX
 * 11:d=2  hl=2 l=   9 prim: OBJECT            :pkcs7-data
 *    06 09 2a 86 48 86 f7 0d 01 07 01
 *    A PKCS #7 ContentInfo, whose contentType is signedData in
 *    public-key integrity mode and data in password integrity mode.
 *    Here, contentType=data
 */

static int header_check_pfx(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(buffer[0]==0x30 && buffer[1]==0x82 &&
      buffer[4]==0x02 && buffer[5]==0x01 && buffer[6]==0x03 &&
      buffer[7]==0x30 && buffer[8]==0x82)
  {
    const uint64_t size=((buffer[2])<<8) + buffer[3] + 4;
    if(size < 11 + 11)
      return 0;
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_pfx.extension;
    file_recovery_new->calculated_file_size=size;
    file_recovery_new->data_check=&data_check_size;
    file_recovery_new->file_check=&file_check_size;
    return 1;
  }
  return 0;
}

static void register_header_check_pfx(file_stat_t *file_stat)
{
  static const unsigned char pfx_header[11]= {
    0x06, 0x09,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01
  };
  register_header_check(11, pfx_header,sizeof(pfx_header), &header_check_pfx, file_stat);
}
