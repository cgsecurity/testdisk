/*

    File: bitlocker_detect.c

    Copyright (C) 2024 Christophe GRENIER <grenier@cgsecurity.org>

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

    BitLocker detection via boot sector signatures (read-only, no decryption).
    Reference: [MS-FVE] Full Volume Encryption specification.

 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "bitlocker_detect.h"

/*
 * BitLocker OEM ID in the boot sector at offset 3 (8 bytes).
 * Present on BitLocker-encrypted NTFS volumes.
 */
static const unsigned char BITLOCKER_OEM_ID[8] = {
  '-','F','V','E','-','F','S','-'
};

/*
 * BitLocker FVE metadata signature at offset 0 of each FVE metadata block.
 * "-FVE-FS-" followed by version fields.
 */
static const unsigned char BITLOCKER_FVE_SIGNATURE[8] = {
  '-','F','V','E','-','F','S','-'
};

/*
 * BitLocker volume GUID: {4967D63B-2E29-4AD8-8399-F6A339E3D001}
 * Stored little-endian in the boot sector at offset 0xA0 in some
 * Windows Vista/7 layouts, or embedded in FVE metadata header.
 * Bytes in on-disk order (mixed-endian GUID):
 *   3B D6 67 49  29 2E  D8 4A  83 99  F6 A3 39 E3 D0 01
 */
static const unsigned char BITLOCKER_GUID[16] = {
  0x3b, 0xd6, 0x67, 0x49,
  0x29, 0x2e,
  0xd8, 0x4a,
  0x83, 0x99,
  0xf6, 0xa3, 0x39, 0xe3, 0xd0, 0x01
};

/* Read a little-endian 16-bit value from a byte pointer */
static uint16_t bl_le16(const uint8_t *p)
{
  return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

/*
 * Map a BitLocker encryption method code to a human-readable cipher string
 * and populate key_bits in info.
 */
static void map_encryption_method(uint16_t method, crypto_info_t *info)
{
  switch(method)
  {
    case BITLOCKER_ENC_AES128_DIFFUSER:
      snprintf(info->cipher, sizeof(info->cipher), "aes-cbc-elephant");
      info->key_bits = 128;
      break;
    case BITLOCKER_ENC_AES256_DIFFUSER:
      snprintf(info->cipher, sizeof(info->cipher), "aes-cbc-elephant");
      info->key_bits = 256;
      break;
    case BITLOCKER_ENC_AES128:
      snprintf(info->cipher, sizeof(info->cipher), "aes-cbc");
      info->key_bits = 128;
      break;
    case BITLOCKER_ENC_AES256:
      snprintf(info->cipher, sizeof(info->cipher), "aes-cbc");
      info->key_bits = 256;
      break;
    case BITLOCKER_ENC_XTS_AES128:
      snprintf(info->cipher, sizeof(info->cipher), "aes-xts");
      info->key_bits = 128;
      break;
    case BITLOCKER_ENC_XTS_AES256:
      snprintf(info->cipher, sizeof(info->cipher), "aes-xts");
      info->key_bits = 256;
      break;
    default:
      snprintf(info->cipher, sizeof(info->cipher), "aes");
      info->key_bits = 0;
      break;
  }
}

/*
 * Scan the buffer for a GUID match starting at the given offset.
 * Returns the offset of the first match, or 0xFFFFFFFF if not found.
 */
static unsigned int find_guid(const unsigned char *buffer,
			      unsigned int buffer_size,
			      unsigned int start_offset)
{
  unsigned int i;
  if(buffer_size < 16)
    return 0xFFFFFFFF;
  for(i = start_offset; i <= buffer_size - 16; i++)
  {
    if(memcmp(buffer + i, BITLOCKER_GUID, 16) == 0)
      return i;
  }
  return 0xFFFFFFFF;
}

/*
 * bitlocker_detect - detect a BitLocker-encrypted volume.
 *
 * Detection strategy (two independent paths — either is sufficient):
 *
 *  Path A — OEM ID check:
 *    Bytes 3-10 of the boot sector contain "-FVE-FS-".
 *    Optionally parse encryption method from FVE metadata if reachable.
 *
 *  Path B — GUID scan:
 *    The BitLocker volume GUID appears somewhere in the first 512 bytes
 *    (common in Vista-era volumes with a slightly different layout).
 *
 * Returns 0 if BitLocker detected and info populated, 1 otherwise.
 */
int bitlocker_detect(const unsigned char *buffer, unsigned int buffer_size,
		     crypto_info_t *info)
{
  int detected = 0;

  if(buffer == NULL || info == NULL || buffer_size < 11)
    return 1;

  memset(info, 0, sizeof(crypto_info_t));

  /* Path A: check OEM ID "-FVE-FS-" at offset 3 */
  if(buffer_size >= 11 &&
     memcmp(buffer + 3, BITLOCKER_OEM_ID, 8) == 0)
  {
    detected = 1;
  }

  /* Path B: scan for BitLocker GUID in first 512 bytes */
  if(!detected && buffer_size >= 16)
  {
    unsigned int scan_end = buffer_size < 512 ? buffer_size : 512;
    if(find_guid(buffer, scan_end, 0) != 0xFFFFFFFF)
      detected = 1;
  }

  if(!detected)
    return 1;

  info->type = CRYPTO_BITLOCKER;

  /*
   * Attempt to read encryption method from FVE metadata volume header.
   * The FVE metadata block begins with the "-FVE-FS-" signature followed
   * by a uint16_t size, uint16_t version, uint16_t encryption_method.
   * This is only readable if the metadata block is in the first sector.
   *
   * Offset layout within FVE metadata entry header (MS-FVE 2.2.1):
   *   0x00  uint16  entry_size
   *   0x02  uint16  entry_version   (1 = Win7, 2 = Win8+)
   *   0x04  uint16  encryption_method
   *
   * The FVE signature at buffer+3 is immediately followed by BIOS
   * parameter block data, so the metadata itself is at a separate offset
   * pointed to by fve_metadata_offset[0] in the boot sector.
   * Since we only have the boot sector here, attempt a heuristic scan
   * for the FVE metadata signature within the buffer.
   */
  {
    unsigned int off;
    unsigned int scan_limit = buffer_size < 512 ? buffer_size : 512;

    for(off = 0; off + 8 + 6 <= scan_limit; off++)
    {
      if(memcmp(buffer + off, BITLOCKER_FVE_SIGNATURE, 8) == 0)
      {
        /* Found FVE signature — read encryption_method at +4 */
        if(off + 8 + 4 + 2 <= buffer_size)
        {
          uint16_t enc_method = bl_le16(buffer + off + 4);
          map_encryption_method(enc_method, info);
        }
        break;
      }
    }

    /* If cipher not set from metadata, use generic label */
    if(info->cipher[0] == '\0')
      snprintf(info->cipher, sizeof(info->cipher), "aes");
  }

  return 0;
}
