/*

    File: luks_detect.c

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

    Deep LUKS1/LUKS2 header parsing (read-only detection, no decryption).

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
#include "luks_detect.h"

/* LUKS magic: "LUKS" followed by 0xBA 0xBE */
static const unsigned char LUKS_MAGIC[6] = {'L','U','K','S', 0xba, 0xbe};

/* Swap big-endian 16-bit to host */
static uint16_t luks_be16(const uint8_t *p)
{
  return (uint16_t)((p[0] << 8) | p[1]);
}

/* Swap big-endian 32-bit to host */
static uint32_t luks_be32(const uint8_t *p)
{
  return ((uint32_t)p[0] << 24) |
         ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] <<  8) |
          (uint32_t)p[3];
}

/*
 * Copy at most dst_size-1 bytes from src, ensuring null termination.
 * src may not be null-terminated within src_len bytes.
 */
static void safe_copy_str(char *dst, unsigned int dst_size,
			  const char *src, unsigned int src_len)
{
  unsigned int n = src_len < dst_size - 1 ? src_len : dst_size - 1;
  memcpy(dst, src, n);
  dst[n] = '\0';
}

/*
 * Parse a LUKS1 header from buffer.
 * Fills info with cipher, hash, key size, uuid, and key slot counts.
 * Returns 0 on success, 1 if not LUKS1.
 */
static int parse_luks1(const unsigned char *buffer, unsigned int buffer_size,
		       crypto_info_t *info)
{
  const luks1_header_t *hdr;
  unsigned int i;
  /* Minimum: header (208 bytes) + 8 key slots (48 bytes each) = 592 bytes */
  const unsigned int LUKS1_HDR_MIN = 592;

  if(buffer_size < LUKS1_HDR_MIN)
    return 1;

  hdr = (const luks1_header_t *)buffer;

  if(memcmp(hdr->magic, LUKS_MAGIC, 6) != 0)
    return 1;
  if(luks_be16((const uint8_t *)&hdr->version) != 1)
    return 1;

  info->type = CRYPTO_LUKS1;

  /* Build cipher string: "cipher_name-cipher_mode", e.g. "aes-xts-plain64" */
  {
    char name[33];
    char mode[33];
    safe_copy_str(name, sizeof(name), hdr->cipher_name, 32);
    safe_copy_str(mode, sizeof(mode), hdr->cipher_mode, 32);
    if(mode[0] != '\0')
      snprintf(info->cipher, sizeof(info->cipher), "%s-%s", name, mode);
    else
      safe_copy_str(info->cipher, sizeof(info->cipher), name, 32);
  }

  safe_copy_str(info->hash, sizeof(info->hash), hdr->hash_spec, 32);

  /* key_bytes is in bytes; convert to bits */
  info->key_bits = luks_be32((const uint8_t *)&hdr->key_bytes) * 8;

  safe_copy_str(info->uuid, sizeof(info->uuid),
		(const char *)hdr->uuid, 40);

  /* Count key slots — they follow immediately after the header */
  {
    const luks1_keyslot_t *slots =
      (const luks1_keyslot_t *)(buffer + sizeof(luks1_header_t));
    unsigned int slot_area_end =
      sizeof(luks1_header_t) + LUKS1_NUMKEYS * sizeof(luks1_keyslot_t);

    info->key_slot_count = LUKS1_NUMKEYS;
    info->key_slots_active = 0;

    if(buffer_size >= slot_area_end)
    {
      for(i = 0; i < LUKS1_NUMKEYS; i++)
      {
        uint32_t active = luks_be32((const uint8_t *)&slots[i].active);
        if(active == LUKS1_KEY_ENABLED)
          info->key_slots_active++;
      }
    }
  }

  return 0;
}

/*
 * Parse a LUKS2 header from buffer.
 * Fills info with uuid and marks type as CRYPTO_LUKS2.
 * Full JSON metadata parsing is out of scope (requires dynamic allocation).
 * Returns 0 on success, 1 if not LUKS2.
 */
static int parse_luks2(const unsigned char *buffer, unsigned int buffer_size,
		       crypto_info_t *info)
{
  const luks2_header_t *hdr;

  if(buffer_size < sizeof(luks2_header_t))
    return 1;

  hdr = (const luks2_header_t *)buffer;

  if(memcmp(hdr->magic, LUKS_MAGIC, 6) != 0)
    return 1;
  if(luks_be16((const uint8_t *)&hdr->version) != 2)
    return 1;

  info->type = CRYPTO_LUKS2;
  safe_copy_str(info->uuid, sizeof(info->uuid),
		(const char *)hdr->uuid, 40);

  /* cipher/hash/key_bits require JSON area parsing — not available in
   * the binary header alone; leave as empty/zero */
  info->cipher[0]       = '\0';
  info->hash[0]         = '\0';
  info->key_bits        = 0;
  /* LUKS2 supports up to 32 key slots (tokens + keyslots in JSON) */
  info->key_slot_count  = 32;
  info->key_slots_active = 0;

  return 0;
}

/*
 * luks_detect - detect and parse a LUKS1 or LUKS2 header.
 *
 * Returns 0 if a LUKS header was found and info populated,
 * 1 otherwise.
 */
int luks_detect(const unsigned char *buffer, unsigned int buffer_size,
		crypto_info_t *info)
{
  if(buffer == NULL || info == NULL || buffer_size < 8)
    return 1;

  memset(info, 0, sizeof(crypto_info_t));

  if(memcmp(buffer, LUKS_MAGIC, 6) != 0)
    return 1;

  /* Dispatch on version field at offset 6 (big-endian uint16) */
  {
    uint16_t ver = luks_be16(buffer + 6);
    if(ver == 1)
      return parse_luks1(buffer, buffer_size, info);
    if(ver == 2)
      return parse_luks2(buffer, buffer_size, info);
  }

  /* Unknown LUKS version — still mark as detected */
  info->type = CRYPTO_UNKNOWN;
  return 0;
}
