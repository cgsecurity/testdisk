/*

    File: crypto_detect.c

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

    Encrypted volume/container detection dispatcher.
    Detects: LUKS1, LUKS2, BitLocker, FileVault 2, VeraCrypt, APFS encrypted.
    No decryption or key handling is performed.

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
#include "crypto_detect.h"
#include "luks_detect.h"
#include "bitlocker_detect.h"

/* --------------------------------------------------------------------------
 * FileVault 2 detection
 *
 * Apple Core Storage LVM logical volume group header begins with the magic
 * bytes 0x43 0x53 ("CS") at offset 88 within the first 512-byte sector.
 * Reference: libdvmfsnotes / Apple Core Storage format.
 * -------------------------------------------------------------------------- */
#define FILEVAULT2_CS_MAGIC_OFFSET	88
static const unsigned char FILEVAULT2_CS_MAGIC[2] = { 0x43, 0x53 };

static int detect_filevault2(const unsigned char *buffer,
			     unsigned int buffer_size,
			     crypto_info_t *info)
{
  if(buffer_size < FILEVAULT2_CS_MAGIC_OFFSET + 2)
    return 1;
  if(memcmp(buffer + FILEVAULT2_CS_MAGIC_OFFSET,
	    FILEVAULT2_CS_MAGIC, 2) != 0)
    return 1;

  /*
   * Core Storage magic present. A Core Storage volume is not necessarily
   * encrypted, but FileVault 2 always uses Core Storage. Without reading
   * the full LVG metadata we cannot confirm encryption is active, so we
   * report the detection as CRYPTO_FILEVAULT2 (possible FileVault 2).
   */
  memset(info, 0, sizeof(crypto_info_t));
  info->type = CRYPTO_FILEVAULT2;
  /* AES-XTS-128 is the standard FileVault 2 cipher */
  snprintf(info->cipher, sizeof(info->cipher), "aes-xts");
  info->key_bits = 128;
  return 0;
}

/* --------------------------------------------------------------------------
 * VeraCrypt / TrueCrypt detection
 *
 * VeraCrypt volumes have no reliable magic by design. The heuristic used
 * here checks for high entropy in the first 64 bytes (the salt/IV area)
 * combined with an absence of any known filesystem or partition signatures.
 *
 * Heuristic: count distinct byte values in the first 64 bytes. A fully
 * random 64-byte block should have roughly 55+ distinct values (birthday
 * problem). A block with < 32 distinct values is unlikely to be encrypted
 * random data.
 * -------------------------------------------------------------------------- */
#define VERACRYPT_SALT_SIZE		64
#define VERACRYPT_MIN_DISTINCT_BYTES	48

static int detect_veracrypt(const unsigned char *buffer,
			    unsigned int buffer_size,
			    crypto_info_t *info)
{
  unsigned int i;
  unsigned int distinct = 0;
  unsigned char seen[256];

  if(buffer_size < VERACRYPT_SALT_SIZE)
    return 1;

  /*
   * Skip buffers that match known signatures at offset 0 — VeraCrypt
   * volumes intentionally have no such signatures.
   */

  /* LUKS magic */
  if(buffer[0]=='L' && buffer[1]=='U' && buffer[2]=='K' && buffer[3]=='S')
    return 1;
  /* BitLocker OEM ID at offset 3 */
  if(buffer_size >= 11 &&
     buffer[3]=='-' && buffer[4]=='F' && buffer[5]=='V' && buffer[6]=='E')
    return 1;
  /* NTFS signature */
  if(buffer[3]=='N' && buffer[4]=='T' && buffer[5]=='F' && buffer[6]=='S')
    return 1;
  /* FAT signatures */
  if(buffer[3]=='F' && buffer[4]=='A' && buffer[5]=='T')
    return 1;
  /* EXT magic at offset 0x38 (1080) — not reachable in a 512-byte buffer */

  memset(seen, 0, sizeof(seen));
  for(i = 0; i < VERACRYPT_SALT_SIZE; i++)
    seen[buffer[i]] = 1;
  for(i = 0; i < 256; i++)
    if(seen[i])
      distinct++;

  if(distinct < VERACRYPT_MIN_DISTINCT_BYTES)
    return 1;

  memset(info, 0, sizeof(crypto_info_t));
  info->type = CRYPTO_VERACRYPT;
  /* VeraCrypt default: AES-256-XTS */
  snprintf(info->cipher, sizeof(info->cipher), "aes-xts");
  info->key_bits = 256;
  return 0;
}

/* --------------------------------------------------------------------------
 * APFS encrypted detection
 *
 * APFS container superblock magic "NXSB" appears at offset 32.
 * The nx_incompatible_features field is at offset 72 (uint64_t LE).
 * Bit 0 of that field is NX_INCOMPAT_CASESENSITIVE; encrypted volumes
 * set the encryption flag (0x04) in the volume superblock's
 * apfs_fs_flags field. Since we only see one sector, we check for the
 * NXSB magic and a non-zero crypto state hint in the incompatible flags.
 *
 * A simpler proxy: APFS encrypted volumes have the APFS volume role
 * field (apfs_role, uint16_t LE at offset 0xBC in APSB superblock) with
 * APFS_VOL_ROLE_DATA (0x0002) and crypto flags set. Without a full
 * superblock parse we check for NXSB + presence of the "APSB" volume
 * magic somewhere in the buffer as a minimum signal.
 * -------------------------------------------------------------------------- */
#define APFS_NXSB_MAGIC_OFFSET	32
static const unsigned char APFS_NXSB_MAGIC[4] = { 'N','X','S','B' };
static const unsigned char APFS_APSB_MAGIC[4] = { 'A','P','S','B' };

static int detect_apfs_encrypted(const unsigned char *buffer,
				 unsigned int buffer_size,
				 crypto_info_t *info)
{
  unsigned int i;

  if(buffer_size < APFS_NXSB_MAGIC_OFFSET + 4)
    return 1;

  if(memcmp(buffer + APFS_NXSB_MAGIC_OFFSET, APFS_NXSB_MAGIC, 4) != 0)
    return 1;

  /*
   * We have an APFS container. Now look for an APSB volume superblock
   * within the same buffer, which would carry the encryption flag.
   * This is a best-effort heuristic for single-sector reads.
   */
  for(i = 0; i + 4 <= buffer_size; i++)
  {
    if(memcmp(buffer + i, APFS_APSB_MAGIC, 4) == 0)
    {
      /*
       * Found APSB volume superblock magic. The apfs_fs_flags field is
       * at offset 0x60 (96) within the APSB block. Encryption flag = 0x04.
       * Only check if the field is within our buffer window.
       */
      if(i + 96 + 8 <= buffer_size)
      {
        uint64_t flags = 0;
        int j;
        for(j = 7; j >= 0; j--)
          flags = (flags << 8) | buffer[i + 96 + j]; /* little-endian */
        if((flags & 0x04) == 0)
          return 1; /* encryption flag not set */
      }
      memset(info, 0, sizeof(crypto_info_t));
      info->type = CRYPTO_APFS_ENCRYPTED;
      snprintf(info->cipher, sizeof(info->cipher), "aes-xts");
      info->key_bits = 128;
      return 0;
    }
  }

  return 1;
}

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

/*
 * crypto_detect - identify the encryption type of a volume/container.
 *
 * Probes buffer in priority order:
 *   1. LUKS1 / LUKS2  (strong magic)
 *   2. BitLocker       (strong OEM ID or GUID)
 *   3. FileVault 2     (Core Storage magic)
 *   4. APFS encrypted  (NXSB + APSB magic)
 *   5. VeraCrypt       (entropy heuristic — weakest signal, checked last)
 *
 * Returns 0 if any encryption was detected, 1 if none found.
 * Sets info->type = CRYPTO_NONE on failure.
 */
int crypto_detect(const unsigned char *buffer, unsigned int buffer_size,
		  crypto_info_t *info)
{
  if(buffer == NULL || info == NULL || buffer_size < 8)
  {
    if(info != NULL)
    {
      memset(info, 0, sizeof(crypto_info_t));
      info->type = CRYPTO_NONE;
    }
    return 1;
  }

  memset(info, 0, sizeof(crypto_info_t));
  info->type = CRYPTO_NONE;

  /* LUKS1 and LUKS2 share the same magic — luks_detect dispatches by version */
  if(luks_detect(buffer, buffer_size, info) == 0)
    return 0;

  if(bitlocker_detect(buffer, buffer_size, info) == 0)
    return 0;

  if(detect_filevault2(buffer, buffer_size, info) == 0)
    return 0;

  if(detect_apfs_encrypted(buffer, buffer_size, info) == 0)
    return 0;

  /* VeraCrypt heuristic is last due to false-positive risk */
  if(detect_veracrypt(buffer, buffer_size, info) == 0)
    return 0;

  info->type = CRYPTO_NONE;
  return 1;
}

/*
 * crypto_type_name - return a human-readable name for a crypto_type_t value.
 */
const char *crypto_type_name(crypto_type_t type)
{
  switch(type)
  {
    case CRYPTO_NONE:           return "None";
    case CRYPTO_LUKS1:          return "LUKS1";
    case CRYPTO_LUKS2:          return "LUKS2";
    case CRYPTO_BITLOCKER:      return "BitLocker";
    case CRYPTO_FILEVAULT2:     return "FileVault 2";
    case CRYPTO_VERACRYPT:      return "VeraCrypt";
    case CRYPTO_APFS_ENCRYPTED: return "APFS (encrypted)";
    case CRYPTO_UNKNOWN:        return "Unknown encrypted";
    default:                    return "Unknown";
  }
}
