/*

    File: crypto_detect.h

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

 */
#ifndef _CRYPTO_DETECT_H
#define _CRYPTO_DETECT_H
#ifdef __cplusplus
extern "C" {
#endif

/* Encrypted volume/container type identifiers */
typedef enum {
  CRYPTO_NONE = 0,
  CRYPTO_LUKS1,
  CRYPTO_LUKS2,
  CRYPTO_BITLOCKER,
  CRYPTO_FILEVAULT2,
  CRYPTO_VERACRYPT,
  CRYPTO_APFS_ENCRYPTED,
  CRYPTO_UNKNOWN
} crypto_type_t;

/* Information extracted from an encrypted volume header (read-only detection) */
typedef struct {
  crypto_type_t	type;
  char		cipher[64];		/* e.g. "aes-xts-plain64" */
  char		hash[32];		/* e.g. "sha256" */
  unsigned int	key_bits;		/* e.g. 256 */
  char		uuid[64];
  int		key_slot_count;		/* LUKS: total key slot count */
  int		key_slots_active;	/* LUKS: number of active key slots */
} crypto_info_t;

/*@
  @ requires \valid_read(buffer+(0..buffer_size-1));
  @ requires \valid(info);
  @ requires buffer_size >= 512;
  @*/
int crypto_detect(const unsigned char *buffer, unsigned int buffer_size,
		  crypto_info_t *info);

/*@
  @ requires type >= CRYPTO_NONE && type <= CRYPTO_UNKNOWN;
  @*/
const char *crypto_type_name(crypto_type_t type);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
