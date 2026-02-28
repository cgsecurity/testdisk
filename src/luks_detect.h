/*

    File: luks_detect.h

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

    LUKS on-disk format: https://gitlab.com/cryptsetup/cryptsetup/blob/master/docs/on-disk-format.pdf

 */
#ifndef _LUKS_DETECT_H
#define _LUKS_DETECT_H
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include "crypto_detect.h"
#ifdef __cplusplus
extern "C" {
#endif

/* LUKS1 on-disk header layout (592 bytes total before key slots) */
typedef struct {
  uint8_t		magic[6];		/* "LUKS\xba\xbe" */
  uint16_t		version;		/* big-endian: 1 */
  char			cipher_name[32];	/* e.g. "aes" */
  char			cipher_mode[32];	/* e.g. "xts-plain64" */
  char			hash_spec[32];		/* e.g. "sha256" */
  uint32_t		payload_offset;		/* sectors, big-endian */
  uint32_t		key_bytes;		/* master key length in bytes, big-endian */
  uint8_t		mk_digest[20];		/* PBKDF2 master key digest */
  uint8_t		mk_digest_salt[32];	/* salt for master key digest */
  uint32_t		mk_digest_iter;		/* PBKDF2 iterations, big-endian */
  uint8_t		uuid[40];		/* UUID string */
} __attribute__((packed)) luks1_header_t;

/* LUKS1 key slot descriptor (follows luks1_header_t, 8 slots total) */
#define LUKS1_KEY_ENABLED	0x00AC71F3
#define LUKS1_NUMKEYS		8

typedef struct {
  uint32_t		active;			/* LUKS1_KEY_ENABLED if in use */
  uint32_t		iterations;		/* PBKDF2 iterations */
  uint8_t		salt[32];		/* PBKDF2 salt */
  uint32_t		key_material_offset;	/* sectors */
  uint32_t		stripes;		/* AF stripes */
} __attribute__((packed)) luks1_keyslot_t;

/* LUKS2 binary header (first 512 bytes) */
typedef struct {
  uint8_t		magic[6];		/* "LUKS\xba\xbe" */
  uint16_t		version;		/* big-endian: 2 */
  uint64_t		hdr_size;		/* header+JSON area size, big-endian */
  uint64_t		seqid;			/* header sequence id, big-endian */
  char			label[48];		/* optional label */
  uint8_t		checksum_alg[32];	/* checksum algorithm name */
  uint8_t		salt[64];		/* random salt */
  uint8_t		uuid[40];		/* UUID string */
  char			subsystem[48];		/* optional subsystem label */
  uint64_t		hdr_offset;		/* offset of this header, big-endian */
  uint8_t		_padding[184];
  uint8_t		csum[64];		/* header checksum */
} __attribute__((packed)) luks2_header_t;

/*@
  @ requires \valid_read(buffer+(0..buffer_size-1));
  @ requires \valid(info);
  @ requires buffer_size >= 512;
  @*/
int luks_detect(const unsigned char *buffer, unsigned int buffer_size,
		crypto_info_t *info);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
