/*

    File: bitlocker_detect.h

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

 */
#ifndef _BITLOCKER_DETECT_H
#define _BITLOCKER_DETECT_H
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include "crypto_detect.h"
#ifdef __cplusplus
extern "C" {
#endif

/*
 * BitLocker FVE volume header layout (partial — fields needed for detection).
 * Starts at sector 0 of a BitLocker-encrypted NTFS volume.
 */
typedef struct {
  uint8_t		jump[3];		/* 0xEB 0x52 0x90 jump instruction */
  uint8_t		oem_id[8];		/* "-FVE-FS-" */
  uint8_t		bpb[53];		/* BPB fields (skipped) */
  uint8_t		_reserved[8];
  uint8_t		fve_guid[16];		/* BitLocker FVE metadata GUID */
  uint64_t		fve_metadata_offset[3]; /* 3 copies, little-endian */
} __attribute__((packed)) bitlocker_boot_sector_t;

/*
 * Encryption method codes from FVE metadata (little-endian uint16 in header).
 * Documented in MS-FVE specification section 2.2.
 */
#define BITLOCKER_ENC_AES128_DIFFUSER	0x8000
#define BITLOCKER_ENC_AES256_DIFFUSER	0x8001
#define BITLOCKER_ENC_AES128		0x8002
#define BITLOCKER_ENC_AES256		0x8003
#define BITLOCKER_ENC_XTS_AES128	0x8004
#define BITLOCKER_ENC_XTS_AES256	0x8005

/*@
  @ requires \valid_read(buffer+(0..buffer_size-1));
  @ requires \valid(info);
  @ requires buffer_size >= 512;
  @*/
int bitlocker_detect(const unsigned char *buffer, unsigned int buffer_size,
		     crypto_info_t *info);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
