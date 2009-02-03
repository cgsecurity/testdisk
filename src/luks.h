/*

    File: luks.h

    Copyright (C) 2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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

    LUKS on-disk-format: http://luks.endorphin.org/spec
 */
#ifdef __cplusplus
extern "C" {
#endif

#define LUKS_CIPHERNAME_L	32
#define LUKS_CIPHERMODE_L	32
#define LUKS_HASHSPEC_L		32
#define LUKS_DIGESTSIZE		20
#define LUKS_SALTSIZE		32
#define LUKS_NUMKEYS		8
#define LUKS_MAGIC_L 		6
#define UUID_STRING_L 		40
typedef struct luks_keyslot luks_keyslot_t;
struct luks_keyslot {
  uint32_t	active;
  uint32_t	passwordIterations;
  uint8_t	passwordSalt[LUKS_SALTSIZE];
  uint32_t	keyMaterialOffset;
  uint32_t	stripes;
};

struct luks_phdr {
  uint8_t	magic[LUKS_MAGIC_L];
  uint16_t	version;
  uint8_t	cipherName[LUKS_CIPHERNAME_L];
  uint8_t	cipherMode[LUKS_CIPHERMODE_L];
  uint8_t	hashSpec[LUKS_HASHSPEC_L];
  uint32_t	payloadOffset;
  uint32_t	keyBytes;
  uint8_t	mkDigest[LUKS_DIGESTSIZE];
  uint8_t	mkDigestSalt[LUKS_SALTSIZE];
  uint32_t	mkDigestIterations;
  uint8_t	uuid[UUID_STRING_L];
  luks_keyslot_t keyslot[LUKS_NUMKEYS];
};

int check_LUKS(disk_t *disk_car, partition_t *partition);
int recover_LUKS(disk_t *disk_car, const struct luks_phdr *sb,partition_t *partition,const int verbose, const int dump_ind);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
