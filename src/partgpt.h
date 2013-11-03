/*

    File: partgpt.h

    Copyright (C) 2007-2008 Christophe GRENIER <grenier@cgsecurity.org>

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
#ifndef _PARTGPT_H
#define	_PARTGPT_H
#ifdef __cplusplus
extern "C" {
#endif

struct gpt_hdr
{
  char		hdr_sig[8];                     /* 0x00 */
#define	GPT_HDR_SIG		"EFI PART"
  uint32_t	hdr_revision;                   /* 0x08 */
#define	GPT_HDR_REVISION	0x00010000
  uint32_t	hdr_size;                       /* 0x0c */
  uint32_t	hdr_crc_self;                   /* 0x10 */
  uint32_t	__reserved;                     /* 0x14 */
  uint64_t	hdr_lba_self;                   /* 0x18 */
  uint64_t	hdr_lba_alt;                    /* 0x20 */
  uint64_t	hdr_lba_start;                  /* 0x28 */
  uint64_t	hdr_lba_end;                    /* 0x30 */
  efi_guid_t hdr_guid;                          /* 0x38 disk GUID */
  uint64_t	hdr_lba_table;                  /* 0x48 */
  uint32_t	hdr_entries;                    /* 0x50 */
  uint32_t	hdr_entsz;                      /* 0x54 */
  uint32_t	hdr_crc_table;                  /* 0x58 */
  uint8_t 	padding[420];                   /* 0x5c */
} __attribute__ ((__packed__));

struct gpt_ent
{
  efi_guid_t ent_type;
  efi_guid_t ent_uuid;
  uint64_t	ent_lba_start;
  uint64_t	ent_lba_end;
  uint64_t	ent_attr;
#define	GPT_ENT_ATTR_PLATFORM		(1ULL << 0)
  uint8_t	ent_name[72];		/* UNICODE-16 */
};

struct systypes_gtp {
  const efi_guid_t part_type;
  const char *name;
};

list_part_t *add_partition_gpt_cli(disk_t *disk_car,list_part_t *list_part, char **current_cmd);
int write_part_gpt(disk_t *disk_car, const list_part_t *list_part, const int ro, const int verbose);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif /* _PARTGPT_H */
