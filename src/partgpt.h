#ifndef _PARTGPT_H
#define	_PARTGPT_H

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

#endif /* _PARTGPT_H */
