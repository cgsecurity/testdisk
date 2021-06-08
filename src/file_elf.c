/*

    File: file_elf.c

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

 */

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_elf)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "common.h"
#include "filegen.h"

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_elf(file_stat_t *file_stat);

const file_hint_t file_hint_elf= {
  .extension="elf",
  .description="Executable and Linking Format",
  .max_filesize=10*1024*1024,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_elf
};

#define EI_NIDENT 16
/* Type for a 16-bit quantity.  */
typedef uint16_t Elf32_Half;
typedef uint16_t Elf64_Half;

/* Types for signed and unsigned 32-bit quantities.  */
typedef uint32_t Elf32_Word;
typedef	int32_t  Elf32_Sword;
typedef uint32_t Elf64_Word;
typedef	int32_t  Elf64_Sword;

/* Types for signed and unsigned 64-bit quantities.  */
typedef uint64_t Elf32_Xword;
typedef	int64_t  Elf32_Sxword;
typedef uint64_t Elf64_Xword;
typedef	int64_t  Elf64_Sxword;

/* Type of addresses.  */
typedef uint32_t Elf32_Addr;
typedef uint64_t Elf64_Addr;

/* Type of file offsets.  */
typedef uint32_t Elf32_Off;
typedef uint64_t Elf64_Off;

/* Type for section indices, which are 16-bit quantities.  */
typedef uint16_t Elf32_Section;
typedef uint16_t Elf64_Section;

/* Type of symbol indices.  */
typedef uint32_t Elf32_Symndx;
typedef uint64_t Elf64_Symndx;

typedef struct {
        unsigned char   e_ident[EI_NIDENT];
        Elf32_Half      e_type;
        Elf32_Half      e_machine;
        Elf32_Word      e_version;
        Elf32_Addr      e_entry;
        Elf32_Off       e_phoff;
        Elf32_Off       e_shoff;
        Elf32_Word      e_flags;
        Elf32_Half      e_ehsize;
        Elf32_Half      e_phentsize;
        Elf32_Half      e_phnum;
        Elf32_Half      e_shentsize;
        Elf32_Half      e_shnum;
        Elf32_Half      e_shtrndx;
} Elf32_Ehdr;

typedef struct {
        unsigned char   e_ident[EI_NIDENT];
        Elf64_Half      e_type;
        Elf64_Half      e_machine;
        Elf64_Word      e_version;
        Elf64_Addr      e_entry;
        Elf64_Off       e_phoff;
        Elf64_Off       e_shoff;
        Elf64_Word      e_flags;
        Elf64_Half      e_ehsize;
        Elf64_Half      e_phentsize;
        Elf64_Half      e_phnum;
        Elf64_Half      e_shentsize;
        Elf64_Half      e_shnum;
        Elf64_Half      e_shtrndx;
} Elf64_Ehdr;

#define EI_CLASS	4		/* File class byte index */
#define ELFCLASS32	1		/* 32-bit objects */
#define ELFCLASS64	2		/* 64-bit objects */

#define EI_DATA		5		/* Data encoding byte index */
#define ELFDATA2LSB	1		/* 2's complement, little endian */
#define ELFDATA2MSB	2		/* 2's complement, big endian */

/*@
  @ requires buffer_size >= sizeof(Elf32_Ehdr);
  @ requires separation: \separated(&file_hint_elf, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_elf32_lsb(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const Elf32_Ehdr *hdr=(const Elf32_Ehdr *)buffer;
  if(le32(hdr->e_version) != 1)
    return 0;
  /* http://en.wikipedia.org/wiki/Executable_and_Linkable_Format */
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_elf.extension;
  {
    const uint32_t tmp=le32(hdr->e_shoff);
    file_recovery_new->min_filesize=le32(hdr->e_phoff);
    if(file_recovery_new->min_filesize < tmp)
      file_recovery_new->min_filesize=tmp;
  }
  return 1;
}

/*@
  @ requires buffer_size >= sizeof(Elf32_Ehdr);
  @ requires separation: \separated(&file_hint_elf, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_elf32_msb(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const Elf32_Ehdr *hdr=(const Elf32_Ehdr *)buffer;
  if(be32(hdr->e_version) != 1)
    return 0;
  /* http://en.wikipedia.org/wiki/Executable_and_Linkable_Format */
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_elf.extension;
  {
    const uint32_t tmp=be32(hdr->e_shoff);
    file_recovery_new->min_filesize=be32(hdr->e_phoff);
    if(file_recovery_new->min_filesize < tmp)
      file_recovery_new->min_filesize=tmp;
  }
  return 1;
}

/*@
  @ requires buffer_size >= sizeof(Elf64_Ehdr);
  @ requires separation: \separated(&file_hint_elf, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_elf64_lsb(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const Elf64_Ehdr *hdr=(const Elf64_Ehdr *)buffer;
  if(le32(hdr->e_version) != 1)
    return 0;
  /* http://en.wikipedia.org/wiki/Executable_and_Linkable_Format */
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_elf.extension;
  {
    const uint64_t tmp=le64(hdr->e_shoff);
    file_recovery_new->min_filesize=le64(hdr->e_phoff);
    if(file_recovery_new->min_filesize < tmp)
      file_recovery_new->min_filesize=tmp;
  }
  return 1;
}

/*@
  @ requires buffer_size >= sizeof(Elf64_Ehdr);
  @ requires separation: \separated(&file_hint_elf, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_elf64_msb(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const Elf64_Ehdr *hdr=(const Elf64_Ehdr *)buffer;
  if(be32(hdr->e_version) != 1)
    return 0;
  /* http://en.wikipedia.org/wiki/Executable_and_Linkable_Format */
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_elf.extension;
  {
    const uint64_t tmp=be64(hdr->e_shoff);
    file_recovery_new->min_filesize=be64(hdr->e_phoff);
    if(file_recovery_new->min_filesize < tmp)
      file_recovery_new->min_filesize=tmp;
  }
  return 1;
}

static void register_header_check_elf(file_stat_t *file_stat)
{
  static const unsigned char elf_header32_lsb[6]  = { 0x7f, 'E','L','F',0x01, ELFDATA2LSB};
  static const unsigned char elf_header32_msb[6]  = { 0x7f, 'E','L','F',0x01, ELFDATA2MSB};
  static const unsigned char elf_header64_lsb[6]  = { 0x7f, 'E','L','F',0x02, ELFDATA2LSB};
  static const unsigned char elf_header64_msb[6]  = { 0x7f, 'E','L','F',0x02, ELFDATA2MSB};
  register_header_check(0, elf_header32_lsb, sizeof(elf_header32_lsb), &header_check_elf32_lsb, file_stat);
  register_header_check(0, elf_header32_msb, sizeof(elf_header32_msb), &header_check_elf32_msb, file_stat);
  register_header_check(0, elf_header64_lsb, sizeof(elf_header64_lsb), &header_check_elf64_lsb, file_stat);
  register_header_check(0, elf_header64_msb, sizeof(elf_header64_msb), &header_check_elf64_msb, file_stat);
}
#endif
