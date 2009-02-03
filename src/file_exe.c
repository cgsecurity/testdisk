/*

    File: file_exe.c

    Copyright (C) 1998-2005,2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include "pe.h"
#include "log.h"

static void register_header_check_exe(file_stat_t *file_stat);
static int header_check_exe(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_exe= {
  .extension="exe",
  .description="MS Windows executable",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_exe
};

static const unsigned char exe_header[2]  = {'M','Z'};

static void register_header_check_exe(file_stat_t *file_stat)
{
  register_header_check(0, exe_header,sizeof(exe_header), &header_check_exe, file_stat);
}

static int header_check_exe(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct dos_image_file_hdr *dos_hdr=(const struct dos_image_file_hdr*)buffer;
  if(memcmp(buffer,exe_header,sizeof(exe_header))==0 &&
    le16(dos_hdr->bytes_in_last_block) <= 512 &&
    le16(dos_hdr->blocks_in_file) > 0 &&
    le16(dos_hdr->min_extra_paragraphs) <= le16(dos_hdr->max_extra_paragraphs)
    )
  {
    const struct pe_image_file_hdr *pe_hdr;
    pe_hdr=(const struct pe_image_file_hdr *)(buffer+le32(dos_hdr->e_lfanew));
    if(le32(dos_hdr->e_lfanew)==0 ||
	le32(dos_hdr->e_lfanew) > buffer_size-sizeof(struct pe_image_file_hdr) ||
	le32(pe_hdr->Magic) != IMAGE_NT_SIGNATURE)
    {
      uint64_t coff_offset=0;
      coff_offset=le16(dos_hdr->blocks_in_file)*512;
      if(le16(dos_hdr->bytes_in_last_block))
	coff_offset-=512-le16(dos_hdr->bytes_in_last_block);

      if(coff_offset+1 < buffer_size &&
	  buffer[coff_offset]==0x4c && buffer[coff_offset+1]==0x01)
      { /*  COFF_I386MAGIC */
	reset_file_recovery(file_recovery_new);
	file_recovery_new->extension=file_hint_exe.extension;
	return 1;
      }
#ifdef DEBUG_EXE
      {
	unsigned int i;
	const struct exe_reloc *exe_reloc;
	log_info("Maybe a DOS EXE\n");
	log_info("blocks %llu\n", (long long unsigned)coff_offset);
	log_info("data start %llx\n", (long long unsigned)16*le16(dos_hdr->header_paragraphs));
	log_info("reloc %u\n", le16(dos_hdr->num_relocs));
	for(i=0, exe_reloc=(const struct exe_reloc *)(buffer+le16(dos_hdr->reloc_table_offset));
	    i < le16(dos_hdr->num_relocs) &&
	    le16(dos_hdr->reloc_table_offset)+ (i+1)*sizeof(struct exe_reloc) < buffer_size;
	    i++, exe_reloc++)
	{
	  log_info("offset %x, segment %x\n",
	      le16(exe_reloc->offset), le16(exe_reloc->segment));
	}
      }
#endif
      return 0;
    }
    if(le16(pe_hdr->Characteristics) & 0x2000)
    {
      /* Dynamic Link Library */
      reset_file_recovery(file_recovery_new);
      file_recovery_new->extension="dll";
    }
    else if(le16(pe_hdr->Characteristics) & 0x02)
    {
      reset_file_recovery(file_recovery_new);
      file_recovery_new->extension=file_hint_exe.extension;
    }
    else
    {
#ifdef DEBUG_EXE
      log_warning("EXE rejected, bad characteristics %02x\n", le16(pe_hdr->Characteristics));
#endif
      return 0;
    }
#ifdef DEBUG_EXE
    {
      const struct pe_image_optional_hdr32 *pe_image_optional32=(const struct pe_image_optional_hdr32 *)
        (((const unsigned char*)pe_hdr + sizeof(struct pe_image_file_hdr)));
      if(le16(pe_image_optional32->Magic)==IMAGE_NT_OPTIONAL_HDR_MAGIC)
      {
        log_debug("SizeOfCode %lx\n", (long unsigned)le32(pe_image_optional32->SizeOfCode));
        log_debug("SizeOfImage %lx\n", (long unsigned)le32(pe_image_optional32->SizeOfImage));
      }
      else if(le16(pe_image_optional32->Magic)==IMAGE_NT_OPTIONAL_HDR64_MAGIC)
      {
        const struct pe_image_optional_hdr64 *pe_image_optional64=(const struct pe_image_optional_hdr64 *)
          (((const unsigned char*)pe_hdr + sizeof(struct pe_image_file_hdr)));
      }
      log_debug("PE image opt 0x%lx-0x%lx\n", (long unsigned)sizeof(struct pe_image_file_hdr),
          (long unsigned)(sizeof(struct pe_image_file_hdr) + le16(pe_hdr->SizeOfOptionalHeader) - 1));
    }
#endif
    {
      unsigned int i;
      uint64_t sum=0;
      const struct pe_image_section_hdr *pe_image_section=(const struct pe_image_section_hdr*)
        ((const unsigned char*)pe_hdr + sizeof(struct pe_image_file_hdr) + le16(pe_hdr->SizeOfOptionalHeader));
      for(i=0;i<le16(pe_hdr->NumberOfSections) && (const unsigned char*)pe_image_section < buffer+buffer_size;i++,pe_image_section++)
      {
        if(le32(pe_image_section->SizeOfRawData)>0)
        {
#ifdef DEBUG_EXE
          log_debug("%s 0x%lx-0x%lx\n", pe_image_section->Name,
              (unsigned long)le32(pe_image_section->PointerToRawData),
              (unsigned long)le32(pe_image_section->PointerToRawData)+le32(pe_image_section->SizeOfRawData)-1);
#endif
          if(le32(pe_image_section->SizeOfRawData)%32==0)
          {
            if(sum < le32(pe_image_section->PointerToRawData) + le32(pe_image_section->SizeOfRawData))
              sum=le32(pe_image_section->PointerToRawData) + le32(pe_image_section->SizeOfRawData);
          }
        }
        if(le16(pe_image_section->NumberOfRelocations)>0)
        {
#ifdef DEBUG_EXE
          log_debug("relocations 0x%lx-0x%lx\n", 
              (unsigned long)le32(pe_image_section->PointerToRelocations),
              (unsigned long)le32(pe_image_section->PointerToRelocations)+1*le16(pe_image_section->NumberOfRelocations)-1);
#endif
          if(sum < le32(pe_image_section->PointerToRelocations)+ 1*le16(pe_image_section->NumberOfRelocations))
            sum = le32(pe_image_section->PointerToRelocations)+ 1*le16(pe_image_section->NumberOfRelocations);
        }
      }
      if(le32(pe_hdr->NumberOfSymbols)>0)
      {
#ifdef DEBUG_EXE
        log_debug("Symboles 0x%lx-0x%lx\n", (long unsigned)le32(pe_hdr->PointerToSymbolTable),
            (long unsigned)(le32(pe_hdr->PointerToSymbolTable)+ IMAGE_SIZEOF_SYMBOL*le32(pe_hdr->NumberOfSymbols))-1);
#endif
        if(le32(pe_hdr->NumberOfSymbols)<0x10000)
        {
          if(sum < le32(pe_hdr->PointerToSymbolTable)+ IMAGE_SIZEOF_SYMBOL*le32(pe_hdr->NumberOfSymbols))
            sum = le32(pe_hdr->PointerToSymbolTable)+ IMAGE_SIZEOF_SYMBOL*le32(pe_hdr->NumberOfSymbols);
        }
      }
      /* It's not perfect, EXE overlay are not recovered */
      file_recovery_new->calculated_file_size=sum;
    }
    file_recovery_new->data_check=&data_check_size;
    file_recovery_new->file_check=&file_check_size;
    return 1;
  }
  return 0;
}

