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

static const unsigned char exe_header[]  = {'M','Z'};

static void register_header_check_exe(file_stat_t *file_stat)
{
  register_header_check(0, exe_header,sizeof(exe_header), &header_check_exe, file_stat);
}

static int header_check_exe(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(buffer,exe_header,sizeof(exe_header))==0)
  {
    const struct pe_image_file_hdr *pe_hdr;
    uint32_t e_lfanew=buffer[0x3c]+ (buffer[0x3c+1]<<8) +
      (buffer[0x3c+2]<<16) + (buffer[0x3c+3]<<24); /* address of new exe header */
    if(e_lfanew==0 || e_lfanew>buffer_size-sizeof(struct pe_image_file_hdr))
    {
#ifdef DEBUG_EXE
      log_debug("EXE rejected, not PE (e_lfanew)\n");
#endif
      return 0;
    }
    pe_hdr=(const struct pe_image_file_hdr *)(buffer+e_lfanew);
    if(le32(pe_hdr->Magic) != IMAGE_NT_SIGNATURE)
    {
#ifdef DEBUG_EXE
      log_debug("EXE rejected, not PE (missing signature)\n");
#endif
      return 0;
    }
    if(le16(pe_hdr->Characteristics) & 0x2000)
    {
      /* Dynamic Link Library */
      reset_file_recovery(file_recovery_new);
      file_recovery_new->extension="dll";
    }
    else if(le16(pe_hdr->Characteristics) & 0x01)
    {
      reset_file_recovery(file_recovery_new);
      file_recovery_new->extension=file_hint_exe.extension;
    }
    else
    {
#ifdef DEBUG_EXE
      log_debug("EXE rejected, bad characteristics\n");
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

