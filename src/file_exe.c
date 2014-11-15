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
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <stdio.h>
#include "types.h"
#include "common.h"
#include "filegen.h"
#include "pe.h"
#include "log.h"

static void register_header_check_exe(file_stat_t *file_stat);
static int header_check_exe(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);
static void file_rename_pe_exe(const char *old_filename);

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
  const struct pe_image_file_hdr *pe_hdr;
  if(memcmp(buffer,exe_header,sizeof(exe_header))!=0)
    return 0;
  pe_hdr=(const struct pe_image_file_hdr *)(buffer+le32(dos_hdr->e_lfanew));
  if(le32(dos_hdr->e_lfanew)>0 &&
      le32(dos_hdr->e_lfanew) <= buffer_size-sizeof(struct pe_image_file_hdr) &&
      (le32(pe_hdr->Magic) & 0xffff) == IMAGE_WIN16_SIGNATURE)
  {
    /* NE Win16 */
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_exe.extension;
    return 1;
  }
  if(le32(dos_hdr->e_lfanew)>0 &&
      le32(dos_hdr->e_lfanew) <= buffer_size-sizeof(struct pe_image_file_hdr) &&
      (le32(pe_hdr->Magic) & 0xffff) == IMAGE_NT_SIGNATURE)
  {
    /* Windows PE */
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
    file_recovery_new->time=le32(pe_hdr->TimeDateStamp);
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
    file_recovery_new->file_rename=&file_rename_pe_exe;
    return 1;
  }
  if(le16(dos_hdr->bytes_in_last_block) <= 512 &&
      le16(dos_hdr->blocks_in_file) > 0 &&
      le16(dos_hdr->min_extra_paragraphs) <= le16(dos_hdr->max_extra_paragraphs)
    )
  {
    /* MSDOS EXE */
    uint64_t coff_offset=le16(dos_hdr->blocks_in_file)*512;
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
  }
  return 0;
}

struct rsrc_entries_s
{
  uint32_t Type;
  uint32_t Pos;
} __attribute__ ((__packed__));

struct PE_index
{
  uint16_t len;
  uint16_t val_len;
  uint16_t type;
} __attribute__ ((__packed__));

static char vs_version_info[32]={
  'V', 0x0, 'S', 0x0, '_', 0x0, 'V', 0x0, 'E', 0x0, 'R', 0x0, 'S', 0x0, 'I', 0x0,
  'O', 0x0, 'N', 0x0, '_', 0x0, 'I', 0x0, 'N', 0x0, 'F', 0x0, 'O', 0x0, 0x0, 0x0
};

static char StringFileInfo[30]={
  'S', 0x0, 't', 0x0, 'r', 0x0, 'i', 0x0, 'n', 0x0, 'g', 0x0, 'F', 0x0, 'i', 0x0,
  'l', 0x0, 'e', 0x0, 'I', 0x0, 'n', 0x0, 'f', 0x0, 'o', 0x0, 0x0, 0x0
};

static char OriginalFilename[34]={
  'O', 0x0, 'r', 0x0, 'i', 0x0, 'g', 0x0, 'i', 0x0, 'n', 0x0, 'a', 0x0, 'l', 0x0,
  'F', 0x0, 'i', 0x0, 'l', 0x0, 'e', 0x0, 'n', 0x0, 'a', 0x0, 'm', 0x0, 'e', 0x0,
  0x0, 0x0
};

static char InternalName[24]={
  'I', 0x0, 'n', 0x0, 't', 0x0, 'e', 0x0, 'r', 0x0, 'n', 0x0, 'a', 0x0, 'l', 0x0,
  'N', 0x0, 'a', 0x0, 'm', 0x0, 'e', 0x0
};

static unsigned int ReadUnicodeStr(const char *buffer, unsigned int pos, const unsigned int len)
{
  for(; pos+2<len && (buffer[pos]!='\0' || buffer[pos+1]!='\0'); pos+=2)
  {
#ifdef DEBUG_EXE
    log_info("%c", buffer[pos]);
#endif
  }
  pos+=2;
  if((pos & 0x03)!=0)
    pos+=2;
  return pos;
}

static int PEVersion_aux(const char*buffer, const unsigned int end, const char *old_filename, const char *needle, const unsigned int needle_len, const int force_ext)
{
  unsigned int pos=0;
  while(1)
  {
    const struct PE_index *PE_index;
    pos=(pos + 3) & 0xfffffffc;  /* align on a 4-byte boundary */
    if(pos + 6 > end)
    {
      return -1;
    }
    PE_index=(const struct PE_index*)&buffer[pos];
    if(le16(PE_index->len)==0 && le16(PE_index->val_len)==0)
    {
      return -1;
    }
    {
      const char *stringName=&buffer[pos+6];
      if(pos + 6 + sizeof(vs_version_info) < end &&
	  memcmp(stringName, vs_version_info, sizeof(vs_version_info))==0)
      {
	pos+=6+sizeof(vs_version_info);
	if((pos & 0x03)!=0)
	  pos+=2;
	pos+=le16(PE_index->val_len);
      }
      else if(pos + 6 + sizeof(StringFileInfo) < end &&
	  memcmp(stringName, StringFileInfo, sizeof(StringFileInfo))==0 &&
	  le16(PE_index->val_len)==0)
      {
	unsigned int i;
	unsigned int pt=pos+6+sizeof(StringFileInfo);
	pos+=le16(PE_index->len);
	for(i=0; pt + 6 < pos; i++)
	{
	  if(i==0)
	  {
	    pt=ReadUnicodeStr(buffer, pt+6, pos);
	  }
	  else
	  {
	    int do_rename=0;
	    PE_index=(const struct PE_index*)&buffer[pt];
	    if(pt+6+needle_len < end &&
		memcmp(&buffer[pt+6], needle, needle_len)==0)
	    {
	      do_rename=1;
	    }
	    pt=ReadUnicodeStr(buffer, pt+6, pos);
	    if(le16(PE_index->val_len)>0)
	    {
	      if(do_rename)
	      {
		file_rename_unicode(old_filename, buffer, end, pt, NULL, force_ext);
		return 0;
	      }
#ifdef DEBUG_EXE
	      log_info(": ");
#endif
	      pt=ReadUnicodeStr(buffer, pt, pos);
	    }
	  }
#ifdef DEBUG_EXE
	  log_info("\n");
#endif
	}
      }
      else
      {
	pos+=le16(PE_index->len)+le16(PE_index->val_len);
      }
    }
  }
}

static void PEVersion(FILE *file, const unsigned int offset, const unsigned int length, const char *old_filename)
{
  char *buffer;
  if(length==0 || length > 1024*1024)
    return;
  if(fseek(file, offset, SEEK_SET)<0)
    return ;
  buffer=(char*)MALLOC(length);
  if(fread(buffer, length, 1, file) != 1)
  {
    free(buffer);
    return ;
  }
  if(PEVersion_aux(buffer, length, old_filename, OriginalFilename, sizeof(OriginalFilename), 0)==0)
  {
    free(buffer);
    return;
  }
  PEVersion_aux(buffer, length, old_filename, InternalName, sizeof(InternalName), 1);
  free(buffer);
}

static void file_exe_ressource(FILE *file, const unsigned int base, const unsigned int dir_start, const unsigned int size, const unsigned int rsrcType, const unsigned int level, const struct pe_image_section_hdr *pe_sections, unsigned int nbr_sections, const char *old_filename)
{
  struct rsrc_entries_s *rsrc_entries;
  struct rsrc_entries_s *rsrc_entry;
  unsigned char buffer[16];
  int buffer_size;
  unsigned int nameEntries;
  unsigned idEntries;
  unsigned int count;
  unsigned int i;
#ifdef DEBUG_EXE
  log_info("file_exe_ressource(file, %u, %u, %u, %u)\n", base, dir_start, size, level);
#endif
  if(level > 2)
    return ;
  if(fseek(file, base + dir_start, SEEK_SET)<0)
    return ;
  buffer_size=fread(buffer, 1, sizeof(buffer), file);
  if(buffer_size<16)
    return ;
  nameEntries = buffer[12]+(buffer[13]<<8);
  idEntries =  buffer[14]+(buffer[15]<<8);
  count = nameEntries + idEntries;
  if(count==0 || count > 1024)
    return ;
  rsrc_entries=(struct rsrc_entries_s *)MALLOC(count * sizeof(struct rsrc_entries_s));
  if(fread(rsrc_entries, sizeof(struct rsrc_entries_s), count, file) != count)
  {
    free(rsrc_entries);
    return ;
  }
  for(i=0, rsrc_entry=rsrc_entries; i<count; i++, rsrc_entry++)
  {
    const unsigned int rsrcType_new=(level==0?le32(rsrc_entry->Type):rsrcType);
#ifdef DEBUG_EXE
    log_info("ressource %u, %x, offset %u\n",
	rsrcType_new,
	le32(rsrc_entry->Pos),
	base + (le32(rsrc_entry->Pos) & 0x7fffffff));
#endif
    /* Only intersted by version resources */
    if(rsrcType_new==16)
    {
      if((le32(rsrc_entry->Pos) & 0x80000000)!=0)
      {
	file_exe_ressource(file,
	    base,
	    le32(rsrc_entry->Pos) & 0x7fffffff,
	    size,
	    (level==0?le32(rsrc_entry->Type):rsrcType),
	    level + 1,
	    pe_sections, nbr_sections, old_filename);
      }
      if(level==2)
      {
	unsigned int off;
	unsigned int len;
	if(fseek(file, base + (le32(rsrc_entry->Pos) & 0x7fffffff), SEEK_SET)<0)
	  return ;
	buffer_size=fread(buffer, 1, sizeof(buffer), file);
	if(buffer_size<16)
	  return ;
	off=buffer[0]+ (buffer[1]<<8) + (buffer[2]<<16) + (buffer[3]<<24);
	len=buffer[4]+ (buffer[5]<<8) + (buffer[6]<<16) + (buffer[7]<<24);
	{
	  const struct pe_image_section_hdr *pe_section;
	  for(i=0, pe_section=pe_sections; i<nbr_sections; i++,pe_section++)
	  {
	    if(le32(pe_section->VirtualAddress) <= off
	      && off < le32(pe_section->VirtualAddress) + le32(pe_section->SizeOfRawData))
	    {
	      PEVersion(file, off - le32(pe_section->VirtualAddress) + base, len, old_filename);
	      free(rsrc_entries);
	      return ;
	    }
	  }
	}
	free(rsrc_entries);
	return ;
      }
    }
  }
  free(rsrc_entries);
}

static void file_rename_pe_exe(const char *old_filename)
{
  unsigned char buffer[4096];
  FILE *file;
  int buffer_size;
  const struct dos_image_file_hdr *dos_hdr=(const struct dos_image_file_hdr*)buffer;
  const struct pe_image_file_hdr *pe_hdr;
  if((file=fopen(old_filename, "rb"))==NULL)
    return;
  buffer_size=fread(buffer, 1, sizeof(buffer), file);
  if(buffer_size < (int)sizeof(struct dos_image_file_hdr))
  {
    fclose(file);
    return ;
  }
  if(memcmp(buffer,exe_header,sizeof(exe_header))!=0)
  {
    fclose(file);
    return ;
  }
  if((unsigned int)buffer_size < le32(dos_hdr->e_lfanew)+sizeof(struct pe_image_file_hdr))
  {
    fclose(file);
    return ;
  }
  pe_hdr=(const struct pe_image_file_hdr *)(buffer+le32(dos_hdr->e_lfanew));
  if(le32(dos_hdr->e_lfanew)==0 ||
      le32(dos_hdr->e_lfanew) > buffer_size-sizeof(struct pe_image_file_hdr) ||
      le32(pe_hdr->Magic) != IMAGE_NT_SIGNATURE)
  {
    fclose(file);
    return ;
  }
  {
    unsigned int i;
    const struct pe_image_section_hdr *pe_sections;
    const struct pe_image_section_hdr *pe_section;
    unsigned int nbr_sections;
    pe_sections=(const struct pe_image_section_hdr*)
      ((const unsigned char*)pe_hdr + sizeof(struct pe_image_file_hdr) + le16(pe_hdr->SizeOfOptionalHeader));
    for(i=0, pe_section=pe_sections;
	i<le16(pe_hdr->NumberOfSections) && (const unsigned char*)pe_section < buffer+buffer_size;
	i++, pe_section++)
    {
#ifdef DEBUG_EXE
      if(le32(pe_section->SizeOfRawData)>0)
      {
	log_info("%s 0x%lx-0x%lx\n", pe_section->Name,
	    (unsigned long)le32(pe_section->VirtualAddress),
	    (unsigned long)le32(pe_section->VirtualAddress)+le32(pe_section->VirtualSize)-1);
      }
#endif
    }
    nbr_sections=i;
    for(i=0, pe_section=pe_sections;
	i<le16(pe_hdr->NumberOfSections) && (const unsigned char*)pe_section < buffer+buffer_size;
	i++, pe_section++)
    {
      if(le32(pe_section->SizeOfRawData)>0)
      {
	if(strcmp((const char*)pe_section->Name, ".rsrc")==0)
	{
	  file_exe_ressource(file,
	      le32(pe_section->PointerToRawData),
	      0,
	      le32(pe_section->SizeOfRawData),
	      0,
	      0,
	      pe_sections, nbr_sections, old_filename);
	  fclose(file);
	  return;
	}
      }
    }
  }
  fclose(file);
}
