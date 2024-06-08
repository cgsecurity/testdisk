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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_exe)
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
#if defined(__FRAMAC__)
#include "__fc_builtin.h"
#endif

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_exe(file_stat_t *file_stat);

const file_hint_t file_hint_exe= {
  .extension="exe",
  .description="MS Windows executable",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_exe
};

static const char *extension_dll="dll";
static const unsigned char exe_header[2]  = {'M','Z'};

struct rsrc_entries_s
{
  uint32_t Type;
  uint32_t Pos;
} __attribute__ ((gcc_struct, __packed__));

struct rsrc_offlen
{
  uint32_t off;
  uint32_t len;
} __attribute__ ((gcc_struct, __packed__));

struct PE_index
{
  uint16_t len;
  uint16_t val_len;
  uint16_t type;	/* 0=binary data, 1=text*/
} __attribute__ ((gcc_struct, __packed__));

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

/*@
  @ requires \valid(file_recovery);
  @ requires valid_read_string((char*)&file_recovery->filename);
  @ requires 4096 >= needle_len > 0;
  @ requires end <= 0xffff;
  @ requires \valid_read(buffer+(0..end-1));
  @ requires \valid_read(needle+(0..needle_len-1));
  @ requires \separated(file_recovery, buffer+(..), needle+(..));
  @ ensures \result <= 0xffff;
  @*/
static int parse_String(file_recovery_t *file_recovery, const char*buffer, const unsigned int end, const char *needle, const unsigned int needle_len, const int force_ext)
{
  const struct PE_index *PE_index;
  unsigned int len;
  unsigned int val_len;
  unsigned int type;
  if(6 > end)
  {
    return -1;
  }
  PE_index=(const struct PE_index*)buffer;
  /*@ assert \valid_read(PE_index); */
  len=le16(PE_index->len);
  /*@ assert len <= 0xffff; */
  val_len=le16(PE_index->val_len);
  type=le16(PE_index->type);
#ifdef DEBUG_EXE
  log_info("parse_String len=%u val_len=%u type=%u\n", len, val_len, type);
#endif
  if(len > end)
    return -1;
  if(6 + 2 * val_len > len)
    return -1;
#ifdef DEBUG_EXE
  dump_log(buffer, len);
#endif
//  type=1 => text
  if(6+needle_len < end && type==1 && memcmp(&buffer[6], needle, needle_len)==0)
  {
    if(6 + needle_len + 2 * val_len > len)
      return -1;
    file_rename_unicode(file_recovery, buffer, end, 6+needle_len, NULL, force_ext);
  }
  return len;
}

/*@
  @ requires \valid(file_recovery);
  @ requires valid_read_string((char*)&file_recovery->filename);
  @ requires 4096 >= needle_len > 0;
  @ requires end <= 0xffff;
  @ requires \valid_read(buffer+(0..end-1));
  @ requires \valid_read(needle+(0..needle_len-1));
  @ requires \separated(file_recovery, buffer+(..), needle+(..));
  @*/
static int parse_StringArray(file_recovery_t *file_recovery, const char*buffer, const unsigned int end, const char *needle, const unsigned int needle_len, const int force_ext)
{
  unsigned int pos=0;
#ifdef DEBUG_EXE
  log_info("parse_StringArray end=%u\n", end);
#endif
  /*@
    @ loop invariant end <= 0xffff;
    @ loop invariant pos <= 0x20000;
    @ loop variant end - pos;
    @*/
  while(pos<end)
  {
    const int res=parse_String(file_recovery, &buffer[pos], end - pos, needle, needle_len, force_ext);
    if(res <= 0)
      return -1;
    /*@ assert 0xffff >= res > 0; */
    pos+=res;
    /* Padding */
    if((pos & 0x03)!=0)
      pos+=2;
  }
  return 0;
}

/*@
  @ requires \valid(file_recovery);
  @ requires valid_read_string((char*)&file_recovery->filename);
  @ requires 4096 >= needle_len > 0;
  @ requires \valid_read(buffer+(0..end-1));
  @ requires \valid_read(needle+(0..needle_len-1));
  @ requires \separated(file_recovery, buffer+(..), needle+(..));
  @*/
static int parse_StringTable(file_recovery_t *file_recovery, const char*buffer, const unsigned int end, const char *needle, const unsigned int needle_len, const int force_ext)
{
  const struct PE_index *PE_index;
  unsigned int pos;
  unsigned int len;
#ifdef DEBUG_EXE
  unsigned int val_len;
#endif
  if(6 > end)
  {
    return -1;
  }
  PE_index=(const struct PE_index*)buffer;
  /*@ assert \valid_read(PE_index); */
  len=le16(PE_index->len);
#ifdef DEBUG_EXE
  val_len=le16(PE_index->val_len);
  log_info("parse_StringTable len=%u val_len=%u type=%u\n", len, val_len, le16(PE_index->type));
#endif
  if(len > end)
    return -1;
  /* szKey: language identifier + code page */
  /* No need to add padding, pos&0x03 == 0 */
  pos = 6 + 2*8 + 2;
  if(pos > len)
    return -1;
  /* An array of one or more String structures */
  return parse_StringArray(file_recovery, &buffer[pos], len - pos, needle, needle_len, force_ext);
}

/*@
  @ requires \valid(file_recovery);
  @ requires valid_read_string((char*)&file_recovery->filename);
  @ requires 4096 >= needle_len > 0;
  @ requires \valid_read(buffer+(0..end-1));
  @ requires \valid_read(needle+(0..needle_len-1));
  @ requires \separated(file_recovery, buffer+(..), needle+(..));
  @*/
static int parse_StringFileInfo(file_recovery_t *file_recovery, const char*buffer, const unsigned int end, const char *needle, const unsigned int needle_len, const int force_ext)
{
  /* https://docs.microsoft.com/en-us/windows/win32/menurc/stringfileinfo */
  const struct PE_index *PE_index;
  unsigned int pos;
  unsigned int len;
  unsigned int val_len;
  if(6 > end)
  {
    return -1;
  }
  PE_index=(const struct PE_index*)buffer;
  /*@ assert \valid_read(PE_index); */
  len=le16(PE_index->len);
  val_len=le16(PE_index->val_len);
#ifdef DEBUG_EXE
  log_info("parse_StringFileInfo len=%u val_len=%u type=%u\n", len, val_len, le16(PE_index->type));
#endif
  if(len > end)
    return -1;
  if(6 + sizeof(StringFileInfo) > end)
    return 0;
  /* szKey == StringFileInfo ? */
  if(memcmp(&buffer[6], StringFileInfo, sizeof(StringFileInfo))!=0)
    return 0;
  if(val_len!=0)
    return -1;
  /* No need to add padding, pos&0x03 == 0 */
  pos=6 + sizeof(StringFileInfo);
  if(pos > len)
    return -1;
  return parse_StringTable(file_recovery, &buffer[pos], len - pos, needle, needle_len, force_ext);
}

/*@
  @ requires \valid(file_recovery);
  @ requires valid_read_string((char*)&file_recovery->filename);
  @ requires end > 0;
  @ requires 4096 >= needle_len > 0;
  @ requires \valid_read(buffer+(0..end-1));
  @ requires \valid_read(needle+(0..needle_len-1));
  @ requires \separated(vs_version_info+(..), file_recovery, buffer+(..), needle+(..));
  @ behavior types: requires \separated(vs_version_info+(..), \union(file_recovery, buffer+(..), needle+(..)));
  @*/
static int parse_VS_VERSIONINFO(file_recovery_t *file_recovery, const char*buffer, const unsigned int end, const char *needle, const unsigned int needle_len, const int force_ext)
{
  /* https://docs.microsoft.com/en-us/windows/win32/menurc/vs-versioninfo */
  unsigned int pos=0;
  const struct PE_index *PE_index;
  const char *stringName;
  unsigned int len;
  unsigned int val_len;
  if(6 > end)
  {
    return -1;
  }
  PE_index=(const struct PE_index*)buffer;
  /*@ assert \valid_read(PE_index); */
  len=le16(PE_index->len);
  val_len=le16(PE_index->val_len);
#ifdef DEBUG_EXE
  log_info("parse_VS_VERSIONINFO len=%u val_len=%u type=%u\n", len, val_len, le16(PE_index->type));
#endif
  if(len==0 && val_len==0)
  {
    return -1;
  }
  if(val_len > len)
    return -1;
  if(len > end)
    return -1;
  /*@ assert len <= end; */
  pos+=6;
  if(pos + sizeof(vs_version_info) >= len)
    return -1;
  stringName=&buffer[pos];
  /* szKey */
  if(memcmp(stringName, vs_version_info, sizeof(vs_version_info))!=0)
    return -1;
  pos+=sizeof(vs_version_info);
  /* Padding1 */
  if((pos & 0x03)!=0)
    pos+=2;
  /* VS_FIXEDFILEINFO */
  pos+=val_len;
  /* Padding2 */
  if((pos & 0x03)!=0)
    pos+=2;
  if(pos > len)
    return -1;
  /* Children */
  /* An array of zero or one StringFileInfo structures, and zero or one
   * VarFileInfo structures that are children of the current VS_VERSIONINFO structure. */
  if(parse_StringFileInfo(file_recovery, &buffer[pos], len - pos, needle, needle_len, force_ext) < 0)
    return -1;
  return 0;
}

/*@
  @ requires \valid(file);
  @ requires \valid(file_recovery);
  @ requires valid_read_string((char*)&file_recovery->filename);
  @*/
static void PEVersion(FILE *file, const unsigned int offset, const unsigned int length, file_recovery_t *file_recovery)
{
  char buffer[1024*1024];
#ifdef DEBUG_EXE
  log_info("PEVersion(file, %u, %u, file_recovery)\n", offset, length);
#endif
  if(length==0 || length > 1024*1024)
    return;
  if(fseek(file, offset, SEEK_SET)<0)
    return ;
  if(fread(&buffer, length, 1, file) != 1)
  {
    return ;
  }
#if defined(__FRAMAC__)
  Frama_C_make_unknown((char *)&buffer, sizeof(buffer));
#endif
  if(parse_VS_VERSIONINFO(file_recovery, (const char *)&buffer, length, OriginalFilename, sizeof(OriginalFilename), 0)==0)
  {
    return;
  }
  parse_VS_VERSIONINFO(file_recovery, buffer, length, InternalName, sizeof(InternalName), 1);
}

/*@
  @ requires \valid(file);
  @ requires base <= 0x7fffffff;
  @ requires \valid_read(pe_sections);
  @ requires \valid(file_recovery);
  @ requires valid_read_string((char*)&file_recovery->filename);
  @ requires \valid_read(rsrc_entry);
  @*/
static int pe_resource_language_aux(FILE *file, const unsigned int base, const struct pe_image_section_hdr *pe_sections, const unsigned int nbr_sections, file_recovery_t *file_recovery, const struct rsrc_entries_s *rsrc_entry)
{
  struct rsrc_offlen buffer;
  uint32_t off;
  unsigned int len;
  unsigned int j;
#ifdef DEBUG_EXE
  log_info("resource lang=%u, %x, offset %u\n",
      le32(rsrc_entry->Type),
      le32(rsrc_entry->Pos),
      base + (le32(rsrc_entry->Pos) & 0x7fffffff));
#endif
  if(fseek(file, base + (le32(rsrc_entry->Pos) & 0x7fffffff), SEEK_SET)<0)
  {
    return -1;
  }
  if(fread(&buffer, 1, sizeof(buffer), file) != sizeof(buffer))
  {
    return -1;
  }
#if defined(__FRAMAC__)
  Frama_C_make_unknown((char *)&buffer, sizeof(buffer));
#endif
  off=le32(buffer.off);
  len=le32(buffer.len);
  /*@
    @ loop invariant 0 <= j <= nbr_sections;
    @ loop variant nbr_sections - j;
    @*/
  for(j=0; j<nbr_sections; j++)
  {
    const struct pe_image_section_hdr *pe_section=&pe_sections[j];
    /*@ assert \valid_read(pe_section); */
    const uint32_t virt_addr_start=le32(pe_section->VirtualAddress);
    const uint64_t virt_addr_end=(uint64_t)virt_addr_start + le32(pe_section->SizeOfRawData);
    if(virt_addr_end <= 0xffffffff && virt_addr_start <= off && off < virt_addr_end && (uint64_t)off - virt_addr_start + base <=0xffffffff)
    {
      PEVersion(file, off - virt_addr_start + base, len, file_recovery);
      return 0;
    }
  }
  return 1;
}

/*@
  @ requires \valid(file);
  @ requires base <= 0x7fffffff;
  @ requires dir_start <= 0x7fffffff;
  @ requires \valid_read(pe_sections);
  @ requires \valid(file_recovery);
  @ requires valid_read_string((char*)&file_recovery->filename);
  @*/
static void pe_resource_language(FILE *file, const unsigned int base, const unsigned int dir_start, const struct pe_image_section_hdr *pe_sections, const unsigned int nbr_sections, file_recovery_t *file_recovery)
{
  struct rsrc_entries_s *rsrc_entries;
  unsigned int count;
  unsigned int i;
#ifdef DEBUG_EXE
  log_info("pe_resource_language(file, %u, %u)\n", base, dir_start);
#endif
  {
    unsigned char buffer[16];
    unsigned int nameEntries;
    unsigned int idEntries;
    if(fseek(file, base + dir_start, SEEK_SET)<0)
      return ;
    if(fread(buffer, 1, sizeof(buffer), file) != sizeof(buffer))
      return ;
#if defined(__FRAMAC__)
    Frama_C_make_unknown((char *)buffer, sizeof(buffer));
#endif
    nameEntries = buffer[12]+(buffer[13]<<8);
    idEntries =  buffer[14]+(buffer[15]<<8);
    count = nameEntries + idEntries;
  }
#ifdef DEBUG_EXE
  log_info("pe_resource_language count=%u\n", count);
#endif
  if(count==0 || count > 1024)
    return ;
  /*@ assert 0 < count <= 1024; */
#ifdef DISABLED_FOR_FRAMAC
  rsrc_entries=(struct rsrc_entries_s *)MALLOC(1024 * sizeof(struct rsrc_entries_s));
#else
  rsrc_entries=(struct rsrc_entries_s *)MALLOC(count * sizeof(struct rsrc_entries_s));
#endif
  /*@ assert \valid((char *)rsrc_entries + (0 ..  (unsigned long)((unsigned long)count * sizeof(struct rsrc_entries_s)) - 1)); */
  if(fread(rsrc_entries, sizeof(struct rsrc_entries_s), count, file) != count)
  {
    free(rsrc_entries);
    return ;
  }
#if defined(__FRAMAC__)
  Frama_C_make_unknown((char *)rsrc_entries, count * sizeof(struct rsrc_entries_s));
#endif
  /*@
    @ loop variant count - i;
    @*/
  for(i=0; i<count; i++)
  {
    const struct rsrc_entries_s *rsrc_entry=&rsrc_entries[i];
    int res=pe_resource_language_aux(file, base, pe_sections, nbr_sections, file_recovery, rsrc_entry);
    if(res <= 0)
    {
      free(rsrc_entries);
      return ;
    }
  }
  free(rsrc_entries);
}

/*@
  @ requires \valid(file);
  @ requires base <= 0x7fffffff;
  @ requires dir_start <= 0x7fffffff;
  @ requires \valid_read(pe_sections);
  @ requires \valid(file_recovery);
  @ requires valid_read_string((char*)&file_recovery->filename);
  @*/
static void pe_resource_id(FILE *file, const unsigned int base, const unsigned int dir_start, const struct pe_image_section_hdr *pe_sections, const unsigned int nbr_sections, file_recovery_t *file_recovery)
{
  struct rsrc_entries_s *rsrc_entries;
  unsigned int count;
  unsigned int i;
#ifdef DEBUG_EXE
  log_info("pe_resource_id(file, %u, %u)\n", base, dir_start);
#endif
  {
    unsigned char buffer[16];
    unsigned int nameEntries;
    unsigned int idEntries;
    if(fseek(file, base + dir_start, SEEK_SET)<0)
      return ;
    if(fread(buffer, 1, sizeof(buffer), file) != sizeof(buffer))
      return ;
#if defined(__FRAMAC__)
    Frama_C_make_unknown((char *)buffer, sizeof(buffer));
#endif
    nameEntries = buffer[12]+(buffer[13]<<8);
    idEntries =  buffer[14]+(buffer[15]<<8);
    count = nameEntries + idEntries;
  }
  if(count==0 || count > 1024)
    return ;
  /*@ assert 0 < count <= 1024; */
#ifdef DISABLED_FOR_FRAMAC
  rsrc_entries=(struct rsrc_entries_s *)MALLOC(1024 * sizeof(struct rsrc_entries_s));
#else
  rsrc_entries=(struct rsrc_entries_s *)MALLOC(count * sizeof(struct rsrc_entries_s));
#endif
  /*@ assert \valid((char *)rsrc_entries + (0 ..  (unsigned long)((unsigned long)count * sizeof(struct rsrc_entries_s)) - 1)); */
  if(fread(rsrc_entries, sizeof(struct rsrc_entries_s), count, file) != count)
  {
    free(rsrc_entries);
    return ;
  }
#if defined(__FRAMAC__)
  Frama_C_make_unknown((char *)rsrc_entries, count * sizeof(struct rsrc_entries_s));
#endif
  /*@
    @ loop variant count - i;
    @*/
  for(i=0; i<count; i++)
  {
    const struct rsrc_entries_s *rsrc_entry=&rsrc_entries[i];
#ifdef DEBUG_EXE
    log_info("resource id=%u, %x, offset %u\n",
	le32(rsrc_entry->Type),
	le32(rsrc_entry->Pos),
	base + (le32(rsrc_entry->Pos) & 0x7fffffff));
#endif
    if((le32(rsrc_entry->Pos) & 0x80000000)!=0)
    {
	pe_resource_language(file,
	    base,
	    le32(rsrc_entry->Pos) & 0x7fffffff,
	    pe_sections, nbr_sections, file_recovery);
    }
  }
  free(rsrc_entries);
}

/*@
  @ requires \valid(file);
  @ requires \valid_read(pe_sections);
  @ requires \valid(file_recovery);
  @ requires valid_read_string((char*)&file_recovery->filename);
  @*/
static void pe_resource_type(FILE *file, const unsigned int base, const unsigned int dir_start, const struct pe_image_section_hdr *pe_sections, const unsigned int nbr_sections, file_recovery_t *file_recovery)
{
  struct rsrc_entries_s *rsrc_entries;
  unsigned int count;
  unsigned int i;
#ifdef DEBUG_EXE
  log_info("pe_resource_type(file, %u, %u)\n", base, dir_start);
#endif
  /* TODO: remove these artifical limits ? */
  if(base > 0x7fffffff || dir_start > 0x7fffffff)
    return ;
  /*@ assert base <= 0x7fffffff; */
  {
    unsigned char buffer[16];
    unsigned int nameEntries;
    unsigned int idEntries;
    if(fseek(file, base, SEEK_SET)<0)
      return ;
    if(fread(buffer, 1, sizeof(buffer), file) != sizeof(buffer))
      return ;
#if defined(__FRAMAC__)
    Frama_C_make_unknown((char *)buffer, sizeof(buffer));
#endif
    nameEntries = buffer[12]+(buffer[13]<<8);
    idEntries =  buffer[14]+(buffer[15]<<8);
    count = nameEntries + idEntries;
  }
  if(count==0 || count > 1024)
    return ;
  /*@ assert 0 < count <= 1024; */
#ifdef DISABLED_FOR_FRAMAC
  rsrc_entries=(struct rsrc_entries_s *)MALLOC(1024 * sizeof(struct rsrc_entries_s));
#else
  rsrc_entries=(struct rsrc_entries_s *)MALLOC(count * sizeof(struct rsrc_entries_s));
#endif
  /*@ assert \valid((char *)rsrc_entries + (0 ..  (unsigned long)((unsigned long)count * sizeof(struct rsrc_entries_s)) - 1)); */
  if(fread(rsrc_entries, sizeof(struct rsrc_entries_s), count, file) != count)
  {
    free(rsrc_entries);
    return ;
  }
#if defined(__FRAMAC__)
  Frama_C_make_unknown((char *)rsrc_entries, count * sizeof(struct rsrc_entries_s));
#endif
  /*@
    @ loop variant count - i;
    @*/
  for(i=0; i<count; i++)
  {
    const struct rsrc_entries_s *rsrc_entry=&rsrc_entries[i];
    /*@ assert \valid_read(rsrc_entry); */
    const unsigned int rsrcType=le32(rsrc_entry->Type);
#ifdef DEBUG_EXE
    log_info("resource type=%u, %x, offset %u\n",
	rsrcType,
	le32(rsrc_entry->Pos),
	base + (le32(rsrc_entry->Pos) & 0x7fffffff));
#endif
    /* https://docs.microsoft.com/en-us/windows/win32/menurc/resource-types
     * RT_CURSOR=1, RT_ICON=3, RT_VERSION=16 */
    /* Only interested by version resources */
    if(rsrcType==16)
    {
      if((le32(rsrc_entry->Pos) & 0x80000000)!=0)
      {
	pe_resource_id(file,
	    base,
	    le32(rsrc_entry->Pos) & 0x7fffffff,
	    pe_sections, nbr_sections, file_recovery);
      }
    }
  }
  free(rsrc_entries);
}

/*@
  @ requires file_recovery->file_rename==&file_rename_pe_exe;
  @ requires valid_file_rename_param(file_recovery);
  @ ensures  valid_file_rename_result(file_recovery);
  @*/
static void file_rename_pe_exe(file_recovery_t *file_recovery)
{
  unsigned char buffer[4096];
  FILE *file;
  int buffer_size;
  const struct dos_image_file_hdr *dos_hdr;
  const struct pe_image_file_hdr *pe_hdr;
  unsigned int e_lfanew;
  if((file=fopen(file_recovery->filename, "rb"))==NULL)
    return;
  buffer_size=fread(buffer, 1, sizeof(buffer), file);
  /*@ assert buffer_size <= sizeof(buffer); */
  if(buffer_size < (int)sizeof(struct dos_image_file_hdr))
  {
    fclose(file);
    return ;
  }
  /*@ assert buffer_size >= sizeof(struct dos_image_file_hdr); */
#if defined(__FRAMAC__)
  Frama_C_make_unknown((char *)buffer, sizeof(buffer));
#endif
  if(memcmp(buffer,exe_header,sizeof(exe_header))!=0)
  {
    fclose(file);
    return ;
  }
  dos_hdr=(const struct dos_image_file_hdr*)buffer;
  /*@ assert \valid_read(dos_hdr); */
  e_lfanew=le32(dos_hdr->e_lfanew);
  if((unsigned int)buffer_size < e_lfanew+sizeof(struct pe_image_file_hdr))
  {
    fclose(file);
    return ;
  }
  if(e_lfanew==0 ||
      e_lfanew > buffer_size-sizeof(struct pe_image_file_hdr))
  {
    fclose(file);
    return ;
  }
  pe_hdr=(const struct pe_image_file_hdr *)(buffer+e_lfanew);
  /*@ assert \valid_read(pe_hdr); */
  if(le32(pe_hdr->Magic) != IMAGE_NT_SIGNATURE)
  {
    fclose(file);
    return ;
  }
  {
    const uint64_t offset_sections=e_lfanew + sizeof(struct pe_image_file_hdr) + le16(pe_hdr->SizeOfOptionalHeader);
    /* https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
     * Windows loader limits the number of sections to 96
     */
    const unsigned int nbr_sections=(le16(pe_hdr->NumberOfSections) < 96?le16(pe_hdr->NumberOfSections) : 96);
    struct pe_image_section_hdr pe_sections[96];
    unsigned int i;
    if(nbr_sections == 0)
    {
      fclose(file);
      return ;
    }
    /*@ assert 0 < nbr_sections <= 96; */
    if(fseek(file, offset_sections, SEEK_SET)<0)
    {
      fclose(file);
      return ;
    }
    if(fread(pe_sections, sizeof(struct pe_image_section_hdr), nbr_sections, file) != nbr_sections)
    {
      fclose(file);
      return ;
    }
#if defined(__FRAMAC__)
    Frama_C_make_unknown((char *)pe_sections, sizeof(pe_sections));
#endif
#ifdef DEBUG_EXE
    /*@
      @ loop invariant 0 <= i <= nbr_sections;
      @ loop variant nbr_sections - i;
      @*/
    for(i=0; i<nbr_sections; i++)
    {
      const struct pe_image_section_hdr *pe_section=&pe_sections[i];
      /*@ assert \valid_read(pe_section); */
      if(le32(pe_section->VirtualSize)>0)
      {
	log_info("%s 0x%lx-0x%lx\n", pe_section->Name,
	    (unsigned long)le32(pe_section->VirtualAddress),
	    (unsigned long)le32(pe_section->VirtualAddress)+le32(pe_section->VirtualSize)-1);
      }
    }
#endif
    /*@
      @ loop invariant 0 <= i <= nbr_sections;
      @ loop variant nbr_sections - i;
      @*/
    for(i=0; i<nbr_sections; i++)
    {
      const struct pe_image_section_hdr *pe_section=&pe_sections[i];
      /*@ assert \valid_read(pe_section); */
      if(le32(pe_section->SizeOfRawData)>0)
      {
	if(memcmp((const char*)pe_section->Name, ".rsrc", 6)==0)
	{
	  pe_resource_type(file,
	      le32(pe_section->PointerToRawData),
	      le32(pe_section->SizeOfRawData),
	      pe_sections, nbr_sections, file_recovery);
	  fclose(file);
	  return;
	}
      }
    }
  }
  fclose(file);
}

/*@
  @ requires buffer_size >= 2;
  @ requires separation: \separated(&file_hint_exe, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ ensures (\result == 1) ==> (file_recovery_new->extension == file_hint_exe.extension || file_recovery_new->extension == extension_dll);
  @ ensures (\result == 1) ==> (file_recovery_new->data_check == \null || file_recovery_new->data_check == &data_check_size);
  @ ensures (\result == 1) ==> (file_recovery_new->file_check == \null || file_recovery_new->file_check == &file_check_size);
  @ ensures (\result == 1) ==> (file_recovery_new->file_rename == \null || file_recovery_new->file_rename == &file_rename_pe_exe);
  @ ensures (\result == 1) ==> (valid_read_string(file_recovery_new->extension));
  @ assigns  *file_recovery_new;
  @*/
static int header_check_exe(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct dos_image_file_hdr *dos_hdr=(const struct dos_image_file_hdr*)buffer;
  if(memcmp(buffer,exe_header,sizeof(exe_header))!=0)
    return 0;
  if(le32(dos_hdr->e_lfanew)>0 &&
      le32(dos_hdr->e_lfanew) <= buffer_size-sizeof(struct pe_image_file_hdr))
  {
    const struct pe_image_file_hdr *pe_hdr=(const struct pe_image_file_hdr *)(buffer+le32(dos_hdr->e_lfanew));
    if((le32(pe_hdr->Magic) & 0xffff) == IMAGE_WIN16_SIGNATURE)
    {
      /* NE Win16 */
      reset_file_recovery(file_recovery_new);
      file_recovery_new->extension=file_hint_exe.extension;
      file_recovery_new->min_filesize=le32(dos_hdr->e_lfanew) + sizeof(struct pe_image_file_hdr);
      return 1;
    }
    if((le32(pe_hdr->Magic) & 0xffff) == IMAGE_NT_SIGNATURE)
    {
      /* Windows PE */
      if(le16(pe_hdr->Characteristics) & 0x2000)
      {
	/* Dynamic Link Library */
	reset_file_recovery(file_recovery_new);
	file_recovery_new->extension=extension_dll;
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
	if((const unsigned char*)(pe_image_optional32+1) <= buffer+buffer_size)
	{
	  /*@ assert \valid_read(pe_image_optional32); */
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
      }
#endif
      {
	unsigned int i;
	uint64_t sum=le32(dos_hdr->e_lfanew) + sizeof(struct pe_image_file_hdr);
	const struct pe_image_section_hdr *pe_image_section=(const struct pe_image_section_hdr*)
	  ((const unsigned char*)pe_hdr + sizeof(struct pe_image_file_hdr) + le16(pe_hdr->SizeOfOptionalHeader));
	/*@
	  @ loop assigns i, pe_image_section, sum;
	  @ loop variant le16(pe_hdr->NumberOfSections) - i;
	  @*/
	for(i=0;
	    i<le16(pe_hdr->NumberOfSections) &&
	    (const unsigned char*)(pe_image_section+1) <= buffer+buffer_size;
	    i++,pe_image_section++)
	{
	  if(le32(pe_image_section->SizeOfRawData)>0)
	  {
	    const uint64_t tmp=(uint64_t)le32(pe_image_section->PointerToRawData) + le32(pe_image_section->SizeOfRawData);
#ifdef DEBUG_EXE
	    log_debug("%s 0x%lx-0x%lx\n", pe_image_section->Name,
		(unsigned long)le32(pe_image_section->PointerToRawData),
		(unsigned long)(tmp-1));
#endif
	    if(le32(pe_image_section->SizeOfRawData)%32==0)
	    {
	      if(sum < tmp)
		sum=tmp;
	    }
	  }
	  if(le16(pe_image_section->NumberOfRelocations)>0)
	  {
	    /*@ assert le16(pe_image_section->NumberOfRelocations)>0; */
	    const uint64_t tmp=(uint64_t)le32(pe_image_section->PointerToRelocations)+ 1*le16(pe_image_section->NumberOfRelocations);
	    /*@ assert tmp > 0; */
#ifdef DEBUG_EXE
	    log_debug("relocations 0x%lx-0x%lx\n",
		(unsigned long)le32(pe_image_section->PointerToRelocations),
		(unsigned long)(tmp-1));
#endif
	    if(sum < tmp)
	      sum = tmp;
	  }
	}
	if(le32(pe_hdr->NumberOfSymbols)>0)
	{
	  /*@ assert le32(pe_hdr->NumberOfSymbols)>0; */
	  const uint64_t tmp=(uint64_t)le32(pe_hdr->PointerToSymbolTable)+ IMAGE_SIZEOF_SYMBOL*(uint64_t)le32(pe_hdr->NumberOfSymbols);
	  /*@ assert tmp > 0; */
#ifdef DEBUG_EXE
	  log_debug("Symboles 0x%lx-0x%lx\n", (long unsigned)le32(pe_hdr->PointerToSymbolTable),
	      (long unsigned)(tmp-1));
#endif
	  if(le32(pe_hdr->NumberOfSymbols)<0x10000)
	  {
	    if(sum < tmp)
	      sum = tmp;
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

    if(coff_offset < buffer_size-1 &&
	buffer[coff_offset]==0x4c && buffer[coff_offset+1]==0x01)
    { /*  COFF_I386MAGIC */
      reset_file_recovery(file_recovery_new);
      file_recovery_new->extension=file_hint_exe.extension;
      file_recovery_new->min_filesize=coff_offset+2;
      return 1;
    }
#ifdef DEBUG_EXE
    {
      const struct exe_reloc *exe_relocs;
      const unsigned int reloc_table_offset=le16(dos_hdr->reloc_table_offset);
      const unsigned int num_relocs=le16(dos_hdr->num_relocs);
      log_info("Maybe a DOS EXE\n");
      log_info("blocks %llu\n", (long long unsigned)coff_offset);
      log_info("data start %llx\n", (long long unsigned)16*le16(dos_hdr->header_paragraphs));
      log_info("reloc %u\n", num_relocs);
      if(reloc_table_offset + num_relocs * sizeof(struct exe_reloc) <= buffer_size)
      {
	unsigned int i;
	/*@ assert reloc_table_offset + num_relocs * sizeof(struct exe_reloc) <= buffer_size; */
	exe_relocs=(const struct exe_reloc *)(buffer+reloc_table_offset);
	/*@ assert \valid_read(exe_relocs + (0 .. num_relocs-1)); */
	/*@
	  @ loop invariant 0 <= i <= num_relocs;
	  @ loop variant num_relocs -i;
	  @ */
	for(i=0; i < num_relocs; i++)
	{
	  /*@ assert 0 <= i <= num_relocs; */
	  const struct exe_reloc *exe_reloc=&exe_relocs[i];
	  /*@ assert \valid_read(exe_reloc); */
	  log_info("offset %x, segment %x\n",
	      le16(exe_reloc->offset), le16(exe_reloc->segment));
	}
      }
    }
#endif
  }
  return 0;
}

static void register_header_check_exe(file_stat_t *file_stat)
{
  register_header_check(0, exe_header,sizeof(exe_header), &header_check_exe, file_stat);
}
#endif

#if defined(MAIN_exe)
#define BLOCKSIZE 65536u
int main()
{
  const char fn[] = "recup_dir.1/f0000000.exe";
  unsigned char buffer[BLOCKSIZE];
  file_recovery_t file_recovery_new;
  file_recovery_t file_recovery;
  file_stat_t file_stats;

  /*@ assert \valid(buffer + (0 .. (BLOCKSIZE - 1))); */
#if defined(__FRAMAC__)
  Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif

  reset_file_recovery(&file_recovery);
  file_recovery.blocksize=BLOCKSIZE;
  file_recovery_new.blocksize=BLOCKSIZE;
  file_recovery_new.data_check=NULL;
  file_recovery_new.file_stat=NULL;
  file_recovery_new.file_check=NULL;
  file_recovery_new.file_rename=NULL;
  file_recovery_new.calculated_file_size=0;
  file_recovery_new.file_size=0;
  file_recovery_new.location.start=0;

  file_stats.file_hint=&file_hint_exe;
  file_stats.not_recovered=0;
  file_stats.recovered=0;
  register_header_check_exe(&file_stats);
  if(header_check_exe(buffer, BLOCKSIZE, 0u, &file_recovery, &file_recovery_new)!=1)
    return 0;
  /*@ assert valid_read_string((char *)&fn); */
  memcpy(file_recovery_new.filename, fn, sizeof(fn));
  /*@ assert valid_read_string((char *)&file_recovery_new.filename); */
  /*@ assert file_recovery_new.file_size == 0;	*/
  /*@ assert file_recovery_new.extension == file_hint_exe.extension || file_recovery_new.extension == extension_dll;	*/
  file_recovery_new.file_stat=&file_stats;
  if(file_recovery_new.file_stat!=NULL && file_recovery_new.file_stat->file_hint!=NULL &&
    file_recovery_new.data_check!=NULL)
  {
    unsigned char big_buffer[2*BLOCKSIZE];
    data_check_t res_data_check=DC_CONTINUE;
    memset(big_buffer, 0, BLOCKSIZE);
    memcpy(big_buffer + BLOCKSIZE, buffer, BLOCKSIZE);
    /*@ assert file_recovery_new.data_check == &data_check_size; */
    /*@ assert file_recovery_new.file_size == 0; */;
    res_data_check=data_check_size(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    file_recovery_new.file_size+=BLOCKSIZE;
    if(res_data_check == DC_CONTINUE)
    {
      memcpy(big_buffer, big_buffer + BLOCKSIZE, BLOCKSIZE);
#if defined(__FRAMAC__)
      Frama_C_make_unknown((char *)big_buffer + BLOCKSIZE, BLOCKSIZE);
#endif
      data_check_size(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    }
  }
  if(file_recovery_new.file_stat!=NULL)
  {
    file_recovery_t file_recovery_new2;
    /* Test when another file of the same is detected in the next block */
    file_recovery_new2.blocksize=BLOCKSIZE;
    file_recovery_new2.file_stat=NULL;
    file_recovery_new2.file_check=NULL;
    file_recovery_new2.location.start=BLOCKSIZE;
    file_recovery_new.handle=NULL;	/* In theory should be not null */
    header_check_exe(buffer, BLOCKSIZE, 0, &file_recovery_new, &file_recovery_new2);
  }
  if(file_recovery_new.file_check!=NULL)
  {
    /*@ assert file_recovery_new.file_check == &file_check_size; */
    file_recovery_new.handle=fopen(fn, "rb");
    if(file_recovery_new.handle!=NULL)
    {
      file_check_size(&file_recovery_new);
      fclose(file_recovery_new.handle);
    }
  }
  if(file_recovery_new.file_rename!=NULL)
  {
    /*@ assert valid_read_string((char *)&file_recovery_new.filename); */
    /*@ assert file_recovery_new.file_rename == &file_rename_pe_exe; */
    file_rename_pe_exe(&file_recovery_new);
  }
  return 0;
}
#endif
