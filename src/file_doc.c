/*

    File: file_doc.c

    Copyright (C) 1998-2009 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include <assert.h>
#include "types.h"
#include "common.h"
#include "filegen.h"
#include "ole.h"
#include "log.h"
#include "memmem.h"
#include "setdate.h"
#include "file_doc.h"
#if defined(__FRAMAC__)
#include "__fc_builtin.h"
#endif

static void register_header_check_doc(file_stat_t *file_stat);
static void file_check_doc(file_recovery_t *file_recovery);
static void file_rename_doc(file_recovery_t *file_recovery);
static uint32_t *OLE_load_FAT(FILE *IN, const struct OLE_HDR *header, const uint64_t offset);
static uint32_t *OLE_load_MiniFAT(FILE *IN, const struct OLE_HDR *header, const uint32_t *fat, const unsigned int fat_entries, const uint64_t offset);

const file_hint_t file_hint_doc= {
  .extension="doc",
  .description="Microsoft Office Document (doc/xls/ppt/vsd/...), 3ds Max, MetaStock, Wilcom ES",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_doc
};


const char WilcomDesignInformationDDD[56]=
{
  0x05, '\0', 'W', '\0', 'i', '\0', 'l', '\0',
  'c', '\0', 'o', '\0', 'm', '\0', 'D', '\0',
  'e', '\0', 's', '\0', 'i', '\0', 'g', '\0',
  'n', '\0', 'I', '\0', 'n', '\0', 'f', '\0',
  'o', '\0', 'r', '\0', 'm', '\0', 'a', '\0',
  't', '\0', 'i', '\0', 'o', '\0', 'n', '\0',
  'D', '\0', 'D', '\0', 'D', '\0', '\0', '\0'
};

/*@
  @ requires \valid(IN);
  @ requires (9 == uSectorShift) || (12 == uSectorShift);
  @ requires \valid( buf + (0 .. (1<<uSectorShift)-1));
  @ ensures \result == -1 || \result == 0;
  @*/
static int OLE_read_block(FILE *IN, unsigned char *buf, const unsigned int uSectorShift, const unsigned int block, const uint64_t offset)
{
  if(block==0xFFFFFFFF || block==0xFFFFFFFE)
    return -1;
  if(my_fseek(IN, offset + ((uint64_t)(1+block)<<uSectorShift), SEEK_SET) < 0)
  {
    return -1;
  }
  if(fread(buf, 1<<uSectorShift, 1, IN)!=1)
  {
    return -1;
  }
#if defined(__FRAMAC__)
  Frama_C_make_unknown((char *)buf, 1<<uSectorShift);
#endif
  return 0;
}

/*@
  @ requires buffer_size >= sizeof(struct OLE_HDR);
  @ requires \valid_read(buffer + (0 .. buffer_size-1));
  @*/
static const char *ole_get_file_extension(const unsigned char *buffer, const unsigned int buffer_size)
{
  const struct OLE_HDR *header=(const struct OLE_HDR *)buffer;
  const uint32_t *fat;
  unsigned int fat_entries;
  unsigned int block;
  unsigned int i;
  /*@ assert 9 == le16(header->uSectorShift) || 12 == le16(header->uSectorShift); */
  /*@ assert le32(header->num_FAT_blocks)>0; */
  const unsigned int uSectorShift=le16(header->uSectorShift);
  if(buffer_size<512)
    return NULL;
  /*@ assert buffer_size >= 512; */
  {
    const uint32_t *fati=(const uint32_t *)(header+1);
    const uint64_t fat_offset=((uint64_t)1+le32(fati[0])) << uSectorShift;
    unsigned int fat_size;
    if(fat_offset > buffer_size)
      return NULL;
    /*@ assert 0 < fat_offset <= buffer_size; */
    fat=(const uint32_t *)&buffer[fat_offset];
    fat_size=(le32(header->num_FAT_blocks) << uSectorShift);
    if(fat_offset + fat_size > buffer_size)
    {
      /*@ assert fat_offset + fat_size <= buffer_size; */
      fat_size=buffer_size - fat_offset;
    }
    fat_entries=fat_size>>2;
    /*@ assert \valid_read(fat + (0 .. fat_entries-1)); */
  }
  /* FFFFFFFE = ENDOFCHAIN
   * Use a loop count i to avoid endless loop */
#ifdef DEBUG_OLE
    log_info("ole_get_file_extension root_start_block=%u, fat_entries=%u\n", le32(header->root_start_block), fat_entries);
#endif
  for(block=le32(header->root_start_block), i=0;
      block<fat_entries && block!=0xFFFFFFFE && i<fat_entries;
      block=le32(fat[block]), i++)
  {
    const uint64_t offset_root_dir=((uint64_t)1+block)<<uSectorShift;
#ifdef DEBUG_OLE
    log_info("Root Directory block=%u (0x%x)\n", block, block);
#endif
    if(offset_root_dir>buffer_size-512)
      return NULL;
    /*@ assert offset_root_dir + 512 <= buffer_size; */
    {
      unsigned int sid;
      const struct OLE_DIR *dir_entries=(const struct OLE_DIR *)&buffer[offset_root_dir];
      /*@ assert \valid_read((char *)dir_entries + (0 .. 512-1)); */
      /*@ assert \valid_read(dir_entries + (0 .. 512/sizeof(struct OLE_DIR)-1)); */
      const char *ext=NULL;
      int is_db=0;
      for(sid=0;
	  sid<512/sizeof(struct OLE_DIR);
	  sid++)
      {
	const struct OLE_DIR *dir_entry=&dir_entries[sid];
	if(dir_entry->type==NO_ENTRY)
	  break;
#ifdef DEBUG_OLE
	{
	  unsigned int j;
	  for(j=0;j<64 && j<le16(dir_entry->namsiz) && dir_entry->name[j]!='\0';j+=2)
	  {
	    log_info("%c",dir_entry->name[j]);
	  }
	  for(;j<64;j+=2)
	    log_info(" ");
	  log_info(" namsiz=%u type %u", le16(dir_entry->namsiz), dir_entry->type);
	  log_info(" Flags=%s", (dir_entry->bflags==0?"Red  ":"Black"));
	  log_info(" sector %u (%u bytes)\n",
	      (unsigned int)le32(dir_entry->start_block),
	      (unsigned int)le32(dir_entry->size));
	}
#endif
	if(sid==1 && memcmp(&dir_entry->name, "1\0\0\0", 4)==0)
	  is_db=1;
	else if(is_db==1 && sid==2 && (memcmp(&dir_entry->name, "2\0\0\0", 4)==0 ||
	      memcmp(&dir_entry->name, "C\0a\0t\0a\0l\0o\0g\0", 14)==0))
	  is_db=2;
	switch(le16(dir_entry->namsiz))
	{
	  case 10:
	    if(memcmp(dir_entry->name, ".\0Q\0D\0F\0\0\0",10)==0)
	      return "qdf-backup";
	    break;
	  case 12:
	    /* 3ds max */
	    if(memcmp(dir_entry->name, "S\0c\0e\0n\0e\0\0\0",12)==0)
	      return "max";
	    /* Licom AlphaCAM */
	    else if(memcmp(dir_entry->name,"L\0i\0c\0o\0m\0\0\0",12)==0)
	      return "amb";
	    break;
	  case 18:
	    /* MS Excel
	     * Note: Microsoft Works Spreadsheet contains the same signature */
	    if(memcmp(dir_entry->name, "W\0o\0r\0k\0b\0o\0o\0k\0\0\0",18)==0)
	      ext="xls";
	    /* Microsoft Works .wps */
	    else if(memcmp(dir_entry->name,"C\0O\0N\0T\0E\0N\0T\0S\0\0\0",18)==0)
	      return "wps";
	    break;
	  case 20:
	    /* Page Maker */
	    if(memcmp(&dir_entry->name, "P\0a\0g\0e\0M\0a\0k\0e\0r\0\0\0", 20)==0)
	      return "p65";
	    break;
	  case 22:
	    /* SigmaPlot .jnb */
	    if(memcmp(dir_entry->name, "J\0N\0B\0V\0e\0r\0s\0i\0o\0n\0\0\0", 22)==0)
	      return "jnb";
	    /* Autodesk Inventor part ipt or iam file */
	    if(memcmp(dir_entry->name, "R\0S\0e\0S\0t\0o\0r\0a\0g\0e\0\0\0", 22)==0)
	      return "ipt";
	    break;
	  case 24:
	    /* HP Photosmart Photo Printing Album */
	    if(memcmp(dir_entry->name,"I\0m\0a\0g\0e\0s\0S\0t\0o\0r\0e\0\0\0",24)==0)
	      return "albm";
	    /* Lotus Approch */
	    if(memcmp(dir_entry->name,"A\0p\0p\0r\0o\0a\0c\0h\0D\0o\0c\0\0\0",24)==0)
	      return "apr";
	    break;
	  case 28:
	    /* Microsoft Works Spreadsheet or Chart */
	    if(memcmp(dir_entry->name,"W\0k\0s\0S\0S\0W\0o\0r\0k\0B\0o\0o\0k\0\0\0",28)==0)
	      return "xlr";
	    /* Visio */
	    else if(memcmp(dir_entry->name,"V\0i\0s\0i\0o\0D\0o\0c\0u\0m\0e\0n\0t\0\0\0",28)==0)
	      return "vsd";
	/* SolidWorks */
	    else if(memcmp(&dir_entry->name,"s\0w\0X\0m\0l\0C\0o\0n\0t\0e\0n\0t\0s\0\0\0",28)==0)
	    {
#ifdef DJGPP
	      return "sld";
#else
	      return "sldprt";
#endif
	    }
	    break;
	  case 32:
	    /* Revit */
	    if(memcmp(dir_entry->name, "R\0e\0v\0i\0t\0P\0r\0e\0v\0i\0e\0w\0004\0.\0000\0\0", 32)==0)
	      return "rvt";
	    break;
	  case 34:
	    if(memcmp(dir_entry->name, "S\0t\0a\0r\0C\0a\0l\0c\0D\0o\0c\0u\0m\0e\0n\0t\0\0\0",34)==0)
	      return "sdc";
	    break;
	  case 36:
	    if(memcmp(dir_entry->name, "S\0t\0a\0r\0D\0r\0a\0w\0D\0o\0c\0u\0m\0e\0n\0t\0003\0\0\0", 36)==0)
	      return "sda";
	    break;
	  case 38:
	    /* Quattro Pro spreadsheet */
	    if(memcmp(dir_entry->name, "N\0a\0t\0i\0v\0e\0C\0o\0n\0t\0e\0n\0t\0_\0M\0A\0I\0N\0\0\0", 38)==0)
	      return "qpw";
	    else if(memcmp(dir_entry->name, "S\0t\0a\0r\0W\0r\0i\0t\0e\0r\0D\0o\0c\0u\0m\0e\0n\0t\0\0\0", 38)==0)
	      return "sdw";
	    break;
	  case 40:
	    if(memcmp(dir_entry->name,"P\0o\0w\0e\0r\0P\0o\0i\0n\0t\0 \0D\0o\0c\0u\0m\0e\0n\0t\0\0\0", 40)==0)
	      return "ppt";
	    /* Outlook */
	    else if(memcmp(dir_entry->name,"_\0_\0n\0a\0m\0e\0i\0d\0_\0v\0e\0r\0s\0i\0o\0n\0001\0.\0000\0\0\0",40)==0)
	      return "msg";
	    break;
	  case 46:
	    if(memcmp(dir_entry->name,
		  "I\0S\0o\0l\0i\0d\0W\0o\0r\0k\0s\0I\0n\0f\0o\0r\0m\0a\0t\0i\0o\0n\0\0\0", 46)==0)
	    {
#ifdef DJGPP
	      return "sld";
#else
	      return "sldprt";
#endif
	    }
	    break;
	  case 56:
	    /* Wilcom ES Software */
	    if(memcmp(dir_entry->name, WilcomDesignInformationDDD, 56)==0)
	      return "emb";
	    break;
	}
	if(sid==1 && memcmp(&dir_entry->name, "D\0g\0n", 6)==0)
	  return "dgn";
      }
      if(ext!=NULL)
	return ext;
      /* Thumbs.db */
      if(is_db==2)
	return "db";
    }
  }
#ifdef DEBUG_OLE
  log_info("Root Directory end\n");
#endif
  return NULL;
}

/*@
  @ requires \valid(file_recovery);
  @ requires \valid(file_recovery->handle);
  @*/
void file_check_doc_aux(file_recovery_t *file_recovery, const uint64_t offset)
{
  unsigned char buffer_header[512];
  uint64_t doc_file_size;
  uint32_t *fat;
  unsigned long int i;
  unsigned int freesect_count=0;
  const struct OLE_HDR *header=(const struct OLE_HDR*)&buffer_header;
  const uint64_t doc_file_size_org=file_recovery->file_size;
  unsigned int uSectorShift;
  unsigned int num_FAT_blocks;
  file_recovery->file_size=offset;
  /*reads first sector including OLE header */
  if(my_fseek(file_recovery->handle, offset, SEEK_SET) < 0 ||
      fread(&buffer_header, sizeof(buffer_header), 1, file_recovery->handle) != 1)
    return ;
#if defined(__FRAMAC__)
  Frama_C_make_unknown((char *)&buffer_header, sizeof(buffer_header));
#endif
  uSectorShift=le16(header->uSectorShift);
  num_FAT_blocks=le32(header->num_FAT_blocks);
  /* Sanity check */
  if( uSectorShift != 9 && uSectorShift != 12)
    return ;
  /*@ assert 9 == uSectorShift || 12 == uSectorShift; */
#ifdef DEBUG_OLE
  log_info("file_check_doc %s\n", file_recovery->filename);
  log_trace("sector size          %u\n",1<<uSectorShift);
  log_trace("num_FAT_blocks       %u\n",num_FAT_blocks);
  log_trace("num_extra_FAT_blocks %u\n",le32(header->num_extra_FAT_blocks));
#endif
  if(num_FAT_blocks==0 ||
      le32(header->num_extra_FAT_blocks)>50)
    return ;
  /*@ assert num_FAT_blocks > 0; */
  /*@ assert 0 <= le32(header->num_extra_FAT_blocks) <= 50; */
  if(num_FAT_blocks > 109+le32(header->num_extra_FAT_blocks)*((1<<uSectorShift)/4-1))
    return ;
  /*@ assert num_FAT_blocks <= 109+le32(header->num_extra_FAT_blocks)*((1<<uSectorShift)/4-1); */
  if((fat=OLE_load_FAT(file_recovery->handle, header, offset))==NULL)
  {
#ifdef DEBUG_OLE
    log_info("OLE_load_FAT failed\n");
#endif
    return ;
  }
  /* Search how many entries are not used at the end of the FAT */
  {
    const unsigned int val_max=(num_FAT_blocks<<uSectorShift)/4-1;
    /*@ assert \valid_read((char *)fat + ( 0 .. val_max)); */
    /*@
      @ loop invariant 0 <= freesect_count <= val_max;
      @ loop assigns freesect_count;
      @ loop variant val_max - freesect_count;
      @*/
    for(freesect_count=0; freesect_count < val_max; freesect_count++)
    {
      const unsigned j=val_max-freesect_count;
      /*@ assert 0 <= j <= val_max; */
      if(fat[j]!=0xFFFFFFFF)
	break;
    }
  }
  /*@ assert 0 <= freesect_count <= (num_FAT_blocks<<uSectorShift)/4-1; */
  {
    const unsigned int block=(num_FAT_blocks<<uSectorShift)/4-freesect_count;
    doc_file_size=offset + (((uint64_t)1+block)<<uSectorShift);
  }
  if(doc_file_size > doc_file_size_org)
  {
#ifdef DEBUG_OLE
    log_info("doc_file_size=%llu + (1+(%u<<%u)/4-%u)<<%u\n",
	(unsigned long long)offset,
	num_FAT_blocks, uSectorShift,
	freesect_count, uSectorShift);
    log_info("doc_file_size %llu > doc_file_size_org %llu\n",
    (unsigned long long)doc_file_size, (unsigned long long)doc_file_size_org);
#endif
    free(fat);
    return ;
  }
#ifdef DEBUG_OLE
  log_trace("==> size : %llu\n", (long long unsigned)doc_file_size);
#endif
  {
    unsigned int block;
    const unsigned int fat_entries=(num_FAT_blocks==0 ?
	109:
	(num_FAT_blocks<<uSectorShift)/4);
#ifdef DEBUG_OLE
    log_info("root_start_block=%u, fat_entries=%u\n", le32(header->root_start_block), fat_entries);
#endif
    /* FFFFFFFE = ENDOFCHAIN
     * Use a loop count i to avoid endless loop */
    for(block=le32(header->root_start_block), i=0;
	block!=0xFFFFFFFE && i<fat_entries;
	block=le32(fat[block]), i++)
    {
      struct OLE_DIR *dir_entries;
#ifdef DEBUG_OLE
      log_info("read block %u\n", block);
#endif
      if(!(block < fat_entries))
      {
	free(fat);
	return ;
      }
#ifdef __FRAMAC__
      dir_entries=(struct OLE_DIR *)MALLOC(1<<12);
#else
      dir_entries=(struct OLE_DIR *)MALLOC(1<<uSectorShift);
#endif
      if(OLE_read_block(file_recovery->handle, (unsigned char *)dir_entries, uSectorShift, block, offset)<0)
      {
#ifdef DEBUG_OLE
	log_info("OLE_read_block failed\n");
#endif
	free(dir_entries);
	free(fat);
	return ;
      }
      {
	unsigned int sid;
	for(sid=0;
	    sid<(1<<uSectorShift)/sizeof(struct OLE_DIR);
	    sid++)
	{
	  const struct OLE_DIR *dir_entry=&dir_entries[sid];
	  if(dir_entry->type==NO_ENTRY)
	    break;
	  if(offset +
		le32(dir_entry->start_block) > 0 && le32(dir_entry->size) > 0 &&
		((le32(dir_entry->size) >= le32(header->miniSectorCutoff)
		  && le32(dir_entry->start_block) > fat_entries) ||
		 le32(dir_entry->size) > doc_file_size))
	  {
#ifdef DEBUG_OLE
	    log_info("error at sid %u\n", sid);
#endif
	    free(dir_entries);
	    free(fat);
	    return ;
	  }
	}
      }
      free(dir_entries);
    }
  }
  free(fat);
  file_recovery->file_size=doc_file_size;
}

/*@
  @ requires \valid(file_recovery);
  @ requires \valid(file_recovery->handle);
  @*/
static void file_check_doc(file_recovery_t *file_recovery)
{
  file_check_doc_aux(file_recovery, 0);
}

/*@
  @ requires buffer_size >= sizeof(struct OLE_HDR);
  @ requires \valid_read(buffer+(0..buffer_size-1));
  @ requires \valid_read(file_recovery);
  @ requires file_recovery->file_stat==\null || valid_read_string((char*)file_recovery->filename);
  @ requires \valid(file_recovery_new);
  @ requires file_recovery_new->blocksize > 0;
  @ requires separation: \separated(file_recovery, file_recovery_new);
  @ ensures \result == 0 || \result == 1;
  @ ensures (\result == 1) ==> (file_recovery_new->file_check == &file_check_doc);
  @ ensures (\result == 1) ==> (file_recovery_new->file_rename == &file_rename_doc);
  @ ensures (\result == 1) ==>  valid_read_string(file_recovery_new->extension);
  @*/
static int header_check_doc(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /*@ assert file_recovery->file_stat==\null || valid_read_string((char*)file_recovery->filename); */
  const struct OLE_HDR *header=(const struct OLE_HDR *)buffer;
  /* Check for Little Endian */
  if(le16(header->uByteOrder)!=0xFFFE)
    return 0;
  if(le16(header->uDllVersion)!=3 && le16(header->uDllVersion)!=4)
    return 0;
  if(le16(header->reserved)!=0 || le32(header->reserved1)!=0)
    return 0;
  if(le16(header->uMiniSectorShift)!=6)
    return 0;
  if(le16(header->uDllVersion)==3 && le16(header->uSectorShift)!=9)
    return 0;
  /* max and qbb file have uSectorShift=12 */
  if(le16(header->uDllVersion)==4 && le16(header->uSectorShift)!=12)
    return 0;
  if(le16(header->uDllVersion)==3 && le32(header->csectDir)!=0)
    return 0;
  /* max file have csectDir=1
   * qbb file have csectDir=4 */
  if(le16(header->uDllVersion)==4 && le32(header->csectDir)==0)
    return 0;
  /*
     num_FAT_blocks=109+num_extra_FAT_blocks*(512-1);
     maximum file size is 512+(num_FAT_blocks*128)*512, about 1.6GB
     */
  if(le32(header->num_FAT_blocks)==0 ||
      le32(header->num_extra_FAT_blocks)>50 ||
      le32(header->num_FAT_blocks)>109+le32(header->num_extra_FAT_blocks)*((1<<le16(header->uSectorShift))/4-1))
    return 0;
  /*@ assert file_recovery->file_stat==\null || valid_read_string((char*)file_recovery->filename); */
  reset_file_recovery(file_recovery_new);
  file_recovery_new->file_check=&file_check_doc;
  file_recovery_new->file_rename=&file_rename_doc;
  file_recovery_new->extension=ole_get_file_extension(buffer, buffer_size);
  if(file_recovery_new->extension!=NULL)
  {
    if(strcmp(file_recovery_new->extension,"sda")==0)
    {
      if(td_memmem(buffer,buffer_size,"StarImpress",11)!=NULL)
	file_recovery_new->extension="sdd";
    }
    else if(strcmp(file_recovery_new->extension,"wps")==0)
    {
      /* Distinguish between MS Works .wps and MS Publisher .pub */
      if(td_memmem(buffer,buffer_size,"Microsoft Publisher",19)!=NULL)
	file_recovery_new->extension="pub";
    }
    return 1;
  }
  if(td_memmem(buffer,buffer_size,"WordDocument",12)!=NULL)
  {
    file_recovery_new->extension="doc";
  }
  else if(td_memmem(buffer,buffer_size,"StarDraw",8)!=NULL)
  {
    file_recovery_new->extension="sda";
  }
  else if(td_memmem(buffer,buffer_size,"StarCalc",8)!=NULL)
  {
    file_recovery_new->extension="sdc";
  }
  else if(td_memmem(buffer,buffer_size,"StarImpress",11)!=NULL)
  {
    file_recovery_new->extension="sdd";
  }
  else if(td_memmem(buffer,buffer_size,"Worksheet",9)!=NULL ||
      td_memmem(buffer,buffer_size,"Book",4)!=NULL ||
      td_memmem(buffer,buffer_size,"Workbook",8)!=NULL ||
      td_memmem(buffer,buffer_size,"Calc",4)!=NULL)
  {
    file_recovery_new->extension="xls";
  }
  else if(td_memmem(buffer,buffer_size,"Power",5)!=NULL)
  {
    file_recovery_new->extension="ppt";
  }
  else if(td_memmem(buffer,buffer_size,"AccessObjSiteData",17)!=NULL)
  {
    file_recovery_new->extension="mdb";
  }
  else if(td_memmem(buffer,buffer_size,"Visio",5)!=NULL)
  {
    file_recovery_new->extension="vsd";
  }
  else if(td_memmem(buffer,buffer_size,"SfxDocument",11)!=NULL)
  {
    file_recovery_new->extension="sdw";
  }
  else if(td_memmem(buffer,buffer_size,"CPicPage",8)!=NULL)
  {	/* Flash Project File */
    file_recovery_new->extension="fla";
  }
  else if(td_memmem(buffer,buffer_size,"Microsoft Publisher",19)!=NULL)
  { /* Publisher */
    file_recovery_new->extension="pub";
  }
  else if(td_memmem(buffer, buffer_size, "Microsoft Works Database", 24)!=NULL
      || td_memmem( buffer, buffer_size, "MSWorksDBDoc", 12)!=NULL)
  { /* Microsoft Works .wdb */
    file_recovery_new->extension="wdb";
  }
  else if(td_memmem(buffer,buffer_size,"MetaStock",9)!=NULL)
  { /* MetaStock */
    file_recovery_new->extension="mws";
  }
  else
    file_recovery_new->extension=file_hint_doc.extension;
  return 1;
}

/*@
  @ requires \valid(IN);
  @ requires \valid_read(header);
  @ requires le32(header->num_FAT_blocks) > 0;
  @ requires 0 <= le32(header->num_extra_FAT_blocks)<= 50;
  @ requires 9 == le16(header->uSectorShift) || 12 == le16(header->uSectorShift);
  @ requires le32(header->num_FAT_blocks) <= 109+le32(header->num_extra_FAT_blocks)*((1<<le16(header->uSectorShift))/4-1);
  @ ensures \result==\null || \valid_read((const char *)\result + ( 0 .. (le32(header->num_FAT_blocks)<<le16(header->uSectorShift))-1));
  @*/
static uint32_t *OLE_load_FAT(FILE *IN, const struct OLE_HDR *header, const uint64_t offset)
{
  uint32_t *fat;
  uint32_t *dif;
  const unsigned int uSectorShift=le16(header->uSectorShift);
  const unsigned int num_FAT_blocks=le32(header->num_FAT_blocks);
  /*@ assert uSectorShift == le16(header->uSectorShift); */
  /*@ assert num_FAT_blocks==le32(header->num_FAT_blocks); */
  /*@ assert num_FAT_blocks <= 109+le32(header->num_extra_FAT_blocks)*((1<<uSectorShift)/4-1); */
  const unsigned int dif_size=109*4+(le32(header->num_extra_FAT_blocks)<<uSectorShift);
  /*@ assert 109*4 <= dif_size <= 109*4+(50<<12); */
#ifdef __FRAMAC__
  dif=(uint32_t*)MALLOC(109*4+(50<<12));
#else
  dif=(uint32_t*)MALLOC(dif_size);
#endif
  /*@ assert \valid((char *)dif+(0..dif_size-1)); */
  memcpy(dif,(header+1),109*4);
  if(le32(header->num_extra_FAT_blocks)>0)
  { /* Load DIF*/
    unsigned long int i;
    for(i=0; i<le32(header->num_extra_FAT_blocks); i++)
    {
      const unsigned int block=(i==0 ? le32(header->FAT_next_block) : le32(dif[109+i*(((1<<uSectorShift)/4)-1)]));
      unsigned char *data=(unsigned char*)&dif[109]+i*((1<<uSectorShift)-4);
      if(OLE_read_block(IN, data, uSectorShift, block, offset) < 0)
      {
	free(dif);
	return NULL;
      }
    }
  }
#ifdef __FRAMAC__
  /*@ assert (109+50*((1<<12)/4-1))<<12 >= num_FAT_blocks<<uSectorShift; */
  fat=(uint32_t*)MALLOC((109+50*((1<<12)/4-1))<<12);
#else
  fat=(uint32_t*)MALLOC(num_FAT_blocks<<uSectorShift);
#endif
  /*@ assert \valid((char *)fat + (0 .. (num_FAT_blocks<<uSectorShift)-1)); */
  { /* Load FAT */
    unsigned int j;
    for(j=0; j<num_FAT_blocks; j++)
    {
      if(OLE_read_block(IN, (unsigned char*)fat + (j<<uSectorShift), uSectorShift, le32(dif[j]), offset)<0)
      {
	free(dif);
	free(fat);
	return NULL;
      }
    }
  }
  free(dif);
  return fat;
}

/*@
  @ requires \valid(IN);
  @ requires \valid_read(fat + (0 .. fat_entries-1));
  @ requires 9 == uSectorShift || 12 == uSectorShift;
  @ requires 0 < len <= 1024*1024;
  @ ensures \result!=\null ==> \valid((char *)\result + (0 .. len - 1));
  @*/
static void *OLE_read_stream(FILE *IN,
    const uint32_t *fat, const unsigned int fat_entries, const unsigned int uSectorShift,
    const unsigned int block_start, const unsigned int len, const uint64_t offset)
{
  //@ split uSectorShift;
  unsigned char *dataPt;
  unsigned int block;
  unsigned int i;
  const unsigned int i_max=((len+(1<<uSectorShift)-1) >> uSectorShift);
#ifdef __FRAMAC__
  dataPt=(unsigned char *)MALLOC(((1024*1024+(1<<uSectorShift)-1) >> uSectorShift) << uSectorShift);
#else
  dataPt=(unsigned char *)MALLOC(i_max << uSectorShift);
#endif
  /*@ assert \valid(dataPt + ( 0 .. len-1)); */
  for(i=0, block=block_start;
      i < i_max;
      i++, block=le32(fat[block]))
  {
    if(!(block < fat_entries))
    {
      free(dataPt);
      return NULL;
    }
    if(OLE_read_block(IN, &dataPt[i<<uSectorShift], uSectorShift, block, offset)<0)
    {
      free(dataPt);
      return NULL;
    }
  }
  return dataPt;
}

/*@
  @ requires \valid(IN);
  @ requires \valid_read(header);
  @ requires \valid_read(fat);
  @ requires 9 == le16(header->uSectorShift) || 12 == le16(header->uSectorShift);
  @ requires 0 < le32(header->csectMiniFat) <= 2048;
  @ ensures \result!=\null ==> \valid((char *)\result + (0 .. (le32(header->csectMiniFat) << le16(header->uSectorShift)) - 1));
  @*/
static uint32_t *OLE_load_MiniFAT(FILE *IN, const struct OLE_HDR *header, const uint32_t *fat, const unsigned int fat_entries, const uint64_t offset)
{
  uint32_t *minifat;
  unsigned int block;
  unsigned int i;
  const unsigned int uSectorShift=le16(header->uSectorShift);
  if(le32(header->csectMiniFat)==0)
    return NULL;
  /*@ assert le32(header->csectMiniFat)!=0; */
#ifdef __FRAMAC__
  minifat=(uint32_t*)MALLOC(2048 << 12);
#else
  minifat=(uint32_t*)MALLOC(le32(header->csectMiniFat) << uSectorShift);
#endif
  block=le32(header->MiniFat_block);
  for(i=0; i < le32(header->csectMiniFat); i++)
  {
    unsigned char*minifat_pos=(unsigned char*)minifat + (i << uSectorShift);
    if(block >= fat_entries)
    {
      free(minifat);
      return NULL;
    }
    if(OLE_read_block(IN, (unsigned char *)minifat_pos, uSectorShift, block, offset)<0)
    {
      free(minifat);
      return NULL;
    }
    block=le32(fat[block]);
  }
  return minifat;
}

/*@
  @ requires \valid_read((char *)buffer + (offset .. offset + 4 - 1));
  @*/
static uint32_t get32u(const void *buffer, const unsigned int offset)
{
  const uint32_t *val=(const uint32_t *)((const unsigned char *)buffer+offset);
  return le32(*val);
}

/*@
  @ requires \valid_read((char *)buffer + (offset .. offset + 8 - 1));
  @*/
static uint64_t get64u(const void *buffer, const unsigned int offset)
{
  const uint64_t *val=(const uint64_t *)((const unsigned char *)buffer+offset);
  return le64(*val);
}

/*@
  @ requires \valid(ext);
  @ requires *ext == \null || valid_read_string(*ext);
  @ requires count > 0;
  @ requires \valid_read(software + (0 .. count-1));
  @ ensures *ext == \null || valid_read_string(*ext);
  @*/
static void software2ext(const char **ext, const unsigned int count, const unsigned char *software)
{
  if(count>=12 && memcmp(software, "MicroStation", 12)==0)
  {
    *ext="dgn";
    return;
  }
  if(count>=14 && memcmp(software, "Microsoft Word", 14)==0)
  {
    *ext="doc";
    return;
  }
  if(count>=15 && memcmp(software, "Microsoft Excel", 15)==0)
  {
    if(*ext==NULL || strcmp(*ext,"sldprt")!=0)
      *ext="xls";
    return;
  }
  if(count>=20 && memcmp(software, "Microsoft PowerPoint", 20)==0)
  {
    *ext="ppt";
    return;
  }
  if(count>=21 && memcmp(software, "Microsoft Office Word", 21)==0)
  {
    *ext="doc";
    return;
  }
  if(count==21 && memcmp(software, "TurboCAD for Windows", 21)==0)
  {
    *ext="tcw";
    return;
  }
  if(count==22 && memcmp(software, "TurboCAD pour Windows", 22)==0)
  {
    *ext="tcw";
    return;
  }
  return ;
}

/*@
  @ requires count > 0;
  @ requires \valid_read(software + (0 .. 2*count-1));
  @ ensures \result == \null || valid_read_string(\result);
  @*/
static const char *software_uni2ext(const unsigned int count, const unsigned char *software)
{
  if(count>=15 && memcmp(software, "M\0i\0c\0r\0o\0s\0o\0f\0t\0 \0E\0x\0c\0e\0l\0", 30)==0)
    return "et";
  if(count>=17 && memcmp(software, "D\0e\0l\0c\0a\0m\0 \0P\0o\0w\0e\0r\0S\0H\0A\0P\0E\0", 34)==0)
    return "psmodel";
  return NULL;
}

struct summary_entry
{
  uint32_t tag;
  uint32_t offset;
};

/*@
  @ requires 8 <= size <= 1024*1024;
  @ requires \valid_read(buffer+ (0 .. size-1));
  @ requires \valid(ext);
  @ requires \valid(title);
  @ requires \valid(file_time);
  @ requires *title == \null || valid_read_string(*title);
  @ requires *ext == \null || valid_read_string(*ext);
  @ ensures *ext == \null || valid_read_string(*ext);
  @ ensures *title == \null || valid_read_string(*title);
  @*/
static void OLE_parse_PropertySet(const unsigned char *buffer, const unsigned int size, const char **ext, char **title, time_t *file_time)
{
  const struct summary_entry *entries=(const struct summary_entry *)&buffer[8];
  const unsigned int numEntries=get32u(buffer, 4);
  unsigned int i;
#ifdef DEBUG_OLE
  log_info("Property Info %u entries - %u bytes\n", numEntries, size);
#endif
  if(numEntries == 0 || numEntries > 1024*1024)
    return ;
  /*@ assert 0 < numEntries <= 1024*1024; */
  if(8 + numEntries * 8 > size)
    return ;
  /*@ assert 8 + numEntries * 8 <= size; */
  /*@ assert numEntries * 8 <= size - 8; */
  /*@ assert numEntries < size/8; */
  if((const unsigned char *)&entries[numEntries] > &buffer[size])
    return ;
  /*TODO assert (const unsigned char *)&entries[numEntries] <= &buffer[size]; */
  /*@ assert \valid_read(buffer  + (0 .. size - 1)); */
  /*@ assert \valid_read((buffer+8)  + (8 .. size - 8 - 1)); */
  /*TODO assert \valid_read((char *)entries + (0 .. size - 8 - 1)); */
  /*TODO assert \valid_read(entries + (0 .. numEntries-1)); */
  /*@
    @ loop invariant 0 <= i <= numEntries;
    @ loop variant numEntries-i;
    @*/
  for(i=0; i<numEntries; i++)
  {
    //    const struct summary_entry *entry=&entries[i];
    const unsigned int entry_offset=8+8*i;
    if(entry_offset + 8 > size)
      return ;
    /*@ assert entry_offset + 8 <= size; */
    {
      const struct summary_entry *entry=(const struct summary_entry *)&buffer[entry_offset];
      const unsigned int tag=le32(entry->tag);
      const unsigned int offset=le32(entry->offset);
      unsigned int type;
      if(offset >= size - 4)
	return ;
      /*@ assert offset < size - 4; */
      /*@ assert \valid_read(buffer + (0 .. offset + 4 - 1)); */
      type=get32u(buffer, offset);
#ifdef DEBUG_OLE
      log_info("entry 0x%x, tag 0x%x, offset 0x%x, offset + 4 0x%x, type 0x%x\n",
	  entry, tag, offset, offset + 4, type);
#endif
      /* tag: Software, type: VT_LPSTR */
      if(tag==0x12 && type==30)
      {
	if(offset >= size - 8)
	  return ;
	/*@ assert offset < size - 8; */
	{
	  const unsigned int count=get32u(buffer, offset + 4);
	  const unsigned int offset_soft=offset + 8;
	  /*@ assert offset_soft == offset + 8; */
	  if(count > size)
	    return ;
	  /*@ assert count <= size; */
	  if(offset_soft + count > size)
	    return ;
	  /*@ assert offset_soft + count <= size; */
	  if(count > 0)
	  {
	    /*@ assert count > 0; */
#ifdef DEBUG_OLE
	    unsigned int j;
	    log_info("Software ");
	    for(j=0; j<count; j++)
	    {
	      log_info("%c", buffer[offset_soft + j]);
	    }
	    log_info("\n");
#endif
	    software2ext(ext, count, &buffer[offset_soft]);
	  }
	}
      }
      /* tag: Software, type: VT_LPWSTR */
      if(tag==0x12 && type==31)
      {
	if(offset >= size - 8)
	  return ;
	/*@ assert offset < size - 8; */
	{
	  const unsigned int count=get32u(buffer, offset + 4);
	  if(count > size)
	    return ;
	  /*@ assert count <= size; */
	  if(offset + 8 + 2 * count > size)
	    return ;
	  /*@ assert offset + 8 + 2 * count <= size; */
	  if(count > 0)
	  {
	    /*@ assert count > 0; */
#ifdef DEBUG_OLE
	    unsigned int j;
	    log_info("Software ");
	    for(j=0; j < 2 * count; j+=2)
	    {
	      log_info("%c", buffer[offset + 8 + j]);
	    }
	    log_info("\n");
#endif
	    *ext=software_uni2ext(count, &buffer[offset + 8]);
	  }
	}
      }
      /* tag: title, type: VT_LPSTR */
      if(tag==0x02 && type==30 && *title==NULL)
      {
	if(offset + 8 > size)
	  return ;
	/*@ assert offset + 8 <= size; */
	{
	  /*@ assert \valid_read(buffer + (0 .. size - 1)); */
	  const unsigned int count=get32u(buffer, offset + 4);
	  const unsigned int offset_tmp=offset + 8;
	  if(count > size)
	    return ;
	  /*@ assert count <= size; */
	  if(offset_tmp + count > size)
	    return ;
	  /*@ assert offset_tmp + count <= size; */
	  if(count > 0)
	  {
	    /*@ assert count > 0; */
	    char *tmp;
	    /*@ assert \valid_read(buffer + (0 .. size - 1)); */
	    /*@ assert \valid_read(buffer + (0 .. offset_tmp + count - 1)); */
	    tmp=(char*)MALLOC(count+1);
	    memcpy(tmp, &buffer[offset_tmp], count);
	    tmp[count]='\0';
#ifdef DEBUG_OLE
	    log_info("Title %s\n", tmp);
#endif
	    *title=tmp;
	  }
	}
      }
      /* ModifyDate, type=VT_FILETIME */
      if(tag==0x0d && type==64)
      {
	uint64_t tmp;
	if(offset + 12 > size)
	  return ;
	/*@ assert offset + 12 <= size; */
	tmp=get64u(buffer, offset + 4);
	tmp/=10000000;
	if(tmp > (uint64_t)134774 * 24 * 3600)
	{
	  tmp -= (uint64_t)134774 * 24 * 3600;
	  *file_time=tmp;
	}
      }
    }
  }
}

/*@
  @ requires 48 <= dirLen <= 1024*1024;
  @ requires \valid_read(dataPt + (0 .. dirLen-1));
  @ requires \valid(ext);
  @ requires \valid(title);
  @ requires \valid(file_time);
  @ requires *title == \null || valid_read_string(*title);
  @ requires *ext == \null || valid_read_string(*ext);
  @ ensures *ext == \null || valid_read_string(*ext);
  @ ensures *title == \null || valid_read_string(*title);
  @*/
static void OLE_parse_summary_aux(const unsigned char *dataPt, const unsigned int dirLen, const char **ext, char **title, time_t *file_time)
{
  unsigned int pos;
  assert(dirLen >= 48 && dirLen<=1024*1024);
#ifdef DEBUG_OLE
  dump_log(dataPt, dirLen);
#endif
#ifndef __FRAMAC__
  if(dataPt[0]!=0xfe || dataPt[1]!=0xff)
    return ;
#endif
  pos=get32u(dataPt, 44);
  if(pos > dirLen - 8)
    return ;
  /*@ assert pos <= dirLen - 8; */
  {
    /* PropertySet */
    const unsigned int size=get32u(dataPt, pos);
    if(size <= 8 || size > dirLen || pos + size > dirLen)
      return ;
    /*@ assert 8 < size <= dirLen <=1024*1024; */
    /*@ assert \valid_read(dataPt + (0 .. dirLen-1)); */
    /*@ assert pos + size <= dirLen; */
    /*@ assert \valid_read(dataPt + (0 .. pos+size-1)); */
    /*TODO assert \valid_read(&dataPt[pos] + (0 .. 1024*1024-1-pos)); */
    OLE_parse_PropertySet(&dataPt[pos], size, ext, title, file_time);
  }
}

/*@
  @ requires \valid_read(ministream + (0 .. ministream_size-1));
  @ requires \valid_read(minifat + (0 .. minifat_entries-1));
  @ requires uMiniSectorShift==6;
  @ requires 48 <= len <= 1024*1024;
  @ ensures \result!=\null ==> \valid((char *)\result + (0 .. len-1));
  @*/
static void *OLE_read_ministream(unsigned char *ministream,
    const uint32_t *minifat, const unsigned int minifat_entries, const unsigned int uMiniSectorShift,
    const unsigned int miniblock_start, const unsigned int len, const unsigned int ministream_size)
{
  unsigned char *dataPt;
  unsigned int mblock;
  unsigned int size_read;
#ifdef __FRAMAC__
  dataPt=(unsigned char *)MALLOC((1024*1024+(1<<uMiniSectorShift)-1) / (1<<uMiniSectorShift) * (1<<uMiniSectorShift));
#else
  dataPt=(unsigned char *)MALLOC((len+(1<<uMiniSectorShift)-1) / (1<<uMiniSectorShift) * (1<<uMiniSectorShift));
#endif
  for(mblock=miniblock_start, size_read=0;
      size_read < len;
      mblock=le32(minifat[mblock]), size_read+=(1<<uMiniSectorShift))
  {
    if(mblock >= minifat_entries)
    {
      free(dataPt);
      return NULL;
    }
    if((mblock+1)> ministream_size>>uMiniSectorShift)
    {
      free(dataPt);
      return NULL;
    }
    /*TODO assert \valid_read(ministream + (0 .. (mblock<<uMiniSectorShift) + (1<<uMiniSectorShift) -1)); */
    memcpy(&dataPt[size_read], &ministream[mblock<<uMiniSectorShift], (1<<uMiniSectorShift));
  }
  return dataPt;
}

/*@
  @ requires \valid(file);
  @ requires \valid_read(fat + (0 .. fat_entries-1));
  @ requires \valid_read(header);
  @ requires 9 == le16(header->uSectorShift) || 12 == le16(header->uSectorShift);
  @ requires 6 == le16(header->uMiniSectorShift);
  @ requires \valid(ext);
  @ requires \valid(title);
  @ requires \valid(file_time);
  @ requires *ext == \null || valid_read_string(*ext);
  @ requires *title == \null || valid_read_string(*title);
  @ ensures *ext == \null || valid_read_string(*ext);
  @ ensures *title == \null || valid_read_string(*title);
  @*/
static void OLE_parse_summary(FILE *file, const uint32_t *fat, const unsigned int fat_entries,
    const struct OLE_HDR *header, const unsigned int ministream_block, const unsigned int ministream_size,
    const unsigned int block, const unsigned int len, const char **ext, char **title, time_t *file_time,
    const uint64_t offset)
{
  const unsigned int uSectorShift=le16(header->uSectorShift);
  unsigned char *summary=NULL;
  if(len < 48 || len>1024*1024)
    return ;
  /*@ assert 48 <= len <= 1024*1024; */
  if(len < le32(header->miniSectorCutoff))
  {
    if(le32(header->csectMiniFat)==0 || ministream_size == 0)
      return ;
    if(ministream_size > 1024*1024 || le32(header->csectMiniFat) > 2048)
      return ;
    /*@ assert 0 < le32(header->csectMiniFat) <= 2048; */
    {
      const unsigned int mini_fat_entries=(le32(header->csectMiniFat) << uSectorShift) / 4;
      uint32_t *minifat;
      unsigned char *ministream;
      if((minifat=OLE_load_MiniFAT(file, header, fat, fat_entries, offset))==NULL)
	return ;
      ministream=(unsigned char *)OLE_read_stream(file,
	  fat, fat_entries, uSectorShift,
	  ministream_block, ministream_size, offset);
      if(ministream != NULL)
      {
	summary=(unsigned char*)OLE_read_ministream(ministream,
	    minifat, mini_fat_entries, le16(header->uMiniSectorShift),
	    block, len, ministream_size);
	free(ministream);
      }
      free(minifat);
    }
  }
  else
    summary=(unsigned char *)OLE_read_stream(file,
	fat, fat_entries, uSectorShift,
	block, len, offset);
  if(summary!=NULL)
  {
    OLE_parse_summary_aux(summary, len, ext, title, file_time);
    free(summary);
  }
}

/*@
  @ requires \valid(file_recovery);
  @ requires valid_read_string((char*)file_recovery->filename);
  @*/
static void file_rename_doc(file_recovery_t *file_recovery)
{
  const char *ext=NULL;
  char *title=NULL;
  FILE *file;
  unsigned char buffer_header[512];
  uint32_t *fat;
  const struct OLE_HDR *header=(const struct OLE_HDR*)&buffer_header;
  time_t file_time=0;
  unsigned int fat_entries;
  unsigned int uSectorShift;
  unsigned int num_FAT_blocks;
  if(strstr(file_recovery->filename, ".sdd")!=NULL)
    ext="sdd";
  if((file=fopen(file_recovery->filename, "rb"))==NULL)
    return;
#ifdef DEBUG_OLE
  log_info("file_rename_doc(%s)\n", file_recovery->filename);
#endif
  /*reads first sector including OLE header */
  if(my_fseek(file, 0, SEEK_SET) < 0 ||
      fread(&buffer_header, sizeof(buffer_header), 1, file) != 1)
  {
    fclose(file);
    return ;
  }
#if defined(__FRAMAC__)
  Frama_C_make_unknown((char *)&buffer_header, sizeof(buffer_header));
#endif
  uSectorShift=le16(header->uSectorShift);
  num_FAT_blocks=le32(header->num_FAT_blocks);
  /* Sanity check */
  if( uSectorShift != 9 && uSectorShift != 12)
  {
    fclose(file);
    return ;
  }
  /*@ assert 9 == uSectorShift || 12 == uSectorShift; */
  if(le16(header->uMiniSectorShift) != 6)
  {
    fclose(file);
    return ;
  }
  /* Sanity check */
  if(num_FAT_blocks==0 ||
      le32(header->num_extra_FAT_blocks)>50)
  {
    fclose(file);
    return ;
  }
  /*@ assert num_FAT_blocks > 0; */
  /*@ assert 0 <= le32(header->num_extra_FAT_blocks) <= 50; */
  if(num_FAT_blocks > 109+le32(header->num_extra_FAT_blocks)*((1<<uSectorShift)/4-1))
  {
    fclose(file);
    return ;
  }
  if((fat=OLE_load_FAT(file, header, 0))==NULL)
  {
    fclose(file);
    return ;
  }
  fat_entries=(num_FAT_blocks==0 ? 109 : (num_FAT_blocks<<uSectorShift)/4);
  {
    unsigned int ministream_block=0;
    unsigned int ministream_size=0;
    unsigned int block;
    unsigned int i;
    /* FFFFFFFE = ENDOFCHAIN
     * Use a loop count i to avoid endless loop */
#ifdef DEBUG_OLE
    log_info("file_rename_doc root_start_block=%u, fat_entries=%u\n", le32(header->root_start_block), fat_entries);
#endif
    for(block=le32(header->root_start_block), i=0;
	block<fat_entries && block!=0xFFFFFFFE && i<fat_entries;
	block=le32(fat[block]), i++)
    {
      struct OLE_DIR *dir_entries;
#ifdef __FRAMAC__
      dir_entries=(struct OLE_DIR *)MALLOC(1<<12);
#else
      dir_entries=(struct OLE_DIR *)MALLOC(1<<uSectorShift);
#endif
      if(OLE_read_block(file, (unsigned char *)dir_entries, uSectorShift, block, 0)<0)
      {
	free(fat);
	free(dir_entries);
	fclose(file);
	free(title);
	return ;
      }
#ifdef DEBUG_OLE
      log_info("Root Directory block=%u (0x%x)\n", block, block);
#endif
      {
	unsigned int sid;
	int is_db=0;
	if(i==0)
	{
	  const struct OLE_DIR *dir_entry=dir_entries;
	  ministream_block=le32(dir_entry->start_block);
	  ministream_size=le32(dir_entry->size);
	}
	for(sid=0;
	    sid<(1<<uSectorShift)/sizeof(struct OLE_DIR);
	    sid++)
	{
	  const struct OLE_DIR *dir_entry=&dir_entries[sid];
	  if(dir_entry->type!=NO_ENTRY)
	  {
	    const char SummaryInformation[40]=
	    {
	      0x05, '\0', 'S', '\0', 'u', '\0', 'm', '\0',
	      'm', '\0', 'a', '\0', 'r', '\0', 'y', '\0',
	      'I', '\0', 'n', '\0', 'f', '\0', 'o', '\0',
	      'r', '\0', 'm', '\0', 'a', '\0', 't', '\0',
	      'i', '\0', 'o', '\0', 'n', '\0', '\0', '\0'
	    };
#ifdef DEBUG_OLE
	    unsigned int j;
	    for(j=0;j<64 && j<le16(dir_entry->namsiz) && dir_entry->name[j]!='\0';j+=2)
	    {
	      log_info("%c",dir_entry->name[j]);
	    }
	    log_info(" type %u", dir_entry->type);
	    log_info(" Flags=%s", (dir_entry->bflags==0?"Red":"Black"));
	    log_info(" sector %u (%u bytes)\n",
		(unsigned int)le32(dir_entry->start_block),
		(unsigned int)le32(dir_entry->size));
#endif
	    switch(le16(dir_entry->namsiz))
	    {
	      case 4:
		if(sid==1 && memcmp(&dir_entry->name, "1\0\0\0", 4)==0)
		  is_db=1;
		if(is_db==1 && sid==2 && memcmp(&dir_entry->name, "2\0\0\0", 4)==0)
		  is_db=2;
		break;
	      case 10:
		if(memcmp(dir_entry->name, ".\0Q\0D\0F\0\0\0",10)==0)
		  ext="qdf-backup";
		break;
	      case 12:
		/* 3ds max */
		if(memcmp(dir_entry->name, "S\0c\0e\0n\0e\0\0\0",12)==0)
		  ext="max";
		/* Licom AlphaCAM */
		else if(memcmp(dir_entry->name,"L\0i\0c\0o\0m\0\0\0",12)==0)
		  ext="amb";
		break;
	      case 16:
		if(sid==1 && memcmp(dir_entry->name, "d\0o\0c\0.\0d\0e\0t\0\0\0", 16)==0)
		  ext="psmodel";
		/* Windows Sticky Notes */
		else if(sid==1 && memcmp(dir_entry->name, "V\0e\0r\0s\0i\0o\0n\0\0\0", 16)==0)
		  ext="snt";
		else if(is_db==1 && sid==2 && memcmp(&dir_entry->name, "C\0a\0t\0a\0l\0o\0g\0\0\0", 16)==0)
		  is_db=2;
		break;
	      case 18:
		/* MS Excel
		 * Note: Microsoft Works Spreadsheet contains the same signature */
		if(ext==NULL &&
		    memcmp(dir_entry->name, "W\0o\0r\0k\0b\0o\0o\0k\0\0\0",18)==0)
		  ext="xls";
		/* Microsoft Works .wps */
		else if(memcmp(dir_entry->name,"C\0O\0N\0T\0E\0N\0T\0S\0\0\0",18)==0)
		  ext="wps";
		break;
	      case 20:
		/* Page Maker */
		if(memcmp(&dir_entry->name, "P\0a\0g\0e\0M\0a\0k\0e\0r\0\0\0", 20)==0)
		  ext="p65";
		break;
	      case 22:
		/* SigmaPlot .jnb */
		if(memcmp(dir_entry->name, "J\0N\0B\0V\0e\0r\0s\0i\0o\0n\0\0\0", 22)==0)
		  ext="jnb";
		/* Autodesk Inventor part ipt or iam file */
		if(memcmp(dir_entry->name, "R\0S\0e\0S\0t\0o\0r\0a\0g\0e\0\0\0", 22)==0)
		  ext="ipt";
		break;
	      case 24:
		/* HP Photosmart Photo Printing Album */
		if(memcmp(dir_entry->name,"I\0m\0a\0g\0e\0s\0S\0t\0o\0r\0e\0\0\0",24)==0)
		  ext="albm";
		/* Lotus Approach */
		else if(memcmp(dir_entry->name,"A\0p\0p\0r\0o\0a\0c\0h\0D\0o\0c\0\0\0",24)==0)
		  ext="apr";
		break;
	      case 28:
		/* Microsoft Works Spreadsheet or Chart */
		if(memcmp(dir_entry->name,"W\0k\0s\0S\0S\0W\0o\0r\0k\0B\0o\0o\0k\0\0\0",28)==0)
		  ext="xlr";
		/* Visio */
		else if(memcmp(dir_entry->name,"V\0i\0s\0i\0o\0D\0o\0c\0u\0m\0e\0n\0t\0\0\0",28)==0)
		  ext="vsd";
		/* SolidWorks */
		else if(memcmp(&dir_entry->name, "s\0w\0X\0m\0l\0C\0o\0n\0t\0e\0n\0t\0s\0\0\0", 28)==0)
		{
#ifdef DJGPP
		  ext="sld";
#else
		  ext="sldprt";
#endif
		}
		break;
	      case 32:
		if(memcmp(dir_entry->name, "m\0a\0n\0i\0f\0e\0s\0t\0.\0c\0a\0m\0x\0m\0l\0\0\0",32)==0)
		  ext="camrec";
	    /* Revit */
		else if(memcmp(dir_entry->name, "R\0e\0v\0i\0t\0P\0r\0e\0v\0i\0e\0w\0004\0.\0000\0\0", 32)==0)
		  ext="rvt";
		break;
	      case 34:
		if(memcmp(dir_entry->name, "S\0t\0a\0r\0C\0a\0l\0c\0D\0o\0c\0u\0m\0e\0n\0t\0\0\0",34)==0)
		  ext="sdc";
		break;
	      case 36:
		/* sda=StarDraw, sdd=StarImpress */
		if((ext==NULL || strcmp(ext,"sdd")!=0) &&
		    memcmp(dir_entry->name, "S\0t\0a\0r\0D\0r\0a\0w\0D\0o\0c\0u\0m\0e\0n\0t\0003\0\0\0", 36)==0)
		  ext="sda";
		else if(memcmp(dir_entry->name, "f\0i\0l\0e\0_\0C\0O\0M\0P\0A\0N\0Y\0_\0F\0I\0L\0E\0\0\0", 36)==0)
		    ext="qbb";
		break;
	      case 38:
		/* Quattro Pro spreadsheet */
		if(memcmp(dir_entry->name, "N\0a\0t\0i\0v\0e\0C\0o\0n\0t\0e\0n\0t\0_\0M\0A\0I\0N\0\0\0", 38)==0)
		  ext="qpw";
		else if(memcmp(dir_entry->name, "S\0t\0a\0r\0W\0r\0i\0t\0e\0r\0D\0o\0c\0u\0m\0e\0n\0t\0\0\0", 38)==0)
		  ext="sdw";
		break;
	      case 40:
		if(memcmp(dir_entry->name, SummaryInformation, 40)==0)
		{
		  OLE_parse_summary(file, fat, fat_entries, header,
		      ministream_block, ministream_size,
		      le32(dir_entry->start_block), le32(dir_entry->size),
		      &ext, &title, &file_time, 0);
		}
		else if(memcmp(dir_entry->name,"P\0o\0w\0e\0r\0P\0o\0i\0n\0t\0 \0D\0o\0c\0u\0m\0e\0n\0t\0\0\0", 40)==0)
		  ext="ppt";
		/* Outlook */
		else if(memcmp(dir_entry->name,"_\0_\0n\0a\0m\0e\0i\0d\0_\0v\0e\0r\0s\0i\0o\0n\0001\0.\0000\0\0\0",40)==0)
		  ext="msg";
		break;
	      case 46:
		if(memcmp(dir_entry->name,
		      "I\0S\0o\0l\0i\0d\0W\0o\0r\0k\0s\0I\0n\0f\0o\0r\0m\0a\0t\0i\0o\0n\0\0\0", 46)==0)
		{
#ifdef DJGPP
		  ext="sld";
#else
		  ext="sldprt";
#endif
		}
		break;
	      case 56:
		/* Wilcom ES Software */
		if(memcmp(dir_entry->name, WilcomDesignInformationDDD, 56)==0)
		  ext="emb";
		break;
	    }
	    if(sid==1 && le16(dir_entry->namsiz) >=6 &&
		memcmp(dir_entry->name, "D\0g\0n", 6)==0)
	      ext="dgn";
#ifdef DEBUG_OLE
	    if(ext!=NULL)
	      log_info("Found %s %u\n", ext, le16(dir_entry->namsiz));
#endif
	  }
	}
	if(ext==NULL && is_db==2)
	  ext="db";
      }
      free(dir_entries);
    }
  }
  free(fat);
  fclose(file);
  if(file_time!=0 && file_time!=(time_t)-1)
    set_date(file_recovery->filename, file_time, file_time);
  if(title!=NULL)
  {
    file_rename(file_recovery, (const unsigned char*)title, strlen(title), 0, ext, 1);
    free(title);
  }
  else
    file_rename(file_recovery, NULL, 0, 0, ext, 1);
}

/*@
  @ requires \valid(file_stat);
  @*/
static void register_header_check_doc(file_stat_t *file_stat)
{
  static const unsigned char doc_header[]= { 0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1};
  register_header_check(0, doc_header,sizeof(doc_header), &header_check_doc, file_stat);
}

#if defined(MAIN_doc)
#define BLOCKSIZE 65536u
int main()
{
  const char fn[] = "recup_dir.1/f0000000.doc";
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

  file_stats.file_hint=&file_hint_doc;
  file_stats.not_recovered=0;
  file_stats.recovered=0;
  register_header_check_doc(&file_stats);
  if(header_check_doc(buffer, BLOCKSIZE, 0u, &file_recovery, &file_recovery_new)!=1)
    return 0;
  /*@ assert file_recovery_new.file_size == 0;	*/
  /*@ assert file_recovery_new.file_check == &file_check_doc; */
  /*@ assert file_recovery_new.file_rename == &file_rename_doc; */
#ifdef __FRAMAC__
  file_recovery_new.file_size = 512*Frama_C_interval(1, 1000);
#endif
  /*@ assert valid_read_string((char *)&fn); */
  memcpy(file_recovery_new.filename, fn, sizeof(fn));
  /*@ assert valid_read_string((char *)&file_recovery_new.filename); */
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  file_recovery_new.file_stat=&file_stats;
  if(file_recovery_new.file_stat!=NULL)
  {
    file_recovery_t file_recovery_new2;
    /* Test when another file of the same is detected in the next block */
    file_recovery_new2.blocksize=BLOCKSIZE;
    file_recovery_new2.file_stat=NULL;
    file_recovery_new2.file_check=NULL;
    file_recovery_new2.location.start=BLOCKSIZE;
    file_recovery_new.handle=NULL;	/* In theory should be not null */
    header_check_doc(buffer, BLOCKSIZE, 0, &file_recovery_new, &file_recovery_new2);
    /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  }
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  {
    file_recovery_new.handle=fopen(fn, "rb");
    if(file_recovery_new.handle!=NULL)
    {
      file_check_doc(&file_recovery_new);
      fclose(file_recovery_new.handle);
    }
  }
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  file_rename_doc(&file_recovery_new);
  return 0;
}
#endif
