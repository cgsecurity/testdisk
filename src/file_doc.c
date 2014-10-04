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
#include "types.h"
#include "common.h"
#include "filegen.h"
#include "ole.h"
#include "log.h"
#include "memmem.h"
#include "setdate.h"

static void register_header_check_doc(file_stat_t *file_stat);
static void file_check_doc(file_recovery_t *file_recovery);
static int header_check_doc(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);
static void file_rename_doc(const char *old_filename);
static uint32_t *OLE_load_FAT(FILE *IN, const struct OLE_HDR *header);
static uint32_t *OLE_load_MiniFAT(FILE *IN, const struct OLE_HDR *header, const uint32_t *fat, const unsigned int fat_entries);

const file_hint_t file_hint_doc= {
  .extension="doc",
  .description="Microsoft Office Document (doc/xls/ppt/vsd/...), 3ds Max, MetaStock, Wilcom ES",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_doc
};

static const unsigned char doc_header[]= { 0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1};

static void register_header_check_doc(file_stat_t *file_stat)
{
  register_header_check(0, doc_header,sizeof(doc_header), &header_check_doc, file_stat);
}

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

static void file_check_doc(file_recovery_t *file_recovery)
{
  unsigned char buffer_header[512];
  uint64_t doc_file_size;
  uint32_t *fat;
  unsigned long int i;
  unsigned int freesect_count=0;  
  const struct OLE_HDR *header=(const struct OLE_HDR*)&buffer_header;
  const uint64_t doc_file_size_org=file_recovery->file_size;
  file_recovery->file_size=0;
  /*reads first sector including OLE header */
  if(
#ifdef HAVE_FSEEKO
      fseeko(file_recovery->handle, 0, SEEK_SET) < 0 ||
#else
      fseek(file_recovery->handle, 0, SEEK_SET) < 0 ||
#endif
      fread(&buffer_header, sizeof(buffer_header), 1, file_recovery->handle) != 1)
    return ;
#ifdef DEBUG_OLE
  log_info("file_check_doc %s\n", file_recovery->filename);
  log_trace("sector size          %u\n",1<<le16(header->uSectorShift));
  log_trace("num_FAT_blocks       %u\n",le32(header->num_FAT_blocks));
  log_trace("num_extra_FAT_blocks %u\n",le32(header->num_extra_FAT_blocks));
#endif
  /* Sanity check */
  if(le32(header->num_FAT_blocks)==0 ||
      le32(header->num_extra_FAT_blocks)>50 ||
      le32(header->num_FAT_blocks)>109+le32(header->num_extra_FAT_blocks)*((1<<le16(header->uSectorShift))-1))
    return ;
  if((fat=OLE_load_FAT(file_recovery->handle, header))==NULL)
  {
#ifdef DEBUG_OLE
    log_info("OLE_load_FAT failed\n");
#endif
    return ;
  }
  /* Search how many entries are not used at the end of the FAT */
  for(i=(le32(header->num_FAT_blocks)<<le16(header->uSectorShift))/4-1;
      i>0 && le32(fat[i])==0xFFFFFFFF;
      i--)
    freesect_count++;
  doc_file_size=((1+(le32(header->num_FAT_blocks)<<le16(header->uSectorShift))/4-freesect_count)<<le16(header->uSectorShift));
  if(doc_file_size > doc_file_size_org)
  {
#ifdef DEBUG_OLE
    log_info("doc_file_size=(1+(%u<<%u)/4-%u)<<%u\n",
	le32(header->num_FAT_blocks), le16(header->uSectorShift),
	freesect_count, le16(header->uSectorShift));
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
    const unsigned int fat_entries=(le32(header->num_FAT_blocks)==0 ?
	109:
	(le32(header->num_FAT_blocks)<<le16(header->uSectorShift))/4);
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
#ifdef HAVE_FSEEKO
      if(fseeko(file_recovery->handle, (1+block)<<le16(header->uSectorShift), SEEK_SET)<0)
#else
      if(fseek(file_recovery->handle, (1+block)<<le16(header->uSectorShift), SEEK_SET)<0)
#endif
      {
#ifdef DEBUG_OLE
	log_info("fseek failed\n");
#endif
	free(fat);
	return ;
      }
      dir_entries=(struct OLE_DIR *)MALLOC(1<<le16(header->uSectorShift));
      if(fread(dir_entries, (1<<le16(header->uSectorShift)), 1, file_recovery->handle)!=1)
      {
#ifdef DEBUG_OLE
	log_info("fread failed\n");
#endif
	free(dir_entries);
	free(fat);
	return ;
      }
      {
	unsigned int sid;
	struct OLE_DIR *dir_entry;
	for(sid=0, dir_entry=dir_entries;
	    sid<(1<<le16(header->uSectorShift))/sizeof(struct OLE_DIR) && dir_entry->type!=NO_ENTRY;
	    sid++,dir_entry++)
	{
	    if(le32(dir_entry->start_block) > 0 && le32(dir_entry->size) > 0 &&
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

static const char *ole_get_file_extension(const unsigned char *buffer, const unsigned int buffer_size)
{
  const struct OLE_HDR *header=(const struct OLE_HDR *)buffer;
  const uint32_t *fat;
  unsigned int fat_entries;
  unsigned int block;
  unsigned int i;
  if(buffer_size<512)
    return NULL;
  if(le32(header->num_FAT_blocks)==0)
  {
    fat=(const uint32_t *)(header+1);
    fat_entries=109;
  }
  else
  {
    const uint32_t *fati=(const uint32_t *)(header+1);
    const unsigned int fat_offset=(1+le32(fati[0])) << le16(header->uSectorShift);
    fat=(const uint32_t *)&buffer[fat_offset];
    fat_entries=(le32(header->num_FAT_blocks) << le16(header->uSectorShift))/4;
    if(fat_offset>buffer_size)
      fat_entries=0;
    else if(fat_offset+fat_entries>buffer_size)
      fat_entries=buffer_size-fat_offset;
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
    const unsigned int offset_root_dir=(1+block)<<le16(header->uSectorShift);
#ifdef DEBUG_OLE
    log_info("Root Directory block=%u (0x%x)\n", block, block);
#endif
    if(offset_root_dir>buffer_size-512)
      return NULL;
    {
      unsigned int sid;
      const struct OLE_DIR *dir_entry;
      const char *ext=NULL;
      int is_db=0;
      for(sid=0,dir_entry=(const struct OLE_DIR *)&buffer[offset_root_dir];
	  sid<512/sizeof(struct OLE_DIR) && dir_entry->type!=NO_ENTRY;
	  sid++,dir_entry++)
      {
#ifdef DEBUG_OLE
	unsigned int j;
	for(j=0;j<64 && j<le16(dir_entry->namsiz) && dir_entry->name[j]!='\0';j+=2)
	{
	  log_info("%c",dir_entry->name[j]);
	}
	for(;j<64;j+=2)
	  log_info(" ");
	log_info(" type %u", dir_entry->type);
	log_info(" Flags=%s", (dir_entry->bflags==0?"Red  ":"Black"));
	log_info(" sector %u (%u bytes)\n",
	    (unsigned int)le32(dir_entry->start_block),
	    (unsigned int)le32(dir_entry->size));
#endif
	if(sid==1 && memcmp(&dir_entry->name, "1\0\0\0", 4)==0)
	  is_db++;
	else if(sid==2 && (memcmp(&dir_entry->name, "2\0\0\0", 4)==0 ||
	      memcmp(&dir_entry->name, "C\0a\0t\0a\0l\0o\0g\0", 14)==0))
	  is_db++;
	switch(le16(dir_entry->namsiz))
	{
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
	    if(memcmp(dir_entry->name, "J\0N\0B\0V\0e\0r\0s\0i\0o\0n\0\0", 22)==0)
	      return "jnb";
	    break;
	  case 24:
	    /* HP Photosmart Photo Printing Album */
	    if(memcmp(dir_entry->name,"I\0m\0a\0g\0e\0s\0S\0t\0o\0r\0e\0\0\0",24)==0)
	      return "albm";
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

static int header_check_doc(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct OLE_HDR *header=(const struct OLE_HDR *)buffer;
  if(memcmp(buffer,doc_header,sizeof(doc_header))!=0)
    return 0;
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
      le32(header->num_FAT_blocks)>109+le32(header->num_extra_FAT_blocks)*((1<<le16(header->uSectorShift))-1))
    return 0;
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

static uint32_t *OLE_load_FAT(FILE *IN, const struct OLE_HDR *header)
{
  uint32_t *fat;
  uint32_t *dif;
  dif=(uint32_t*)MALLOC(109*4+(le32(header->num_extra_FAT_blocks)<<le16(header->uSectorShift)));
  memcpy(dif,(header+1),109*4);
  if(le32(header->num_extra_FAT_blocks)>0)
  { /* Load DIF*/
    unsigned long int i;
    unsigned long int block;
    unsigned char *data=(unsigned char*)&dif[109];
    for(i=0, block=le32(header->FAT_next_block);
	i<le32(header->num_extra_FAT_blocks) && block!=0xFFFFFFFF && block!=0xFFFFFFFE;
	i++, block=le32(dif[109+i*(((1<<le16(header->uSectorShift))/4)-1)]))
    {
#ifdef HAVE_FSEEKO
      if(fseeko(IN, (1+block)<<le16(header->uSectorShift), SEEK_SET) < 0)
#else
      if(fseek(IN, (1+block)<<le16(header->uSectorShift), SEEK_SET) < 0)
#endif
      {
	free(dif);
	return NULL;
      }
      if(fread(data, 1<<le16(header->uSectorShift), 1, IN)!=1)
      {
	free(dif);
	return NULL;
      }
      data+=(1<<le16(header->uSectorShift))-4;
    }
  }
  fat=(uint32_t*)MALLOC(le32(header->num_FAT_blocks)<<le16(header->uSectorShift));
  { /* Load FAT */
    unsigned long int j;
    unsigned char *data;
    for(j=0, data=(unsigned char*)fat;
	j<le32(header->num_FAT_blocks);
	j++, data+=(1<<le16(header->uSectorShift)))
    {
#ifdef HAVE_FSEEKO
      if(fseeko(IN, (1+le32(dif[j]))<<le16(header->uSectorShift), SEEK_SET)<0)
#else
      if(fseek(IN, (1+le32(dif[j]))<<le16(header->uSectorShift), SEEK_SET)<0)
#endif
      {
	free(dif);
	free(fat);
	return NULL;
      }
      if(fread(data, (1<<le16(header->uSectorShift)), 1, IN)!=1)
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

static void *OLE_read_stream(FILE *IN,
    const uint32_t *fat, const unsigned int fat_entries, const unsigned int uSectorShift,
    const unsigned int block_start, const unsigned int len)
{
  unsigned char *dataPt;
  unsigned int block;
  unsigned int size_read;
  dataPt=(unsigned char *)MALLOC((len+(1<<uSectorShift)-1) / (1<<uSectorShift) * (1<<uSectorShift));
  for(block=block_start, size_read=0;
      size_read < len;
      block=le32(fat[block]), size_read+=(1<<uSectorShift))
  {
    if(!(block < fat_entries))
    {
      free(dataPt);
      return NULL;
    }
#ifdef HAVE_FSEEKO
    if(fseeko(IN, (1+block)<<uSectorShift, SEEK_SET)<0)
#else
    if(fseek(IN, (1+block)<<uSectorShift, SEEK_SET)<0)
#endif
    {
      free(dataPt);
      return NULL;
    }
    if(fread(&dataPt[size_read], (1<<uSectorShift), 1, IN)!=1)
    {
      free(dataPt);
      return NULL;
    }
  }
  return dataPt;
}

static uint32_t *OLE_load_MiniFAT(FILE *IN, const struct OLE_HDR *header, const uint32_t *fat, const unsigned int fat_entries)
{
  unsigned char*minifat_pos;
  uint32_t *minifat;
  unsigned int block;
  unsigned int i;
  if(le32(header->csectMiniFat)==0)
    return NULL;
  minifat=(uint32_t*)MALLOC(le32(header->csectMiniFat) << le16(header->uSectorShift));
  minifat_pos=(unsigned char*)minifat;
  block=le32(header->MiniFat_block);
  for(i=0; i < le32(header->csectMiniFat) && block < fat_entries; i++)
  {
#ifdef HAVE_FSEEKO
    if(fseeko(IN, ((uint64_t)1+block) << le16(header->uSectorShift), SEEK_SET) < 0)
#else
    if(fseek(IN, ((uint64_t)1+block) << le16(header->uSectorShift), SEEK_SET) < 0)
#endif
    {
      free(minifat);
      return NULL;
    }
    if(fread(minifat_pos, 1 << le16(header->uSectorShift), 1, IN) != 1)
    {
      free(minifat);
      return NULL;
    }
    minifat_pos+=1 << le16(header->uSectorShift);
    block=le32(fat[block]);
  }
  return minifat;
}

static uint32_t get32u(const void *buffer, const unsigned int offset)
{
  const uint32_t *val=(const uint32_t *)((const unsigned char *)buffer+offset);
  return le32(*val);
}

static uint64_t get64u(const void *buffer, const unsigned int offset)
{
  const uint64_t *val=(const uint64_t *)((const unsigned char *)buffer+offset);
  return le64(*val);
}

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

static const char *software_uni2ext(const unsigned int count, const unsigned char *software)
{
  if(count>=17 && memcmp(software, "D\0e\0l\0c\0a\0m\0 \0P\0o\0w\0e\0r\0S\0H\0A\0P\0E\0", 34)==0)
    return "psmodel";
  return NULL;
}

static void OLE_parse_summary_aux(const unsigned char *dataPt, const unsigned int dirLen, const char **ext, char **title, time_t *file_time)
{
  unsigned int pos;
#ifdef DEBUG_OLE
  dump_log(dataPt, dirLen);
#endif
  if(dataPt[0]!=0xfe || dataPt[1]!=0xff)
    return ;
  pos=get32u(dataPt, 44);
  {
//    unsigned int size;
    unsigned int numEntries;
    unsigned int i;
    if(pos+8 > dirLen)
      return ;
    numEntries=get32u(dataPt, pos+4);
#ifdef DEBUG_OLE
    {
      unsigned int size=get32u(dataPt, pos);
      log_info("Property Info %u - %u at 0x%x\n", numEntries, size, pos);
    }
#endif
    if(pos + 8 + 8 * numEntries > dirLen)
      return ;
    for(i=0; i<numEntries; i++)
    {
      const unsigned int entry = pos + 8 + 8 * i;
      const unsigned int tag=get32u(dataPt, entry);
      const unsigned int offset=get32u(dataPt, entry + 4);
      const unsigned int valStart = pos + 4 + offset;
      unsigned int type;
      if(valStart >= dirLen)
	return ;
      type=get32u(dataPt, pos + offset);
#ifdef DEBUG_OLE
      log_info("entry 0x%x, tag 0x%x, offset 0x%x, valStart 0x%x, type 0x%x\n",
	  entry, tag, offset, valStart, type);
#endif
      /* tag: Software, type: VT_LPSTR */
      if(tag==0x12 && type==30)
      {
	unsigned int count=get32u(dataPt, valStart);
	if(valStart + 4 + count > dirLen)
	  return ;
#ifdef DEBUG_OLE
	{
	  unsigned int j;
	  log_info("Software ");
	  for(j=0; j<count; j++)
	  {
	    log_info("%c", dataPt[valStart + 4 + j]);
	  }
	  log_info("\n");
	}
#endif
	software2ext(ext, count, &dataPt[valStart + 4]);
      }
      /* tag: Software, type: VT_LPWSTR */
      if(tag==0x12 && type==31)
      {
	unsigned int count=get32u(dataPt, valStart);
	if(valStart + 4 + 2 * count > dirLen)
	  return ;
#ifdef DEBUG_OLE
	{
	  unsigned int j;
	  log_info("Software ");
	  for(j=0; j < 2 * count; j+=2)
	  {
	    log_info("%c", dataPt[valStart + 4 + j]);
	  }
	  log_info("\n");
	}
#endif
	*ext=software_uni2ext(count, &dataPt[valStart + 4]);
      }
      if(tag==0x02 && type==30 && *title==NULL)
      {
	const unsigned int count=get32u(dataPt, valStart);
	if(valStart + 4 + count > dirLen)
	  return ;
	*title=(char*)MALLOC(count+1);
	memcpy(*title, &dataPt[valStart + 4], count);
	(*title)[count]='\0';
#ifdef DEBUG_OLE
	log_info("Title %s\n", *title);
#endif
      }
      /* ModifyDate, type=VT_FILETIME */
      if(tag==0x0d && type==64)
      {
	uint64_t tmp=get64u(dataPt, valStart);
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

static void *OLE_read_ministream(unsigned char *ministream,
    const uint32_t *minifat, const unsigned int minifat_entries, const unsigned int uMiniSectorShift,
    const unsigned int miniblock_start, const unsigned int len, const unsigned int ministream_size)
{
  unsigned char *dataPt;
  unsigned int mblock;
  unsigned int size_read;
  dataPt=(unsigned char *)MALLOC((len+(1<<uMiniSectorShift)-1) / (1<<uMiniSectorShift) * (1<<uMiniSectorShift));
  for(mblock=miniblock_start, size_read=0;
      size_read < len;
      mblock=le32(minifat[mblock]), size_read+=(1<<uMiniSectorShift))
  {
    if(!(mblock < minifat_entries))
    {
      free(dataPt);
      return NULL;
    }
    if((mblock<<uMiniSectorShift)+ (1<<uMiniSectorShift) <= ministream_size)
      memcpy(&dataPt[size_read], &ministream[mblock<<uMiniSectorShift], (1<<uMiniSectorShift));
  }
  return dataPt;
}

static void OLE_parse_summary(FILE *file, const uint32_t *fat, const unsigned int fat_entries,
    const struct OLE_HDR *header, const unsigned int ministream_block, const unsigned int ministream_size,
    const unsigned int block, const unsigned int len, const char **ext, char **title, time_t *file_time)
{
  unsigned char *summary=NULL;
  if(len < 48 || len>1024*1024)
    return ;
  if(len < le32(header->miniSectorCutoff))
  {
    if(le32(header->csectMiniFat)!=0 && ministream_size > 0 && ministream_size < 1024*1024)
    {
      const unsigned int mini_fat_entries=(le32(header->csectMiniFat) << le16(header->uSectorShift)) / 4;
      uint32_t *minifat;
      unsigned char *ministream;
      if((minifat=OLE_load_MiniFAT(file, header, fat, fat_entries))==NULL)
	return ;
      ministream=(unsigned char *)OLE_read_stream(file,
	  fat, fat_entries, le16(header->uSectorShift),
	  ministream_block, ministream_size);
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
	fat, fat_entries, le16(header->uSectorShift),
	block, len);
  if(summary!=NULL)
  {
    OLE_parse_summary_aux(summary, len, ext, title, file_time);
    free(summary);
  }
}

static void file_rename_doc(const char *old_filename)
{
  const char *ext=NULL;
  char *title=NULL;
  FILE *file;
  unsigned char buffer_header[512];
  uint32_t *fat;
  const struct OLE_HDR *header=(const struct OLE_HDR*)&buffer_header;
  time_t file_time=0;
  unsigned int fat_entries;
  if(strstr(old_filename, ".sdd")!=NULL)
    ext="sdd";
  if((file=fopen(old_filename, "rb"))==NULL)
    return;
#ifdef DEBUG_OLE
  log_info("file_rename_doc(%s)\n", old_filename);
#endif
  /*reads first sector including OLE header */
  if(
#ifdef HAVE_FSEEKO
      fseeko(file, 0, SEEK_SET) < 0 ||
#else
      fseek(file, 0, SEEK_SET) < 0 ||
#endif
      fread(&buffer_header, sizeof(buffer_header), 1, file) != 1)
  {
    fclose(file);
    return ;
  }
  /* Sanity check */
  if(le32(header->num_FAT_blocks)==0 ||
      le32(header->num_extra_FAT_blocks)>50 ||
      le32(header->num_FAT_blocks)>109+le32(header->num_extra_FAT_blocks)*((1<<le16(header->uSectorShift))-1))
  {
    fclose(file);
    return ;
  }
  if((fat=OLE_load_FAT(file, header))==NULL)
  {
    fclose(file);
    return ;
  }
  fat_entries=(le32(header->num_FAT_blocks)==0 ?
      109:
      (le32(header->num_FAT_blocks)<<le16(header->uSectorShift))/4);
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
#ifdef HAVE_FSEEKO
      if(fseeko(file, (1+block)<<le16(header->uSectorShift), SEEK_SET)<0)
#else
      if(fseek(file, (1+block)<<le16(header->uSectorShift), SEEK_SET)<0)
#endif
      {
	free(fat);
	fclose(file);
	free(title);
	return ;
      }
      dir_entries=(struct OLE_DIR *)MALLOC(1<<le16(header->uSectorShift));
      if(fread(dir_entries, 1<<le16(header->uSectorShift), 1, file)!=1)
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
	const struct OLE_DIR *dir_entry=dir_entries;
	if(i==0)
	{
	  ministream_block=le32(dir_entry->start_block);
	  ministream_size=le32(dir_entry->size);
	}
	for(sid=0, dir_entry=dir_entries;
	    sid<(1<<le16(header->uSectorShift))/sizeof(struct OLE_DIR);
	    sid++,dir_entry++)
	{
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
		if(memcmp(dir_entry->name, "J\0N\0B\0V\0e\0r\0s\0i\0o\0n\0\0", 22)==0)
		  ext="jnb";
		break;
	      case 24:
		/* HP Photosmart Photo Printing Album */
		if(memcmp(dir_entry->name,"I\0m\0a\0g\0e\0s\0S\0t\0o\0r\0e\0\0\0",24)==0)
		  ext="albm";
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
		      &ext, &title, &file_time);
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
      }
      free(dir_entries);
    }
  }
  free(fat);
  fclose(file);
  if(file_time!=0 && file_time!=(time_t)-1)
    set_date(old_filename, file_time, file_time);
  if(title!=NULL)
  {
    file_rename(old_filename, (const unsigned char*)title, strlen(title), 0, ext, 1);
    free(title);
  }
  else
    file_rename(old_filename, NULL, 0, 0, ext, 1);
}
