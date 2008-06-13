/*

    File: file_doc.c

    Copyright (C) 1998-2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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

static void register_header_check_doc(file_stat_t *file_stat);
static void file_check_doc(file_recovery_t *file_recovery);
static int header_check_doc(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);
static uint64_t test_OLE(FILE *file);

const file_hint_t file_hint_doc= {
  .extension="doc",
  .description="Microsoft Office Document (doc/xls/ppt/vis/...), 3ds Max, MetaStock",
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

static void file_check_doc(file_recovery_t *file_recovery)
{
  uint64_t doc_file_size=test_OLE(file_recovery->handle);
  file_recovery->file_size=(doc_file_size>0?((doc_file_size<=(file_recovery->file_size))?doc_file_size:0):0);
#ifdef DEBUG_OLE
  log_trace("size found : %llu\n",(long long unsigned)doc_file_size);
  log_trace("==> size : %llu\n",(long long unsigned)file_recovery->file_size);
#endif
}

static int header_check_doc(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(buffer,doc_header,sizeof(doc_header))==0)
  {
    const struct OLE_HDR *header=(const struct OLE_HDR *)buffer;
    if(le16(header->reserved)!=0 || le32(header->reserved1)!=0 || le32(header->reserved2)!=0)
      return 0;
    if(le16(header->uMiniSectorShift)!=6 || le16(header->uSectorShift)!=9)
      return 0;
    /*
       num_FAT_blocks=109+num_extra_FAT_blocks*(512-1);
       maximum file size is 512+(num_FAT_blocks*128)*512, about 1.6GB
     */
    if(le32(header->num_FAT_blocks)==0 ||
	le32(header->num_extra_FAT_blocks)>50 ||
	le32(header->num_FAT_blocks)>109+le32(header->num_extra_FAT_blocks)*((1<<le16(header->uSectorShift))-1))
      return 0;
    /* TODO read the Root Directory */
    reset_file_recovery(file_recovery_new);
    file_recovery_new->file_check=&file_check_doc;
    if(td_memmem(buffer,buffer_size,"S\0c\0e\0n\0e\0",10)!=NULL)
    {
      file_recovery_new->extension="max";
    }
    else if(td_memmem(buffer,buffer_size,"WordDocument",12)!=NULL)
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
    else if(td_memmem(buffer,buffer_size,"W\0k\0s\0S\0S\0W\0o\0r\0k\0B\0o\0o\0k\0",26)!=NULL)
    {
      file_recovery_new->extension="xlr";
    }
    else if(td_memmem(buffer,buffer_size,"I\0m\0a\0g\0e\0s\0S\0t\0o\0r\0e\0",22)!=NULL)
    { /* HP Photosmart Photo Printing Album */
      file_recovery_new->extension="albm";
    }
    else if(td_memmem(buffer,buffer_size,"Worksheet",9)!=NULL ||
	td_memmem(buffer,buffer_size,"Book",4)!=NULL || 
	td_memmem(buffer,buffer_size,"Workbook",8)!=NULL || 
	td_memmem(buffer,buffer_size,"W\0o\0r\0k\0b\0o\0o\0k\0",16)!=NULL || 
	td_memmem(buffer,buffer_size,"Calc",4)!=NULL)
    {
      file_recovery_new->extension="xls";
    }
    else if(td_memmem(buffer,buffer_size,"Power",5)!=NULL ||
        td_memmem(buffer,buffer_size,"P\0o\0w\0e\0r\0",10)!=NULL)
    {
      file_recovery_new->extension="ppt";
    }
    else if(td_memmem(buffer,buffer_size,"AccessObjSiteData",17)!=NULL)
    {
      file_recovery_new->extension="mdb";
    }
    else if(td_memmem(buffer,buffer_size,"Visio",5)!=NULL)
    {
      file_recovery_new->extension="vis";
    }
    else if(td_memmem(buffer,buffer_size,"Sfx",3)!=NULL)
    {
      file_recovery_new->extension="sdw";
    }
    else if(td_memmem(buffer,buffer_size,"CPicPage",8)!=NULL)
    {	/* Flash */
      file_recovery_new->extension="fla";
    }
    else if(td_memmem(buffer,buffer_size,"Microsoft Publisher",19)!=NULL)
    {
      file_recovery_new->extension="pub";
    }
    else if(td_memmem(buffer, buffer_size, "Microsoft Works Database", 24)!=NULL
	|| td_memmem( buffer, buffer_size, "MSWorksDBDoc", 12)!=NULL)
    { /* Microsoft Works .wdb */
      file_recovery_new->extension="wdb";
    }
    else if(td_memmem(buffer,buffer_size,"C\0O\0N\0T\0E\0N\0T\0S\0",16)!=NULL)
    { /* Microsoft Works .wps */
      file_recovery_new->extension="wps";
    }
    else if(td_memmem(buffer,buffer_size,"MetaStock",9)!=NULL)
    {
      file_recovery_new->extension="mws";
    }
    else if(td_memmem(buffer,buffer_size,"_\0_\0n\0a\0m\0e\0i\0d\0_\0v\0e\0r\0s\0i\0o\0n\0001\0.\0000\0",38)!=NULL)
    { /* Outlook */
      file_recovery_new->extension="msg";
    }
    else if(td_memmem(buffer,buffer_size,"Publisher",9)!=NULL)
    { /* Publisher */
      file_recovery_new->extension="pub";
    }
    else if(td_memmem(buffer,buffer_size,"L\0i\0c\0o\0m\0",10)!=NULL)
    { /* Licom AlphaCAM */
      file_recovery_new->extension="amb";
    }
    else
      file_recovery_new->extension=file_hint_doc.extension;
    return 1;
  }
  return 0;
}

static uint64_t test_OLE(FILE *IN)
{
  unsigned char buffer_header[512];
  uint64_t totalsize;
  uint32_t *dif;
  uint32_t *fat;
  unsigned int freesect_count=0;  
  struct OLE_HDR *header=(struct OLE_HDR*)&buffer_header;
  if(!IN)
    return 0;
  fseek(IN,0,SEEK_SET);
  if(fread(&buffer_header,sizeof(buffer_header),1,IN)!=1)	/*reads first sector including OLE header */
    return 0;
  /*
  log_trace("num_FAT_blocks       %u\n",le32(header->num_FAT_blocks));
  log_trace("num_extra_FAT_blocks %u\n",le32(header->num_extra_FAT_blocks));
  */
  /* Sanity check */
  if(le32(header->num_FAT_blocks)==0 ||
      le32(header->num_extra_FAT_blocks)>50 ||
      le32(header->num_FAT_blocks)>109+le32(header->num_extra_FAT_blocks)*((1<<le16(header->uSectorShift))-1))
    return 0;
  dif=(uint32_t*)MALLOC(109*4+(le32(header->num_extra_FAT_blocks)<<le16(header->uSectorShift)));
  memcpy(dif,(header+1),109*4);
  if(le32(header->num_extra_FAT_blocks)>0)
  { /* Load DIF*/
    uint32_t *dif_pos=dif+109;
    unsigned long int i;
    unsigned long int block=le32(header->FAT_next_block);
    for(i=0;i<le32(header->num_extra_FAT_blocks) && block!=0xFFFFFFFF && block!=0xFFFFFFFE;i++)
    {
//      log_trace("pointeur:0x%x\n",block);
      if(fseek(IN,512+(block<<le16(header->uSectorShift)),SEEK_SET)<0)
      {
	free(dif);
	return 0;
      }
      if(fread(dif_pos, (i<le32(header->num_extra_FAT_blocks)?128:(le32(header->num_FAT_blocks)-109)%127),4,IN)!=4)
      {
	free(dif);
	return 0;
      }
      dif_pos+=(((1<<le16(header->uSectorShift))/4)-1);
      block=le32(dif[109+i*(((1<<le16(header->uSectorShift))/4)-1)+127]);
    }
  }
  fat=(uint32_t*)MALLOC(le32(header->num_FAT_blocks)<<le16(header->uSectorShift));
  { /* Load FAT */
    unsigned long int j;
    for(j=0;j<le32(header->num_FAT_blocks);j++)
    {
      if(fseek(IN,512+(le32(dif[j])<<le16(header->uSectorShift)),SEEK_SET)<0)
      {
	free(dif);
	free(fat);
	return 0;
      }
      if(fread(fat+((j<<le16(header->uSectorShift))/4),(1<<le16(header->uSectorShift)),1,IN)!=1)
      {
	free(dif);
	free(fat);
	return 0;
      }
    }
  }
  { /* Search how many entries are not used at the end of the FAT */
    unsigned long int i;
    for(i=(le32(header->num_FAT_blocks)<<le16(header->uSectorShift))/4-1;
	i>((le32(header->num_FAT_blocks)-1)<<le16(header->uSectorShift))/4 && le32(fat[i])==0xFFFFFFFF; i--)
      freesect_count++;
  }
  totalsize=512+((le32(header->num_FAT_blocks)*128-freesect_count)<<le16(header->uSectorShift));
  free(dif);
  free(fat);
  return totalsize;
}
