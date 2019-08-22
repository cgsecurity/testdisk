/*

    File: partgptw.c

    Copyright (C) 2007-2009 Christophe GRENIER <grenier@cgsecurity.org>

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

#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include "types.h"
#if defined(HAVE_UUID_H)
#include <uuid.h>
#elif defined(HAVE_UUID_UUID_H)
#include <uuid/uuid.h>
#elif defined(HAVE_SYS_UUID_H)
#include <sys/uuid.h>
#endif
#include "common.h"
#include "fnctdsk.h"
#include "partgpt.h"
#include "log.h"
#include "guid_cmp.h"
#include "guid_cpy.h"
#include "unicode.h"
#include "crc.h"
extern const arch_fnct_t arch_i386;

static void efi_generate_uuid(efi_guid_t *ent_uuid);

static void swap_uuid_and_efi_guid(efi_guid_t *guid)
{
  guid->time_low            = le32(guid->time_low);
  guid->time_mid            = le16(guid->time_mid);
  guid->time_hi_and_version = le16(guid->time_hi_and_version);
}

static void efi_generate_uuid(efi_guid_t *ent_uuid)
{
#ifdef HAVE_UUID_GENERATE
  uuid_generate((unsigned char*)ent_uuid);
#elif defined HAVE_UUIDGEN
  uuidgen((struct uuid*)ent_uuid,1);
#elif defined HAVE_UUID_CREATE
  uuid_t *uuid;
  char *data_ptr=(char*)&ent_uuid;
  size_t data_len=sizeof(ent_uuid);;
  uuid_create(&uuid);
  uuid_make(uuid, UUID_MAKE_V1);
  uuid_export(uuid, UUID_FMT_BIN, (void **)&data_ptr, &data_len);
  uuid_destroy(uuid);
#else
#warning "You need a uuid_generate, uuidgen or uuid_create function"
#endif
  swap_uuid_and_efi_guid(ent_uuid);
}

static int find_gpt_entry(const uint64_t lba_start, const struct gpt_ent* gpt_entries_org)
{
  int i;
  if(gpt_entries_org==NULL)
    return -1;
  for(i=0; i<128; i++)
  {
    if(gpt_entries_org[i].ent_lba_start==le64(lba_start) &&
	guid_cmp(gpt_entries_org[i].ent_uuid, GPT_ENT_TYPE_UNUSED)!=0)
    {
      int j;
      for(j=0; j<i; j++)
	if(guid_cmp(gpt_entries_org[j].ent_uuid, gpt_entries_org[i].ent_uuid)==0)
	  return -1;
      return i;
    }
  }
  return -1;
}

static void partition_generate_gpt_entry(struct gpt_ent* gpt_entry, const partition_t *partition, const disk_t *disk_car, const struct gpt_ent* gpt_entries_org)
{
  const int entry=find_gpt_entry(partition->part_offset / disk_car->sector_size, gpt_entries_org);
  guid_cpy(&gpt_entry->ent_type, &partition->part_type_gpt);
  gpt_entry->ent_lba_start=le64(partition->part_offset / disk_car->sector_size);
  gpt_entry->ent_lba_end=le64((partition->part_offset + partition->part_size - 1) / disk_car->sector_size);
  str2UCSle((uint16_t *)&gpt_entry->ent_name, partition->partname, sizeof(gpt_entry->ent_name)/2);
  if(entry >= 0)
    guid_cpy(&gpt_entry->ent_uuid, &gpt_entries_org[entry].ent_uuid);
  else if(guid_cmp(partition->part_uuid, GPT_ENT_TYPE_UNUSED)!=0)
    guid_cpy(&gpt_entry->ent_uuid, &partition->part_uuid);
  else
    efi_generate_uuid(&gpt_entry->ent_uuid);
  gpt_entry->ent_attr=le64(0);  /* May need fixing */
}

static int write_part_gpt_i386(disk_t *disk_car, const list_part_t *list_part)
{
  /* The Protective MBR has the same format as a legacy MBR. */
  const list_part_t *element;
  list_part_t *list_part_i386=NULL;
  uint64_t efi_psize=disk_car->disk_size;
  partition_t *part_mac=NULL;
  partition_t *part_linux=NULL;
  partition_t *part_windows=NULL;
  for(element=list_part;element!=NULL;element=element->next)
  {
    if(part_mac==NULL && element->part->part_type_i386==P_HFS)
      part_mac=element->part;
    else if(part_linux==NULL && element->part->part_type_i386==P_LINUX)
      part_linux=element->part;
    else if(part_windows==NULL && element->part->part_type_i386==P_NTFS)
      part_windows=element->part;
  }
  if(part_mac!=NULL && (part_linux!=NULL || part_windows!=NULL))
  { /* For bootcamp, the layout should be
     * 1 EFI
     * 2 MacOS X
     * 3 Linux if any
     * 4 Windows
     */
    {
      int insert_error=0;
      partition_t *new_partition=partition_new(NULL);
      dup_partition_t(new_partition, part_mac);
      new_partition->arch=&arch_i386;
      new_partition->status=STATUS_PRIM;
      new_partition->order=2;
      list_part_i386=insert_new_partition(list_part_i386, new_partition, 0, &insert_error);
      if(insert_error>0)
        free(new_partition);
      else if(efi_psize > new_partition->part_offset)
        efi_psize=new_partition->part_offset;
    }
    if(part_linux!=NULL)
    {
      int insert_error=0;
      partition_t *new_partition=partition_new(NULL);
      dup_partition_t(new_partition, part_linux);
      new_partition->arch=&arch_i386;
      new_partition->status=STATUS_PRIM;
      new_partition->order=3;
      list_part_i386=insert_new_partition(list_part_i386, new_partition, 0, &insert_error);
      if(insert_error>0)
        free(new_partition);
      else if(efi_psize > new_partition->part_offset)
        efi_psize=new_partition->part_offset;
    }
    if(part_windows!=NULL)
    {
      int insert_error=0;
      partition_t *new_partition=partition_new(NULL);
      dup_partition_t(new_partition, part_windows);
      new_partition->arch=&arch_i386;
      new_partition->status=STATUS_PRIM;
      new_partition->order=4;
      list_part_i386=insert_new_partition(list_part_i386, new_partition, 0, &insert_error);
      if(insert_error>0)
        free(new_partition);
      else if(efi_psize > new_partition->part_offset)
        efi_psize=new_partition->part_offset;
    }
    {
      int insert_error=0;
      partition_t *new_partition=partition_new(&arch_i386);
      new_partition->status=STATUS_PRIM;
      new_partition->order=1;
      new_partition->part_type_i386=0xee;
      new_partition->part_offset=disk_car->sector_size;
      new_partition->part_size=efi_psize - new_partition->part_offset;
      list_part_i386=insert_new_partition(list_part_i386, new_partition, 0, &insert_error);
      if(insert_error>0)
        free(new_partition);
    }
  }
  else
  { /* The Protective MBR contains one partition entry of OS type 0xEE and
     * reserves the entire space used on the disk by the GPT partitions,
     * including all headers.
     */
    int insert_error=0;
    partition_t *new_partition=partition_new(&arch_i386);
    new_partition->status=STATUS_PRIM;
    new_partition->order=1;
    new_partition->part_type_i386=0xee;
    new_partition->part_offset=disk_car->sector_size;
    new_partition->part_size=disk_car->disk_size - new_partition->part_offset;
    list_part_i386=insert_new_partition(list_part_i386, new_partition, 0, &insert_error);
    if(insert_error>0)
      free(new_partition);
  }
  arch_i386.write_part(disk_car, list_part_i386, 0, 0);
  part_free_list(list_part_i386);
  return 0;
}

int write_part_gpt(disk_t *disk_car, const list_part_t *list_part, const int ro, const int verbose)
{
  struct gpt_hdr *gpt;
  struct gpt_ent* gpt_entries;
  struct gpt_hdr *gpt_org;
  struct gpt_ent* gpt_entries_org;
  const list_part_t *element;
  const unsigned int hdr_entries=128;
  const unsigned int gpt_entries_size=hdr_entries*sizeof(struct gpt_ent);
  if(ro>0)
    return 0;
  gpt_entries_org=(struct gpt_ent*)MALLOC(gpt_entries_size);
  disk_car->pread(disk_car, gpt_entries_org, gpt_entries_size, 2 * disk_car->sector_size);

  gpt_entries=(struct gpt_ent*)MALLOC(gpt_entries_size);
  for(element=list_part;element!=NULL;element=element->next)
  {
    if(element->part->order > 0 && element->part->order <= hdr_entries)
    {
      partition_generate_gpt_entry(&gpt_entries[element->part->order-1],
          element->part, disk_car, gpt_entries_org);
    }
  }
  gpt=(struct gpt_hdr*)MALLOC(disk_car->sector_size);
  gpt_org=(struct gpt_hdr*)MALLOC(disk_car->sector_size);
  if(disk_car->pread(disk_car, gpt_org, disk_car->sector_size, disk_car->sector_size) == disk_car->sector_size)
    guid_cpy(&gpt->hdr_guid, &gpt_org->hdr_guid);
  else
    efi_generate_uuid(&gpt->hdr_guid);

  memcpy(gpt->hdr_sig, GPT_HDR_SIG, 8);
  gpt->hdr_revision=le32(GPT_HDR_REVISION);
  gpt->hdr_size=le32(92);
  gpt->hdr_entries=le32(hdr_entries);
  gpt->hdr_entsz=le32(sizeof(struct gpt_ent));
  gpt->__reserved=le32(0);
  gpt->hdr_lba_start=le64(1 + gpt_entries_size/disk_car->sector_size + 1);
  gpt->hdr_lba_end=le64((disk_car->disk_size-1 - gpt_entries_size)/disk_car->sector_size - 1);
  gpt->hdr_crc_table=le32(get_crc32(gpt_entries, gpt_entries_size, 0xFFFFFFFF)^0xFFFFFFFF);
  gpt->hdr_lba_self=le64(1);
  gpt->hdr_lba_alt=le64((disk_car->disk_size-1)/disk_car->sector_size);
  gpt->hdr_lba_table=le64(1+1);
  gpt->hdr_crc_self=le32(0);
  gpt->hdr_crc_self=le32(get_crc32(gpt, le32(gpt->hdr_size), 0xFFFFFFFF)^0xFFFFFFFF);

#ifdef DEBUG_GPT
  dump2_log(gpt_entries, gpt_entries_org, gpt_entries_size);
  dump2_log(gpt, gpt_org, disk_car->sector_size);
#endif

  if((unsigned)disk_car->pwrite(disk_car, gpt_entries, gpt_entries_size, le64(gpt->hdr_lba_table) * disk_car->sector_size) != gpt_entries_size)
  {
    free(gpt_org);
    free(gpt_entries_org);
    free(gpt);
    free(gpt_entries);
    return 1;
  }
  if((unsigned)disk_car->pwrite(disk_car, gpt, disk_car->sector_size, le64(gpt->hdr_lba_self) * disk_car->sector_size) != disk_car->sector_size)
  {
    free(gpt_org);
    free(gpt_entries_org);
    free(gpt);
    free(gpt_entries);
    return 1;
  }
  gpt->hdr_lba_self=le64((disk_car->disk_size-1)/disk_car->sector_size);
  gpt->hdr_lba_alt=le64(1);
  gpt->hdr_lba_table=le64((disk_car->disk_size-1 - gpt_entries_size)/disk_car->sector_size);
  gpt->hdr_crc_self=le32(0);
  gpt->hdr_crc_self=le32(get_crc32(gpt, le32(gpt->hdr_size), 0xFFFFFFFF)^0xFFFFFFFF);
  if((unsigned)disk_car->pwrite(disk_car, gpt_entries, gpt_entries_size, le64(gpt->hdr_lba_table) * disk_car->sector_size) != gpt_entries_size)
  {
    free(gpt_org);
    free(gpt_entries_org);
    free(gpt);
    free(gpt_entries);
    return 1;
  }
  if((unsigned)disk_car->pwrite(disk_car, gpt, disk_car->sector_size, le64(gpt->hdr_lba_self) * disk_car->sector_size) != disk_car->sector_size)
  {
    free(gpt_org);
    free(gpt_entries_org);
    free(gpt);
    free(gpt_entries);
    return 1;
  }
  free(gpt_org);
  free(gpt_entries_org);
  free(gpt);
  free(gpt_entries);
  write_part_gpt_i386(disk_car, list_part);
  disk_car->sync(disk_car);
  return 0;
}
