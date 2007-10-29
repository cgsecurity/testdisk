/*

    File: partgpt.c

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


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
 
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <ctype.h>      /* tolower */
#include "types.h"
#ifdef HAVE_UUID_UUID_H
#include <uuid/uuid.h>
#elif defined(HAVE_SYS_UUID_H)
#include <sys/uuid.h>
#endif
#include "common.h"
#include "testdisk.h"
#include "fnctdsk.h"
#include "lang.h"
#include "intrf.h"
#include "intrfn.h"
#include "chgtype.h"
#include "partgpt.h"
#include "savehdr.h"
#include "cramfs.h"
#include "ext2.h"
#include "fat.h"
#include "hfs.h"
#include "hfsp.h"
#include "jfs_superblock.h"
#include "jfs.h"
#include "ntfs.h"
#include "rfs.h"
#include "xfs.h"
#include "log.h"
#include "guid_cmp.h"
#include "guid_cpy.h"
#include "unicode.h"
#include "crc.h"
/* #include "partnone.h" */
extern const arch_fnct_t arch_i386;

static int check_part_gpt(disk_t *disk_car, const int verbose,partition_t *partition,const int saveheader);
static list_part_t *read_part_gpt(disk_t *disk_car, const int verbose, const int saveheader);
static int write_part_gpt(disk_t *disk_car, const list_part_t *list_part, const int ro , const int verbose, const int align);
static list_part_t *init_part_order_gpt(const disk_t *disk_car, list_part_t *list_part);
static list_part_t *add_partition_gpt(disk_t *disk_car,list_part_t *list_part, const int verbose, char **current_cmd);
static void set_next_status_gpt(const disk_t *disk_car, partition_t *partition);
static int test_structure_gpt(list_part_t *list_part);
static int is_part_known_gpt(const partition_t *partition);
static void init_structure_gpt(const disk_t *disk_car,list_part_t *list_part, const int verbose);
static const char *get_partition_typename_gpt(const partition_t *partition);
static const char *get_gpt_typename(const efi_guid_t part_type_gpt);
#if 0
static int set_part_type_gpt(partition_t *partition, efi_guid_t part_type_gpt);
static efi_guid_t get_part_type_gpt(const partition_t *partition);
#endif

struct systypes_gtp {
  const efi_guid_t part_type;
  const char *name;
};

static const struct systypes_gtp gpt_sys_types[] = {
  { GPT_ENT_TYPE_EFI, 			"EFI System"		},
  { GPT_ENT_TYPE_MBR,			"MBR"			},
  { GPT_ENT_TYPE_FREEBSD,		"FreeBSD"		},
  { GPT_ENT_TYPE_FREEBSD_SWAP,		"FreeBSD Swap"		},
  { GPT_ENT_TYPE_FREEBSD_UFS,		"FreeBSD UFS"		},
  { GPT_ENT_TYPE_FREEBSD_VINUM,		"FreeBSD Vinum"		},
//  { GPT_ENT_TYPE_FREEBSD_UFS2,		"FreeBSD UFS2"		},
  { GPT_ENT_TYPE_MS_RESERVED,		"MS Reserved"		},
  { GPT_ENT_TYPE_MS_BASIC_DATA,		"MS Data"		},
  { GPT_ENT_TYPE_MS_LDM_METADATA,	"MS LDM MetaData"	},
  { GPT_ENT_TYPE_MS_LDM_DATA,		"MS LDM Data"		},
//  { GPT_ENT_TYPE_LINUX_DATA
  { GPT_ENT_TYPE_LINUX_RAID,		"Linux Raid"		},
  { GPT_ENT_TYPE_LINUX_SWAP,		"Linux Swap"		},
  { GPT_ENT_TYPE_LINUX_LVM,		"Linux LVM"		},
  { GPT_ENT_TYPE_LINUX_RESERVED,	"Linux Reserved"	},
  { GPT_ENT_TYPE_HPUX_DATA,		"HPUX Data"		},
  { GPT_ENT_TYPE_HPUX_SERVICE,		"HPUX Service"		},
  { GPT_ENT_TYPE_MAC_HFS,		"Mac HFS"		},
  { GPT_ENT_TYPE_MAC_UFS,		"Mac UFS"		},
  { GPT_ENT_TYPE_MAC_RAID,		"Mac Raid"		},
  { GPT_ENT_TYPE_MAC_RAID_OFFLINE,	"Mac Raid (Offline)"	},
  { GPT_ENT_TYPE_MAC_BOOT,		"Mac Boot"		},
  { GPT_ENT_TYPE_MAC_LABEL,		"Mac Label"		},
  { GPT_ENT_TYPE_MAC_TV_RECOVERY,	"Mac TV Recovery"	},
  { GPT_ENT_TYPE_SOLARIS_BOOT,		"Solaris /boot"		},
  { GPT_ENT_TYPE_SOLARIS_ROOT,		"Solaris /"		},
  { GPT_ENT_TYPE_SOLARIS_SWAP,		"Solaris Swap"		},
  { GPT_ENT_TYPE_SOLARIS_BACKUP,	"Solaris Backup"	},
  { GPT_ENT_TYPE_SOLARIS_USR,		"Solaris /usr"		},
  { GPT_ENT_TYPE_SOLARIS_VAR,		"Solaris /var"		},
  { GPT_ENT_TYPE_SOLARIS_HOME,		"Solaris /home"		},
  { GPT_ENT_TYPE_SOLARIS_EFI_ALTSCTR,	"Solaris EFI Alt."	},
  { GPT_ENT_TYPE_SOLARIS_RESERVED1,	"Solaris Reserved1"	},
  { GPT_ENT_TYPE_SOLARIS_RESERVED2,	"Solaris Reserved2"	},
  { GPT_ENT_TYPE_SOLARIS_RESERVED3,	"Solaris Reserved3"	},
  { GPT_ENT_TYPE_SOLARIS_RESERVED4,	"Solaris Reserved4"	},
  { GPT_ENT_TYPE_SOLARIS_RESERVED5,	"Solaris Reserved5"	},
  { GPT_ENT_TYPE_UNUSED,  NULL }
 };

arch_fnct_t arch_gpt=
{
  .part_name="EFI GPT",
  .part_name_option="partition_gpt",
  .msg_part_type="                P=Primary  D=Deleted",
  .read_part=read_part_gpt,
  .write_part=write_part_gpt,
  .init_part_order=init_part_order_gpt,
  .get_geometry_from_mbr=NULL,
  .check_part=check_part_gpt,
  .write_MBR_code=NULL,
  .add_partition=add_partition_gpt,
  .set_prev_status=set_next_status_gpt,
  .set_next_status=set_next_status_gpt,
  .test_structure=test_structure_gpt,
  .set_part_type=NULL,
//  .set_part_type=set_part_type_none,
  .is_part_known=is_part_known_gpt,
  .init_structure=init_structure_gpt,
  .erase_list_part=NULL,
  .get_partition_typename=get_partition_typename_gpt,
//  .get_part_type=get_part_type_gpt
//  .get_part_type=get_part_type_none
  .get_part_type=NULL
};

static void swap_uuid_and_efi_guid(efi_guid_t *guid)
{
  guid->time_low            = le32(guid->time_low);
  guid->time_mid            = le16(guid->time_mid);
  guid->time_hi_and_version = le16(guid->time_hi_and_version);
}

list_part_t *read_part_gpt(disk_t *disk_car, const int verbose, const int saveheader)
{
  struct gpt_hdr *gpt;
  struct gpt_ent* gpt_entries;
  list_part_t *new_list_part=NULL;
  unsigned int i;
  uint32_t gpt_entries_size;
  uint64_t gpt_entries_offset;

  gpt=(struct gpt_hdr*)MALLOC(disk_car->sector_size);
  aff_buffer(BUFFER_RESET,"Q");
  if(disk_car->read(disk_car, disk_car->sector_size, gpt, disk_car->sector_size)!=0)
  {
    free(gpt);
    return NULL;
  }
  if(memcmp(gpt->hdr_sig, GPT_HDR_SIG, 8)!=0)
  {
    aff_buffer(BUFFER_ADD,"Bad GPT partition, invalid signature.\n");
    free(gpt);
    return NULL;
  }
  log_info("hdr_size=%llu\n", (long long unsigned)le32(gpt->hdr_size));
  log_info("hdr_lba_self=%llu\n", (long long unsigned)le64(gpt->hdr_lba_self));
  log_info("hdr_lba_alt=%llu (expected %llu)\n",
      (long long unsigned)le64(gpt->hdr_lba_alt),
      (long long unsigned)((disk_car->disk_size-1)/disk_car->sector_size));
  log_info("hdr_lba_start=%llu\n", (long long unsigned)le64(gpt->hdr_lba_start));
  log_info("hdr_lba_end=%llu\n", (long long unsigned)le64(gpt->hdr_lba_end));
  log_info("hdr_lba_table=%llu\n",
      (long long unsigned)le64(gpt->hdr_lba_table));
  log_info("hdr_entries=%llu\n", (long long unsigned)le32(gpt->hdr_entries));
  log_info("hdr_entsz=%llu\n", (long long unsigned)le32(gpt->hdr_entsz));
  /* Check header size */
  if(le32(gpt->hdr_size)<92 || le32(gpt->hdr_size) > disk_car->sector_size)
  {
    aff_buffer(BUFFER_ADD,"GPT: invalid header size.\n");
    free(gpt);
    return NULL;
  }
  { /* CRC check */
    uint32_t crc;
    uint32_t origcrc;
    origcrc=le32(gpt->hdr_crc_self);
    gpt->hdr_crc_self=le32(0);
    crc=get_crc32(gpt, le32(gpt->hdr_size), 0xFFFFFFFF)^0xFFFFFFFF;
    if(crc!=origcrc)
    {
      aff_buffer(BUFFER_ADD,"Bad GPT partition, invalid header checksum.\n");
      free(gpt);
      return NULL;
    }
    gpt->hdr_crc_self=le32(origcrc);
  }
  if(le64(gpt->hdr_lba_self)!=1)
  {
    aff_buffer(BUFFER_ADD,"Bad GPT partition, invalid LBA self location.\n");
    free(gpt);
    return NULL;
  }
  if(le64(gpt->hdr_lba_start) >= le64(gpt->hdr_lba_end))
  {
    aff_buffer(BUFFER_ADD,"Bad GPT partition, invalid LBA start/end location.\n");
    free(gpt);
    return NULL;
  }
  if(le32(gpt->hdr_revision)!=GPT_HDR_REVISION)
  {
    aff_buffer(BUFFER_ADD,"GPT: Warning - not revision 1.0\n");
  }
  if(le32(gpt->__reserved)!=0)
  {
    aff_buffer(BUFFER_ADD,"GPT: Warning - __reserved!=0\n");
  }
  if(le32(gpt->hdr_entries)==0 || le32(gpt->hdr_entries)>4096)
  {
    aff_buffer(BUFFER_ADD,"GPT: invalid number (%u) of partition entries.\n",
        (unsigned int)le32(gpt->hdr_entries));
    free(gpt);
    return NULL;
  }
  /* le32(gpt->hdr_entsz)==128 */
  if(le32(gpt->hdr_entsz)%8!=0 || le32(gpt->hdr_entsz)<128 || le32(gpt->hdr_entsz)>4096)
  {
    aff_buffer(BUFFER_ADD,"GPT: invalid partition entry size.\n");
    free(gpt);
    return NULL;
  }

  gpt_entries_size=le32(gpt->hdr_entries) * le32(gpt->hdr_entsz);
  if(gpt_entries_size<16384)
  {
    aff_buffer(BUFFER_ADD,"GPT: A minimum of 16,384 bytes of space must be reserved for the GUID Partition Entry array.\n");
    free(gpt);
    return NULL;
  }
  gpt_entries_offset=(uint64_t)le64(gpt->hdr_lba_table) * disk_car->sector_size;
  if((uint64_t) le64(gpt->hdr_lba_self) + le32(gpt->hdr_size) - 1 >= gpt_entries_offset ||
      gpt_entries_offset >= le64(gpt->hdr_lba_start) * disk_car->sector_size)
  {
    aff_buffer(BUFFER_ADD, "GPT: The primary GUID Partition Entry array must be located after the primary GUID Partition Table Header and end before the FirstUsableLBA.\n");
    free(gpt);
    return NULL;
  }

  gpt_entries=(struct gpt_ent*)MALLOC(gpt_entries_size);
  if(disk_car->read(disk_car, gpt_entries_size, gpt_entries, gpt_entries_offset)!=0)
  {
    free(gpt_entries);
    free(gpt);
    return new_list_part;
  }
  { /* CRC check */
    uint32_t crc;
    crc=get_crc32(gpt_entries, gpt_entries_size, 0xFFFFFFFF)^0xFFFFFFFF;
    if(crc!=le32(gpt->hdr_crc_table))
    {
      aff_buffer(BUFFER_ADD,"Bad GPT partition entries, invalid checksum.\n");
      free(gpt_entries);
      free(gpt);
      return NULL;
    }
  }
  for(i=0;i<le32(gpt->hdr_entries);i++)
  {
    const struct gpt_ent* gpt_entry;
    gpt_entry=(const struct gpt_ent*)((const char*)gpt_entries + (unsigned long)i*le32(gpt->hdr_entsz));
    if(guid_cmp(gpt_entry->ent_type, GPT_ENT_TYPE_UNUSED)!=0 &&
        le64(gpt_entry->ent_lba_start) < le64(gpt_entry->ent_lba_end))
    {
      int insert_error=0;
      partition_t *new_partition=partition_new(&arch_gpt);
      new_partition->order=i+1;
      guid_cpy(&new_partition->part_uuid, &gpt_entry->ent_uuid);
      guid_cpy(&new_partition->part_type_gpt, &gpt_entry->ent_type);
      new_partition->part_offset=(uint64_t)le64(gpt_entry->ent_lba_start)*disk_car->sector_size;
      new_partition->part_size=(uint64_t)(le64(gpt_entry->ent_lba_end) -
          le64(gpt_entry->ent_lba_start)+1) * disk_car->sector_size;
      new_partition->status=STATUS_PRIM;
      UCSle2str(new_partition->partname, (const uint16_t *)&gpt_entry->ent_name, sizeof(gpt_entry->ent_name)/2);
      new_partition->arch->check_part(disk_car,verbose,new_partition,saveheader);
      /* log_debug("%u ent_attr %08llx\n", new_partition->order, (long long unsigned)le64(gpt_entry->ent_attr)); */
      aff_part_buffer(AFF_PART_ORDER,disk_car,new_partition);
      new_list_part=insert_new_partition(new_list_part, new_partition, 0, &insert_error);
      if(insert_error>0)
        free(new_partition);
    }
  }
  /* TODO: The backup GUID Partition Entry array must be
     located after the LastUsableLBA and end before the backup GUID Partition Table Header.
   */
  free(gpt_entries);
  free(gpt);
  return new_list_part;
}

static void partition_generate_gpt_entry(struct gpt_ent* gpt_entry, const partition_t *partition, const disk_t *disk_car)
{
  guid_cpy(&gpt_entry->ent_type, &partition->part_type_gpt);
  gpt_entry->ent_lba_start=le64(partition->part_offset / disk_car->sector_size);
  gpt_entry->ent_lba_end=le64((partition->part_offset + partition->part_size - 1) / disk_car->sector_size);
  str2UCSle((uint16_t *)&gpt_entry->ent_name, partition->partname, sizeof(gpt_entry->ent_name)/2);
  if(guid_cmp(partition->part_uuid, GPT_ENT_TYPE_UNUSED)!=0)
    guid_cpy(&gpt_entry->ent_uuid, &partition->part_uuid);
  else
  {
#ifdef HAVE_UUID_GENERATE
    uuid_generate((unsigned char*)(&gpt_entry->ent_uuid));
#else
    uuidgen((struct uuid*)(&gpt_entry->ent_uuid),1);
#endif
    swap_uuid_and_efi_guid((efi_guid_t *)(&gpt_entry->ent_uuid));
  }
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
  arch_i386.write_part(disk_car, list_part_i386, 0, 0, 0);
  part_free_list(list_part_i386);
  return 0;
}

static int write_part_gpt(disk_t *disk_car, const list_part_t *list_part, const int ro, const int verbose, const int align)
{
  struct gpt_hdr *gpt;
  struct gpt_ent* gpt_entries;
  const list_part_t *element;
  const unsigned int hdr_entries=128;
  const unsigned int gpt_entries_size=hdr_entries*sizeof(struct gpt_ent);
  if(ro>0)
    return 0;
  gpt_entries=(struct gpt_ent*)MALLOC(gpt_entries_size);
  for(element=list_part;element!=NULL;element=element->next)
  {
    if(element->part->order > 0 && element->part->order <= hdr_entries)
    {
      partition_generate_gpt_entry(&gpt_entries[element->part->order-1],
          element->part, disk_car);
    }
  }
  gpt=(struct gpt_hdr*)MALLOC(disk_car->sector_size);
  memcpy(gpt->hdr_sig, GPT_HDR_SIG, 8);
  gpt->hdr_revision=le32(GPT_HDR_REVISION);
  gpt->hdr_size=le32(92);
  gpt->hdr_entries=le32(hdr_entries);
  gpt->hdr_entsz=le32(sizeof(struct gpt_ent));
  gpt->hdr_crc_self=le32(0);
  gpt->__reserved=le32(0);
  gpt->hdr_lba_start=le64(1 + gpt_entries_size/disk_car->sector_size + 1);
  gpt->hdr_lba_end=le64((disk_car->disk_size-1 - gpt_entries_size)/disk_car->sector_size - 1);
#ifdef HAVE_UUID_GENERATE
    uuid_generate((unsigned char*)(&gpt->hdr_guid));
#else
    uuidgen((struct uuid*)(&gpt->hdr_guid),1);
#endif
  swap_uuid_and_efi_guid((efi_guid_t *)(&gpt->hdr_guid));
  gpt->hdr_crc_table=le32(get_crc32(gpt_entries, gpt_entries_size, 0xFFFFFFFF)^0xFFFFFFFF);
  gpt->hdr_lba_self=le64(1);
  gpt->hdr_lba_alt=le64((disk_car->disk_size-1)/disk_car->sector_size);
  gpt->hdr_lba_table=le64(1+1);
  gpt->hdr_crc_self=le32(get_crc32(gpt, le32(gpt->hdr_size), 0xFFFFFFFF)^0xFFFFFFFF);
  if(disk_car->write(disk_car, gpt_entries_size, gpt_entries, le64(gpt->hdr_lba_table) * disk_car->sector_size))
  {
    free(gpt);
    free(gpt_entries);
    return 1;
  }
  if(disk_car->write(disk_car, disk_car->sector_size, gpt, le64(gpt->hdr_lba_self) * disk_car->sector_size))
  {
    free(gpt);
    free(gpt_entries);
    return 1;
  }
  gpt->hdr_lba_self=le64((disk_car->disk_size-1)/disk_car->sector_size);
  gpt->hdr_lba_alt=le64(1);
  gpt->hdr_lba_table=le64((disk_car->disk_size-1 - gpt_entries_size)/disk_car->sector_size);
  gpt->hdr_crc_self=le32(get_crc32(gpt, le32(gpt->hdr_size), 0xFFFFFFFF)^0xFFFFFFFF);
  if(disk_car->write(disk_car, gpt_entries_size, gpt_entries, le64(gpt->hdr_lba_table) * disk_car->sector_size))
  {
    free(gpt);
    free(gpt_entries);
    return 1;
  }
  if(disk_car->write(disk_car, disk_car->sector_size, gpt, le64(gpt->hdr_lba_self) * disk_car->sector_size))
  {
    free(gpt);
    free(gpt_entries);
    return 1;
  }
  free(gpt);
  free(gpt_entries);
  write_part_gpt_i386(disk_car, list_part);
  return 0;
}

static list_part_t *init_part_order_gpt(const disk_t *disk_car, list_part_t *list_part)
{
  list_part_t *element;
  unsigned int order=1;
  for(element=list_part;element!=NULL;element=element->next)
  {
    if(element->part->part_size>0 &&
        guid_cmp(element->part->part_type_gpt, GPT_ENT_TYPE_UNUSED)!=0)
      element->part->order=order++;
  }
  return list_part;
}

static list_part_t *add_partition_gpt_cli(disk_t *disk_car,list_part_t *list_part, const int verbose, char **current_cmd)
{
  partition_t *new_partition=partition_new(&arch_gpt);
  new_partition->part_offset=disk_car->sector_size;
  new_partition->part_size=disk_car->disk_size-new_partition->part_offset;
  while(*current_cmd[0]==',')
    (*current_cmd)++;
  while(1)
  {
    if(strncmp(*current_cmd,"s,",2)==0)
    {
      uint64_t part_offset;
      (*current_cmd)+=2;
      part_offset=new_partition->part_offset;
      new_partition->part_offset=(uint64_t)ask_number_cli(
          current_cmd,
          new_partition->part_offset/disk_car->sector_size,
          1,
          (disk_car->disk_size-1)/disk_car->sector_size,
          "Enter the starting sector ") *
        (uint64_t)disk_car->sector_size;
      new_partition->part_size=new_partition->part_size + part_offset - new_partition->part_offset;
    }
    else if(strncmp(*current_cmd,"S,",2)==0)
    {
      (*current_cmd)+=2;
      new_partition->part_size=(uint64_t)ask_number_cli(
          current_cmd,
          (new_partition->part_offset+new_partition->part_size-1)/disk_car->sector_size,
          new_partition->part_offset/disk_car->sector_size,
          (disk_car->disk_size-1)/disk_car->sector_size,
          "Enter the ending sector ") *
        (uint64_t)disk_car->sector_size +
        disk_car->sector_size - new_partition->part_offset;
    }
    else if(strncmp(*current_cmd,"T,",2)==0)
    {
      (*current_cmd)+=2;
      change_part_type(disk_car,new_partition,current_cmd);
    }
    else if(new_partition->part_size>0 && guid_cmp(new_partition->part_type_gpt, GPT_ENT_TYPE_UNUSED)!=0)
    {
      int insert_error=0;
      list_part_t *new_list_part=insert_new_partition(list_part, new_partition, 0, &insert_error);
      if(insert_error>0)
      {
        free(new_partition);
        return new_list_part;
      }
      new_partition->status=STATUS_PRIM;
      if(test_structure_gpt(list_part)!=0)
        new_partition->status=STATUS_DELETED;
      return new_list_part;
    }
    else
    {
      free(new_partition);
      return list_part;
    }
  }
}

#ifdef HAVE_NCURSES
static list_part_t *add_partition_gpt_ncurses(disk_t *disk_car,list_part_t *list_part, const int verbose, char **current_cmd)
{
  int position=0;
  int done = FALSE;
  partition_t *new_partition=partition_new(&arch_gpt);
  new_partition->part_offset=disk_car->sector_size;
  new_partition->part_size=disk_car->disk_size-disk_car->sector_size;
  while (done==FALSE)
  {
    int command;
    static struct MenuItem menuGeometry[]=
    {
      { 's', "Sector", 	"Change starting sector" },
      { 'S', "Sector", 	"Change ending sector" },
      { 'T' ,"Type",	"Change partition type"},
      { 'd', "Done", "" },
      { 0, NULL, NULL }
    };
    aff_copy(stdscr);
    wmove(stdscr,4,0);
    wdoprintf(stdscr,"%s",disk_car->description(disk_car));
    wmove(stdscr,10, 0);
    wclrtoeol(stdscr);
    aff_part(stdscr,AFF_PART_SHORT,disk_car,new_partition);
    wmove(stdscr,INTER_GEOM_Y, INTER_GEOM_X);
    wclrtoeol(stdscr);
    wrefresh(stdscr);
    command=wmenuSimple(stdscr,menuGeometry, position);
    switch (command) {
      case 's':
        {
          uint64_t part_offset;
          part_offset=new_partition->part_offset;
          wmove(stdscr, INTER_GEOM_Y, INTER_GEOM_X);
          new_partition->part_offset=(uint64_t)ask_number(
              new_partition->part_offset/disk_car->sector_size,
              1,
              (disk_car->disk_size-1)/disk_car->sector_size,
              "Enter the starting sector ") *
            (uint64_t)disk_car->sector_size;
          new_partition->part_size=new_partition->part_size + part_offset - new_partition->part_offset;
          position=1;
        }
        break;
      case 'S':
        wmove(stdscr, INTER_GEOM_Y, INTER_GEOM_X);
        new_partition->part_size=(uint64_t)ask_number(
            (new_partition->part_offset+new_partition->part_size-1)/disk_car->sector_size,
            new_partition->part_offset/disk_car->sector_size,
            (disk_car->disk_size-1)/disk_car->sector_size,
            "Enter the ending sector ") *
          (uint64_t)disk_car->sector_size +
          disk_car->sector_size - new_partition->part_offset;
        position=2;
        break;
      case 'T':
      case 't':
        change_part_type(disk_car,new_partition, current_cmd);
        position=3;
        break;
      case key_ESC:
      case 'd':
      case 'D':
      case 'q':
      case 'Q':
        done = TRUE;
        break;
    }
  }
  if(new_partition->part_size>0 && guid_cmp(new_partition->part_type_gpt, GPT_ENT_TYPE_UNUSED)!=0)
  {
    int insert_error=0;
    list_part_t *new_list_part=insert_new_partition(list_part, new_partition, 0, &insert_error);
    if(insert_error>0)
    {
      free(new_partition);
      return new_list_part;
    }
    new_partition->status=STATUS_PRIM;
    if(test_structure_gpt(list_part)!=0)
      new_partition->status=STATUS_DELETED;
    return new_list_part;
  }
  free(new_partition);
  return list_part;
}
#endif

static list_part_t *add_partition_gpt(disk_t *disk_car,list_part_t *list_part, const int verbose, char **current_cmd)
{
  if(*current_cmd!=NULL)
    return add_partition_gpt_cli(disk_car, list_part, verbose, current_cmd);
#ifdef HAVE_NCURSES
  return add_partition_gpt_ncurses(disk_car, list_part, verbose, current_cmd);
#else
  return list_part;
#endif
}

static void set_next_status_gpt(const disk_t *disk_car, partition_t *partition)
{
  if(partition->status==STATUS_DELETED)
    partition->status=STATUS_PRIM;
  else
    partition->status=STATUS_DELETED;
}

static int test_structure_gpt(list_part_t *list_part)
{ /* Return 1 if bad*/
  int res;
  list_part_t *new_list_part;
  new_list_part=gen_sorted_partition_list(list_part);
  res=is_part_overlapping(new_list_part);
  part_free_list_only(new_list_part);
  return res;
}

#if 0
static efi_guid_t get_part_type_gpt(const partition_t *partition)
{
  return partition->part_type_gpt;
}

static int set_part_type_gpt(partition_t *partition, efi_guid_t part_type_gpt)
{
  if(guid_cmp(partition->part_type_gpt, GPT_ENT_TYPE_UNUSED)!=0)
  {
    guid_cpy(&partition->part_type_gpt, &part_type_gpt);
    return 0;
  }
  return 1;
}
#endif

static int is_part_known_gpt(const partition_t *partition)
{
  return (guid_cmp(partition->part_type_gpt, GPT_ENT_TYPE_UNUSED)!=0);
}

static void init_structure_gpt(const disk_t *disk_car,list_part_t *list_part, const int verbose)
{
  list_part_t *element;
  list_part_t *new_list_part=NULL;
  /* Create new list */
  for(element=list_part;element!=NULL;element=element->next)
    element->to_be_removed=0;
  for(element=list_part;element!=NULL;element=element->next)
  {
    int insert_error=0;
    list_part_t *element2;
    for(element2=element->next;element2!=NULL;element2=element2->next)
    {
      if(element->part->part_offset+element->part->part_size-1 >= element2->part->part_offset)
      {
        element->to_be_removed=1;
        element2->to_be_removed=1;
      }
    }
    if(element->to_be_removed==0)
      new_list_part=insert_new_partition(new_list_part, element->part, 0, &insert_error);
  }
#ifdef DEBUG
  check_list_part(new_list_part);
#endif
    for(element=new_list_part;element!=NULL;element=element->next)
      element->part->status=STATUS_PRIM;
  if(disk_car->arch->test_structure(new_list_part))
  {
    for(element=new_list_part;element!=NULL;element=element->next)
      element->part->status=STATUS_DELETED;
  }
  part_free_list_only(new_list_part);
#ifdef DEBUG
  check_list_part(list_part);
#endif
}

static int check_part_gpt(disk_t *disk_car,const int verbose,partition_t *partition, const int saveheader)
{
  int ret=0;
  unsigned int old_levels;
  old_levels=log_set_levels(0);
  if(guid_cmp(partition->part_type_gpt, GPT_ENT_TYPE_MS_BASIC_DATA)==0 ||
      guid_cmp(partition->part_type_gpt, GPT_ENT_TYPE_MS_RESERVED)==0)
  {
    ret=check_FAT(disk_car,partition,verbose);
    if(ret!=0)
      ret=check_NTFS(disk_car,partition,verbose,0);
    if(ret!=0)
      ret=check_JFS(disk_car,partition,verbose);
    if(ret!=0)
      ret=check_rfs(disk_car,partition,verbose);
    if(ret!=0)
      ret=check_EXT2(disk_car,partition,verbose);
    if(ret!=0)
      ret=check_cramfs(disk_car,partition,verbose);
    if(ret!=0)
      ret=check_xfs(disk_car,partition,verbose);
    if(ret!=0)
    {
      aff_buffer(BUFFER_ADD,"No FAT, NTFS, EXT2, JFS, Reiser, cramfs or XFS marker\n"); 
    }
  }
  /* TODO: complete me */
  log_set_levels(old_levels);
  if(ret!=0)
  {
    log_error("check_part_gpt failed for partition\n");
    aff_part_buffer(AFF_PART_ORDER,disk_car,partition);
    if(saveheader>0)
    {
      save_header(disk_car,partition,verbose);
    }
  }
  return ret;
}

static const char *get_gpt_typename(const efi_guid_t part_type_gpt)
{
  int i;
  for(i=0; gpt_sys_types[i].name!=NULL; i++)
    if(guid_cmp(gpt_sys_types[i].part_type, part_type_gpt)==0)
      return gpt_sys_types[i].name;
  return NULL;
}

static const char *get_partition_typename_gpt(const partition_t *partition)
{
  return get_gpt_typename(partition->part_type_gpt);
}

