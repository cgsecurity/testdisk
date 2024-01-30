/*

    File: partgpt.c

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

#if !defined(SINGLE_PARTITION_TYPE) || defined(SINGLE_PARTITION_GPT)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#if defined(DISABLED_FOR_FRAMAC)
#undef HAVE_SYS_UUID_H
#undef HAVE_UUID_H
#undef HAVE_UUID_UUID_H
#endif

#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <ctype.h>      /* tolower */
#include "types.h"
#if defined(HAVE_UUID_H)
#include <uuid.h>
#elif defined(HAVE_UUID_UUID_H)
#include <uuid/uuid.h>
#elif defined(HAVE_SYS_UUID_H)
#include <sys/uuid.h>
#endif
#include <assert.h>
#include "common.h"
#include "fnctdsk.h"
#include "lang.h"
#include "intrf.h"
#ifndef DISABLED_FOR_FRAMAC
#include "analyse.h"
#endif
#include "chgtype.h"
#include "partgpt.h"
#include "savehdr.h"
#ifndef DISABLED_FOR_FRAMAC
#include "apfs.h"
#include "bfs.h"
#include "exfat.h"
#include "fat.h"
#include "hfs.h"
#include "hfsp.h"
#include "lvm.h"
#include "md.h"
#include "ntfs.h"
#include "refs.h"
#endif
#include "log.h"
#include "log_part.h"
#include "guid_cmp.h"
#include "guid_cpy.h"
#include "unicode.h"
#include "crc.h"

/*@
  @ requires \valid(disk);
  @ requires \valid(partition);
  @*/
static int check_part_gpt(disk_t *disk, const int verbose, partition_t *partition, const int saveheader);

/*@
  @ requires \valid(disk_car);
  @ ensures  valid_list_part(\result);
  @*/
static list_part_t *read_part_gpt(disk_t *disk_car, const int verbose, const int saveheader);

/*@
  @ requires \valid(disk_car);
  @ requires list_part == \null || \valid(list_part);
  @ requires separation: \separated(disk_car, list_part);
  @*/
static list_part_t *init_part_order_gpt(const disk_t *disk_car, list_part_t *list_part);

/*@
  @ requires \valid_read(disk_car);
  @ requires \valid(partition);
  @ requires separation: \separated(disk_car, partition);
  @ assigns partition->status;
  @*/
static void set_next_status_gpt(const disk_t *disk_car, partition_t *partition);

/*@
  @ requires list_part == \null || \valid_read(list_part);
  @*/
static int test_structure_gpt(const list_part_t *list_part);

/*@
  @ requires \valid(partition);
  @ assigns \nothing;
  @*/
static int is_part_known_gpt(const partition_t *partition);

/*@
  @ requires \valid_read(disk_car);
  @ requires list_part == \null || \valid(list_part);
  @*/
static void init_structure_gpt(const disk_t *disk_car,list_part_t *list_part, const int verbose);

/*@
  @ requires \valid_read(partition);
  @ assigns \nothing;
  @*/
static const char *get_partition_typename_gpt(const partition_t *partition);

/*@
  @ assigns \nothing;
  @*/
static const char *get_gpt_typename(const efi_guid_t part_type_gpt);

const struct systypes_gtp gpt_sys_types[] = {
  { GPT_ENT_TYPE_EFI, 			"EFI System"		},
  { GPT_ENT_TYPE_EBP, 			"Extended Boot"		},
  { GPT_ENT_TYPE_MBR,			"MBR"			},
  { GPT_ENT_TYPE_FREEBSD,		"FreeBSD"		},
  { GPT_ENT_TYPE_FREEBSD_SWAP,		"FreeBSD Swap"		},
  { GPT_ENT_TYPE_FREEBSD_UFS,		"FreeBSD UFS"		},
  { GPT_ENT_TYPE_FREEBSD_VINUM,		"FreeBSD Vinum"		},
//  { GPT_ENT_TYPE_FREEBSD_UFS2,		"FreeBSD UFS2"		},
  { GPT_ENT_TYPE_FREEBSD_ZFS,		"FreeBSD ZFS"		},
  { GPT_ENT_TYPE_MS_RESERVED,		"MS Reserved"		},
  { GPT_ENT_TYPE_MS_BASIC_DATA,		"MS Data"		},
  { GPT_ENT_TYPE_MS_LDM_METADATA,	"MS LDM MetaData"	},
  { GPT_ENT_TYPE_MS_LDM_DATA,		"MS LDM Data"		},
  { GPT_ENT_TYPE_MS_RECOVERY,		"Windows Recovery Env"  },
  { GPT_ENT_TYPE_MS_SPACES,		"MS Storage Spaces"	},
//  { GPT_ENT_TYPE_LINUX_DATA
  { GPT_ENT_TYPE_LINUX_RAID,		"Linux Raid"		},
  { GPT_ENT_TYPE_LINUX_SWAP,		"Linux Swap"		},
  { GPT_ENT_TYPE_LINUX_LVM,		"Linux LVM"		},
  { GPT_ENT_TYPE_LINUX_RESERVED,	"Linux Reserved"	},
  { GPT_ENT_TYPE_LINUX_HOME,		"Linux /home"		},
  { GPT_ENT_TYPE_LINUX_SRV,		"Linux /src"		},
  { GPT_ENT_TYPE_LINUX_DATA,		"Linux filesys. data"	},
  { GPT_ENT_TYPE_HPUX_DATA,		"HPUX Data"		},
  { GPT_ENT_TYPE_HPUX_SERVICE,		"HPUX Service"		},
  { GPT_ENT_TYPE_MAC_APFS,		"Apple APFS"		},
  { GPT_ENT_TYPE_MAC_HFS,		"Mac HFS"		},
  { GPT_ENT_TYPE_MAC_UFS,		"Mac UFS"		},
  { GPT_ENT_TYPE_MAC_RAID,		"Mac Raid"		},
  { GPT_ENT_TYPE_MAC_RAID_OFFLINE,	"Mac Raid (Offline)"	},
  { GPT_ENT_TYPE_MAC_BOOT,		"Mac Boot"		},
  { GPT_ENT_TYPE_MAC_LABEL,		"Mac Label"		},
  { GPT_ENT_TYPE_MAC_TV_RECOVERY,	"Mac TV Recovery"	},
  { GPT_ENT_TYPE_APPLE_CORE_STORAGE,	"Apple Core Storage"	},
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
  { GPT_ENT_TYPE_BEOS_BFS,		"BeFS"},
  { GPT_ENT_TYPE_UNUSED,  NULL }
 };

arch_fnct_t arch_gpt=
{
  .part_name="EFI GPT",
  .part_name_option="partition_gpt",
  .msg_part_type="                P=Primary  D=Deleted",
  .read_part=&read_part_gpt,
  .write_part=&write_part_gpt,
  .init_part_order=&init_part_order_gpt,
  .get_geometry_from_mbr=NULL,
  .check_part=&check_part_gpt,
  .write_MBR_code=NULL,
  .set_prev_status=&set_next_status_gpt,
  .set_next_status=&set_next_status_gpt,
  .test_structure=&test_structure_gpt,
  .get_part_type=NULL,
  .set_part_type=NULL,
  .init_structure=&init_structure_gpt,
  .erase_list_part=NULL,
  .get_partition_typename=&get_partition_typename_gpt,
  .is_part_known=&is_part_known_gpt
};

/*@
  @ requires \valid(disk_car);
  @ requires valid_disk(disk_car);
  @*/
// ensures  valid_list_part(\result);
static list_part_t *read_part_gpt_aux(disk_t *disk_car, const int verbose, const int saveheader, const uint64_t hdr_lba)
{
  struct gpt_hdr *gpt;
  struct gpt_ent* gpt_entries;
  list_part_t *new_list_part=NULL;
  unsigned int i;
  uint32_t gpt_entries_size;
  uint64_t gpt_entries_offset;

  gpt=(struct gpt_hdr*)MALLOC(disk_car->sector_size);
  if((unsigned)disk_car->pread(disk_car, gpt, disk_car->sector_size,
	hdr_lba * disk_car->sector_size) != disk_car->sector_size)
  {
    free(gpt);
    return NULL;
  }
  if(memcmp(gpt->hdr_sig, GPT_HDR_SIG, 8)!=0)
  {
    screen_buffer_add("Bad GPT partition, invalid signature.\n");
    free(gpt);
    return NULL;
  }
  if(verbose>0)
  {
    log_info("hdr_size=%llu\n", (long long unsigned)le32(gpt->hdr_size));
    log_info("hdr_lba_self=%llu\n", (long long unsigned)le64(gpt->hdr_lba_self));
    log_info("hdr_lba_alt=%llu (expected %llu)\n",
	(long long unsigned)le64(gpt->hdr_lba_alt),
	(hdr_lba==1?
	 (long long unsigned)((disk_car->disk_size-1)/disk_car->sector_size):
	 1));
    log_info("hdr_lba_start=%llu\n", (long long unsigned)le64(gpt->hdr_lba_start));
    log_info("hdr_lba_end=%llu\n", (long long unsigned)le64(gpt->hdr_lba_end));
    log_info("hdr_lba_table=%llu\n",
	(long long unsigned)le64(gpt->hdr_lba_table));
    log_info("hdr_entries=%llu\n", (long long unsigned)le32(gpt->hdr_entries));
    log_info("hdr_entsz=%llu\n", (long long unsigned)le32(gpt->hdr_entsz));
  }
  /* Check header size */
  if(le32(gpt->hdr_size)<92 || le32(gpt->hdr_size) > disk_car->sector_size)
  {
    screen_buffer_add("GPT: invalid header size.\n");
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
      screen_buffer_add("Bad GPT partition, invalid header checksum.\n");
      free(gpt);
      return NULL;
    }
    gpt->hdr_crc_self=le32(origcrc);
  }
  if(le64(gpt->hdr_lba_self)!=hdr_lba)
  {
    screen_buffer_add("Bad GPT partition, invalid LBA self location.\n");
    free(gpt);
    return NULL;
  }
  if(le64(gpt->hdr_lba_start) >= le64(gpt->hdr_lba_end))
  {
    screen_buffer_add("Bad GPT partition, invalid LBA start/end location.\n");
    free(gpt);
    return NULL;
  }
  if(le32(gpt->hdr_revision)!=GPT_HDR_REVISION)
  {
    screen_buffer_add("GPT: Warning - not revision 1.0\n");
  }
  if(le32(gpt->__reserved)!=0)
  {
    screen_buffer_add("GPT: Warning - __reserved!=0\n");
  }
  if(le32(gpt->hdr_entries)==0 || le32(gpt->hdr_entries)>4096)
  {
    screen_buffer_add("GPT: invalid number (%u) of partition entries.\n",
        (unsigned int)le32(gpt->hdr_entries));
    free(gpt);
    return NULL;
  }
  /* le32(gpt->hdr_entsz)==128 */
  if(le32(gpt->hdr_entsz)%8!=0 || le32(gpt->hdr_entsz)<128 || le32(gpt->hdr_entsz)>4096)
  {
    screen_buffer_add("GPT: invalid partition entry size.\n");
    free(gpt);
    return NULL;
  }

  gpt_entries_size=le32(gpt->hdr_entries) * le32(gpt->hdr_entsz);
  if(gpt_entries_size<16384)
  {
    screen_buffer_add("GPT: A minimum of 16,384 bytes of space must be reserved for the GUID Partition Entry array.\n");
    free(gpt);
    return NULL;
  }
  gpt_entries_offset=(uint64_t)le64(gpt->hdr_lba_table) * disk_car->sector_size;
  if(hdr_lba==1)
  {
    if((uint64_t) le64(gpt->hdr_lba_self) + le32(gpt->hdr_size) - 1 >= gpt_entries_offset ||
	gpt_entries_offset >= le64(gpt->hdr_lba_start) * disk_car->sector_size)
    {
      screen_buffer_add( "GPT: The primary GUID Partition Entry array must be located after the primary GUID Partition Table Header and end before the FirstUsableLBA.\n");
      free(gpt);
      return NULL;
    }
  }

  gpt_entries=(struct gpt_ent*)MALLOC(gpt_entries_size);
  if((unsigned)disk_car->pread(disk_car, gpt_entries, gpt_entries_size, gpt_entries_offset) != gpt_entries_size)
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
      screen_buffer_add("Bad GPT partition entries, invalid checksum.\n");
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
      check_part_gpt(disk_car,verbose,new_partition,saveheader);
      /* log_debug("%u ent_attr %08llx\n", new_partition->order, (long long unsigned)le64(gpt_entry->ent_attr)); */
      aff_part_buffer(AFF_PART_ORDER|AFF_PART_STATUS,disk_car,new_partition);
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

list_part_t *read_part_gpt(disk_t *disk, const int verbose, const int saveheader)
{
  list_part_t *list_part;
  screen_buffer_reset();
  if((list_part=read_part_gpt_aux(disk, verbose, saveheader, 1))!=NULL)
    return list_part;
  screen_buffer_add( "Trying alternate GPT\n");
  list_part=read_part_gpt_aux(disk, verbose, saveheader, 
      (disk->disk_size-1)/disk->sector_size);
  screen_buffer_to_log();
  return list_part;
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

list_part_t *add_partition_gpt_cli(const disk_t *disk_car, list_part_t *list_part, char **current_cmd)
{
  partition_t *new_partition;
  assert(current_cmd!=NULL);
  new_partition=partition_new(&arch_gpt);
  new_partition->part_offset=disk_car->sector_size;
  new_partition->part_size=disk_car->disk_size-new_partition->part_offset;
  /*@
    @ loop invariant valid_list_part(list_part);
    @ loop invariant valid_read_string(*current_cmd);
    @ */
  while(1)
  {
    skip_comma_in_command(current_cmd);
    if(check_command(current_cmd,"s,",2)==0)
    {
      uint64_t part_offset;
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
    else if(check_command(current_cmd,"S,",2)==0)
    {
      new_partition->part_size=(uint64_t)ask_number_cli(
          current_cmd,
          (new_partition->part_offset+new_partition->part_size-1)/disk_car->sector_size,
          new_partition->part_offset/disk_car->sector_size,
          (disk_car->disk_size-1)/disk_car->sector_size,
          "Enter the ending sector ") *
        (uint64_t)disk_car->sector_size +
        disk_car->sector_size - new_partition->part_offset;
    }
    else if(check_command(current_cmd,"T,",2)==0)
    {
      change_part_type_cli(disk_car,new_partition,current_cmd);
    }
    else if(new_partition->part_size>0 && guid_cmp(new_partition->part_type_gpt, GPT_ENT_TYPE_UNUSED)!=0)
    {
      int insert_error=0;
      list_part_t *new_list_part=insert_new_partition(list_part, new_partition, 0, &insert_error);
      /*@ assert valid_list_part(new_list_part); */
      if(insert_error>0)
      {
        free(new_partition);
	/*@ assert valid_list_part(new_list_part); */
        return new_list_part;
      }
      new_partition->status=STATUS_PRIM;
      if(test_structure_gpt(list_part)!=0)
        new_partition->status=STATUS_DELETED;
      /*@ assert valid_list_part(new_list_part); */
      return new_list_part;
    }
    else
    {
      free(new_partition);
      /*@ assert valid_list_part(list_part); */
      return list_part;
    }
  }
}

static void set_next_status_gpt(const disk_t *disk_car, partition_t *partition)
{
  if(partition->status==STATUS_DELETED)
    partition->status=STATUS_PRIM;
  else
    partition->status=STATUS_DELETED;
}

static int test_structure_gpt(const list_part_t *list_part)
{ /* Return 1 if bad*/
  int res;
  list_part_t *new_list_part;
  new_list_part=gen_sorted_partition_list(list_part);
  res=is_part_overlapping(new_list_part);
  part_free_list_only(new_list_part);
  return res;
}

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
    for(element=new_list_part;element!=NULL;element=element->next)
      element->part->status=STATUS_PRIM;
  if(test_structure_gpt(new_list_part))
  {
    for(element=new_list_part;element!=NULL;element=element->next)
      element->part->status=STATUS_DELETED;
  }
  part_free_list_only(new_list_part);
}

static int check_part_gpt(disk_t *disk, const int verbose,partition_t *partition, const int saveheader)
{
  int ret=0;
  unsigned int old_levels;
  old_levels=log_set_levels(0);
  if(guid_cmp(partition->part_type_gpt, GPT_ENT_TYPE_MS_BASIC_DATA)==0 ||
      guid_cmp(partition->part_type_gpt, GPT_ENT_TYPE_MS_RESERVED)==0)
  {
    ret=check_FAT(disk,partition,verbose);
    if(ret!=0)
      ret=check_exFAT(disk, partition);
    if(ret!=0)
      ret=check_NTFS(disk,partition,verbose,0);
    if(ret!=0)
      ret=check_ReFS(disk, partition);
    if(ret!=0)
      ret=check_linux(disk, partition, verbose);
    if(ret!=0)
      screen_buffer_add("No FAT, NTFS, ext2, JFS, Reiser, cramfs or XFS marker\n"); 
  }
  else if(guid_cmp(partition->part_type_gpt, GPT_ENT_TYPE_LINUX_RAID)==0)
  {
    ret=check_MD(disk, partition, verbose);
    if(ret!=0)
      screen_buffer_add("Invalid RAID superblock\n");
  }
  else if(guid_cmp(partition->part_type_gpt, GPT_ENT_TYPE_LINUX_LVM)==0)
  {
    ret=check_LVM(disk, partition, verbose);
    if(ret!=0)
      ret=check_LVM2(disk, partition, verbose);
    if(ret!=0)
      screen_buffer_add("No LVM or LVM2 structure\n");
  }
  else if(guid_cmp(partition->part_type_gpt, GPT_ENT_TYPE_MAC_HFS)==0)
  {
    ret=check_HFS(disk, partition, verbose);
    if(ret!=0)
      ret=check_HFSP(disk, partition, verbose);
    if(ret!=0)
      screen_buffer_add("No HFS or HFS+ structure\n");
  }
  else if(guid_cmp(partition->part_type_gpt, GPT_ENT_TYPE_MAC_APFS)==0)
  {
    ret=check_APFS(disk, partition);
    if(ret!=0)
      screen_buffer_add("No valid APFS structure\n");
  }
  else if(guid_cmp(partition->part_type_gpt, GPT_ENT_TYPE_BEOS_BFS)==0)
  {
    ret=check_BeFS(disk, partition);
    if(ret!=0)
      screen_buffer_add("No BFS structure\n");
  }
  log_set_levels(old_levels);
  if(ret!=0)
  {
    log_error("check_part_gpt failed for partition\n");
    log_partition(disk, partition);
    aff_part_buffer(AFF_PART_ORDER|AFF_PART_STATUS,disk,partition);
    if(saveheader>0)
    {
      save_header(disk, partition, verbose);
    }
  }
  return ret;
}

static const char *get_gpt_typename(const efi_guid_t part_type_gpt)
{
  int i;
  /*@ loop assigns i; */
  for(i=0; gpt_sys_types[i].name!=NULL; i++)
    if(guid_cmp(gpt_sys_types[i].part_type, part_type_gpt)==0)
      return gpt_sys_types[i].name;
#ifndef DISABLED_FOR_FRAMAC
  log_info("%8x %04x %04x %02x %02x %02x %02x %02x %02x %02x %02x\n",
      part_type_gpt.time_low,
      part_type_gpt.time_mid,
      part_type_gpt.time_hi_and_version,
      part_type_gpt.clock_seq_hi_and_reserved,
      part_type_gpt.clock_seq_low,
      part_type_gpt.node[0],
      part_type_gpt.node[1],
      part_type_gpt.node[2],
      part_type_gpt.node[3],
      part_type_gpt.node[4],
      part_type_gpt.node[5]);
#endif
  return NULL;
}

static const char *get_partition_typename_gpt(const partition_t *partition)
{
  return get_gpt_typename(partition->part_type_gpt);
}
#endif
