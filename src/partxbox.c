/*

    File: partxbox.c

    Copyright (C) 2005-2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include <ctype.h>      /* tolower */
#include <assert.h>
#include "types.h"
#include "common.h"
#include "fnctdsk.h"
#include "lang.h"
#include "intrf.h"
#include "chgtype.h"
#include "partxbox.h"
#include "savehdr.h"
#include "fatx.h"
#include "log.h"

static int check_part_xbox(disk_t *disk_car, const int verbose,partition_t *partition,const int saveheader);
static list_part_t *read_part_xbox(disk_t *disk_car, const int verbose, const int saveheader);
static int write_part_xbox(disk_t *disk_car, const list_part_t *list_part, const int ro , const int verbose);
static list_part_t *init_part_order_xbox(const disk_t *disk_car, list_part_t *list_part);
static void set_next_status_xbox(const disk_t *disk_car, partition_t *partition);
static int test_structure_xbox(list_part_t *list_part);
static int set_part_type_xbox(partition_t *partition, unsigned int part_type_xbox);
static int is_part_known_xbox(const partition_t *partition);
static void init_structure_xbox(const disk_t *disk_car,list_part_t *list_part, const int verbose);
static const char *get_partition_typename_xbox(const partition_t *partition);
static const char *get_partition_typename_xbox_aux(const unsigned int part_type_xbox);
static unsigned int get_part_type_xbox(const partition_t *partition);

static const struct systypes xbox_sys_types[] = {
  { PXBOX_UNK,  "Unknown"		},
  { PXBOX_FATX, "FATX"			},
  { PXBOX_UNK,		NULL }
};

arch_fnct_t arch_xbox=
{
  .part_name="XBox",
  .part_name_option="partition_xbox",
  .msg_part_type="                P=Primary  D=Deleted",
  .read_part=&read_part_xbox,
  .write_part=&write_part_xbox,
  .init_part_order=&init_part_order_xbox,
  .get_geometry_from_mbr=NULL,
  .check_part=&check_part_xbox,
  .write_MBR_code=NULL,
  .set_prev_status=&set_next_status_xbox,
  .set_next_status=&set_next_status_xbox,
  .test_structure=&test_structure_xbox,
  .get_part_type=&get_part_type_xbox,
  .set_part_type=&set_part_type_xbox,
  .init_structure=&init_structure_xbox,
  .erase_list_part=NULL,
  .get_partition_typename=&get_partition_typename_xbox,
  .is_part_known=&is_part_known_xbox
};

static unsigned int get_part_type_xbox(const partition_t *partition)
{
  return partition->part_type_xbox;
}

static list_part_t *read_part_xbox(disk_t *disk_car, const int verbose, const int saveheader)
{
  unsigned char buffer[0x800];
  list_part_t *new_list_part=NULL;
  screen_buffer_reset();
  if(disk_car->pread(disk_car, &buffer, sizeof(buffer), 0) != sizeof(buffer))
    return new_list_part;
  {
    uint64_t offsets[]={ 0x00080000, 0x2ee80000, 0x5dc80000, 0x8ca80000, 0xabe80000 };
    unsigned int i;
    struct xbox_partition *xboxlabel=(struct xbox_partition*)&buffer;
    if (memcmp(xboxlabel->magic,"BRFR",4))
    {
      screen_buffer_add("\nBad XBOX partition, invalid signature\n");
      return NULL;
    }
    for(i=0;i<sizeof(offsets)/sizeof(uint64_t);i++)
    {
      if(offsets[i]<disk_car->disk_size)
      {
	int insert_error=0;
	partition_t *partition=partition_new(&arch_xbox);
	partition->part_type_xbox=PXBOX_FATX;
	partition->part_offset=offsets[i];
	partition->order=1+i;
	if(i==sizeof(offsets)/sizeof(uint64_t)-1 || disk_car->disk_size<=offsets[i+1])
	  partition->part_size=disk_car->disk_size-offsets[i];
	else
	  partition->part_size=offsets[i+1]-offsets[i];
	partition->status=STATUS_PRIM;
	disk_car->arch->check_part(disk_car,verbose,partition,saveheader);
	aff_part_buffer(AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition);
	new_list_part=insert_new_partition(new_list_part, partition, 0, &insert_error);
	if(insert_error>0)
	  free(partition);
      }
    }
  }
  return new_list_part;
}

static int write_part_xbox(disk_t *disk_car, const list_part_t *list_part, const int ro, const int verbose)
{
  /* TODO: Implement it */
  if(ro==0)
    return -1;
  return 0;
}

static list_part_t *init_part_order_xbox(const disk_t *disk_car, list_part_t *list_part)
{
  return list_part;
}

list_part_t *add_partition_xbox_cli(disk_t *disk_car,list_part_t *list_part, char **current_cmd)
{
  partition_t *new_partition=partition_new(&arch_xbox);
  assert(current_cmd!=NULL);
  new_partition->part_offset=disk_car->sector_size;
  new_partition->part_size=disk_car->disk_size-disk_car->sector_size;
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
	  0x800/disk_car->sector_size,
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
    else if(new_partition->part_size>0 && new_partition->part_type_xbox>0)
    {
      int insert_error=0;
      list_part_t *new_list_part=insert_new_partition(list_part, new_partition, 0, &insert_error);
      if(insert_error>0)
      {
	free(new_partition);
	return new_list_part;
      }
      new_partition->status=STATUS_PRIM;
      if(test_structure_xbox(list_part)!=0)
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

static void set_next_status_xbox(const disk_t *disk_car, partition_t *partition)
{
  if(partition->status==STATUS_DELETED)
    partition->status=STATUS_PRIM;
  else
    partition->status=STATUS_DELETED;
}

static int test_structure_xbox(list_part_t *list_part)
{ /* Return 1 if bad*/
  list_part_t *new_list_part;
  int res;
  new_list_part=gen_sorted_partition_list(list_part);
  res=is_part_overlapping(new_list_part);
  part_free_list_only(new_list_part);
  return res;
}

static int set_part_type_xbox(partition_t *partition, unsigned int part_type_xbox)
{
  if(part_type_xbox>0 && part_type_xbox <= 255)
  {
    partition->part_type_xbox=part_type_xbox;
    return 0;
  }
  return 1;
}

static int is_part_known_xbox(const partition_t *partition)
{
  return (partition->part_type_xbox!=PXBOX_UNK);
}

static void init_structure_xbox(const disk_t *disk_car,list_part_t *list_part, const int verbose)
{
  list_part_t *element;
  list_part_t *new_list_part=NULL;
  /* Create new list */
  for(element=list_part;element!=NULL;element=element->next)
    element->to_be_removed=0;
  for(element=list_part;element!=NULL;element=element->next)
  {
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
    {
      int insert_error=0;
      new_list_part=insert_new_partition(new_list_part, element->part, 0, &insert_error);
    }
  }
    for(element=new_list_part;element!=NULL;element=element->next)
      element->part->status=STATUS_PRIM;
  if(disk_car->arch->test_structure(new_list_part))
  {
    for(element=new_list_part;element!=NULL;element=element->next)
      element->part->status=STATUS_DELETED;
  }
  part_free_list_only(new_list_part);
}

static int check_part_xbox(disk_t *disk_car,const int verbose,partition_t *partition, const int saveheader)
{
  int ret=0;
  switch(partition->part_type_xbox)
  {
    case PXBOX_FATX:
      ret=check_FATX(disk_car, partition);
      if(ret!=0)
      { screen_buffer_add("Invalid FATX signature\n"); }
      break;
    default:
      if(verbose>0)
      {
	log_info("check_part_xbox %u type %02X: no test\n",partition->order,partition->part_type_xbox);
      }
      break;
  }
  if(ret!=0)
  {
    log_error("check_part_xbox failed for partition type %02X\n", partition->part_type_xbox);
    aff_part_buffer(AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition);
    if(saveheader>0)
    {
      save_header(disk_car,partition,verbose);
    }
  }
  return ret;
}

static const char *get_partition_typename_xbox_aux(const unsigned int part_type_xbox)
{
  int i;
  for (i=0; xbox_sys_types[i].name!=NULL; i++)
    if (xbox_sys_types[i].part_type == part_type_xbox)
      return xbox_sys_types[i].name;
  return NULL;
}

static const char *get_partition_typename_xbox(const partition_t *partition)
{
  return get_partition_typename_xbox_aux(partition->part_type_xbox);
}
