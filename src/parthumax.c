/*

    File: parthumax.c

    Copyright (C) 2010 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include "log.h"
#include "parthumax.h"

static list_part_t *read_part_humax(disk_t *disk_car, const int verbose, const int saveheader);
static int write_part_humax(disk_t *disk_car, const list_part_t *list_part, const int ro , const int verbose);
static list_part_t *init_part_order_humax(const disk_t *disk_car, list_part_t *list_part);
static void set_next_status_humax(const disk_t *disk_car, partition_t *partition);
static int test_structure_humax(list_part_t *list_part);
static int is_part_known_humax(const partition_t *partition);
static void init_structure_humax(const disk_t *disk_car,list_part_t *list_part, const int verbose);
static const char *get_partition_typename_humax(const partition_t *partition);
static unsigned int get_part_type_humax(const partition_t *partition);

#if 0
static const struct systypes humax_sys_types[] = {
  {0x00,	 	"Empty"        	},
  {PHUMAX_PARTITION,	"Partition"	},
  {0, NULL }
};
#endif

struct partition_humax {
  uint32_t unk1;
  uint32_t num_sectors;
  uint32_t unk2;
  uint32_t start_sector;
} __attribute__ ((gcc_struct, __packed__));

struct humaxlabel {
  char unk1[0x1be];
  struct partition_humax partitions[4];
  uint16_t magic;
} __attribute__ ((gcc_struct, __packed__));

arch_fnct_t arch_humax=
{
  .part_name="Humax",
  .part_name_option="partition_humax",
  .msg_part_type="                P=Primary  D=Deleted",
  .read_part=&read_part_humax,
  .write_part=&write_part_humax,
  .init_part_order=&init_part_order_humax,
  .get_geometry_from_mbr=NULL,
  .check_part=NULL,
  .write_MBR_code=NULL,
  .set_prev_status=&set_next_status_humax,
  .set_next_status=&set_next_status_humax,
  .test_structure=&test_structure_humax,
  .get_part_type=&get_part_type_humax,
  .set_part_type=NULL,
  .init_structure=&init_structure_humax,
  .erase_list_part=NULL,
  .get_partition_typename=&get_partition_typename_humax,
  .is_part_known=&is_part_known_humax
};

static int is_part_known_humax(const partition_t *partition)
{
  return (partition->part_type_humax != PHUMAX_PARTITION);
}

static unsigned int get_part_type_humax(const partition_t *partition)
{
  return partition->part_type_humax;
}

static list_part_t *read_part_humax(disk_t *disk_car, const int verbose, const int saveheader)
{
  unsigned int i;
  struct humaxlabel *humaxlabel;
  list_part_t *new_list_part=NULL;
  uint32_t *p32;
  unsigned char *buffer;
  if(disk_car->sector_size < DEFAULT_SECTOR_SIZE)
    return NULL;
  buffer=(unsigned char *)MALLOC(disk_car->sector_size);
  screen_buffer_reset();
  humaxlabel=(struct humaxlabel*)buffer;
  p32=(uint32_t*)buffer;
  if(disk_car->pread(disk_car, buffer, DEFAULT_SECTOR_SIZE, (uint64_t)0) != DEFAULT_SECTOR_SIZE)
  {
    screen_buffer_add( msg_PART_RD_ERR);
    free(buffer);
    return NULL;
  }
  for(i=0; i<0x200/4; i++)
    p32[i]=be32(p32[i]);
  dump_log(buffer, DEFAULT_SECTOR_SIZE);
  if (le16(humaxlabel->magic) != 0xAA55)
  {
    screen_buffer_add("Bad HUMAX partition\n");
    free(buffer);
    return NULL;
  }
  for(i=0;i<4;i++)
  {
     if (humaxlabel->partitions[i].num_sectors > 0)
     {
       int insert_error=0;
       partition_t *new_partition=partition_new(&arch_humax);
       new_partition->order=i+1;
       new_partition->part_type_humax=PHUMAX_PARTITION;
       new_partition->part_offset=be32(humaxlabel->partitions[i].start_sector)*disk_car->sector_size;
       new_partition->part_size=(uint64_t)be32(humaxlabel->partitions[i].num_sectors)*disk_car->sector_size;
       new_partition->status=STATUS_PRIM;
//       disk_car->arch->check_part(disk_car,verbose,new_partition,saveheader);
       aff_part_buffer(AFF_PART_ORDER|AFF_PART_STATUS,disk_car,new_partition);
       new_list_part=insert_new_partition(new_list_part, new_partition, 0, &insert_error);
       if(insert_error>0)
	 free(new_partition);
     }
  }
  free(buffer);
  return new_list_part;
}

static int write_part_humax(disk_t *disk_car, const list_part_t *list_part, const int ro, const int verbose)
{
  /* TODO: Implement it */
  if(ro==0)
    return -1;
  return 0;
}

static list_part_t *init_part_order_humax(const disk_t *disk_car, list_part_t *list_part)
{
  int nbr_prim=0;
  list_part_t *element;
  for(element=list_part;element!=NULL;element=element->next)
  {
    switch(element->part->status)
    {
      case STATUS_PRIM:
	element->part->order=nbr_prim++;
	break;
      default:
	log_critical("init_part_order_humax: severe error\n");
	break;
    }
  }
  return list_part;
}

list_part_t *add_partition_humax_cli(disk_t *disk_car,list_part_t *list_part, char **current_cmd)
{
  CHS_t start,end;
  partition_t *new_partition=partition_new(&arch_humax);
  assert(current_cmd!=NULL);
  start.cylinder=0;
  start.head=0;
  start.sector=1;
  end.cylinder=disk_car->geom.cylinders-1;
  end.head=disk_car->geom.heads_per_cylinder-1;
  end.sector=disk_car->geom.sectors_per_head;
  while(1)
  {
    skip_comma_in_command(current_cmd);
    if(check_command(current_cmd,"c,",2)==0)
    {
      start.cylinder=ask_number_cli(current_cmd, start.cylinder,0,disk_car->geom.cylinders-1,"Enter the starting cylinder ");
    }
    else if(check_command(current_cmd,"C,",2)==0)
    {
      end.cylinder=ask_number_cli(current_cmd, end.cylinder,start.cylinder,disk_car->geom.cylinders-1,"Enter the ending cylinder ");
    }
    else if(check_command(current_cmd,"T,",2)==0)
    {
      change_part_type_cli(disk_car,new_partition,current_cmd);
    }
    else if((CHS2offset(disk_car,&end)>new_partition->part_offset) &&
      new_partition->part_type_humax>0)
    {
      int insert_error=0;
      list_part_t *new_list_part=insert_new_partition(list_part, new_partition, 0, &insert_error);
      if(insert_error>0)
      {
	free(new_partition);
	return new_list_part;
      }
      new_partition->status=STATUS_PRIM;
      if(test_structure_humax(list_part)!=0)
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

static void set_next_status_humax(const disk_t *disk_car, partition_t *partition)
{
  if(partition->status==STATUS_DELETED)
    partition->status=STATUS_PRIM;
  else
    partition->status=STATUS_DELETED;
}

static int test_structure_humax(list_part_t *list_part)
{ /* Return 1 if bad*/
  list_part_t *new_list_part=NULL;
  int res;
  unsigned int nbr_prim=0;
  list_part_t *element;
  for(element=list_part;element!=NULL;element=element->next)
  {
    switch(element->part->status)
    {
      case STATUS_PRIM:
	nbr_prim++;
	break;
      case STATUS_DELETED:
	break;
      default:
	log_critical("test_structure_humax: severe error\n");
	break;
    }
  }
  if(nbr_prim>4)
    return 1;
  new_list_part=gen_sorted_partition_list(list_part);
  res=is_part_overlapping(new_list_part);
  part_free_list_only(new_list_part);
  return res;
}

static void init_structure_humax(const disk_t *disk_car,list_part_t *list_part, const int verbose)
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

static const char *get_partition_typename_humax(const partition_t *partition)
{
  return "Partition";
}
