/*

    File: fnctdsk.c

    Copyright (C) 1998-2005,2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include "common.h"
#include "fnctdsk.h"
#include "log.h"
#include "log_part.h"
#include "guid_cpy.h"

/*@
  @ requires \valid(part);
  @ ensures \valid(\result);
  @*/
static list_part_t *element_new(partition_t *part)
{
  list_part_t *new_element=(list_part_t*)MALLOC(sizeof(*new_element));
  /*@ assert \valid(new_element); */
  new_element->part=part;
  new_element->prev=new_element->next=NULL;
  new_element->to_be_removed=0;
  return new_element;
}

unsigned long int C_H_S2LBA(const disk_t *disk_car,const unsigned int C, const unsigned int H, const unsigned int S)
{
  return ((unsigned long int)C * disk_car->geom.heads_per_cylinder + H) * disk_car->geom.sectors_per_head + S - 1;
}

uint64_t CHS2offset(const disk_t *disk_car,const CHS_t*CHS)
{
  return (((uint64_t)CHS->cylinder * disk_car->geom.heads_per_cylinder + CHS->head) *
      disk_car->geom.sectors_per_head + CHS->sector - 1) * disk_car->sector_size;
//  return (uint64_t)C_H_S2LBA(disk_car, CHS->cylinder, CHS->head, CHS->sector) * disk_car->sector_size;
}

unsigned int offset2sector(const disk_t *disk_car, const uint64_t offset)
{
  return ((offset / disk_car->sector_size) % disk_car->geom.sectors_per_head) + 1;
}

unsigned int offset2head(const disk_t *disk_car, const uint64_t offset)
{
  return ((offset / disk_car->sector_size) / disk_car->geom.sectors_per_head) % disk_car->geom.heads_per_cylinder;
}

unsigned int offset2cylinder(const disk_t *disk_car, const uint64_t offset)
{
  return ((offset / disk_car->sector_size) / disk_car->geom.sectors_per_head) / disk_car->geom.heads_per_cylinder;
}

void offset2CHS(const disk_t *disk_car,const uint64_t offset, CHS_t*CHS)
{
  uint64_t pos=offset/disk_car->sector_size;
  CHS->sector=(pos%disk_car->geom.sectors_per_head)+1;
  pos/=disk_car->geom.sectors_per_head;
  CHS->head=pos%disk_car->geom.heads_per_cylinder;
  CHS->cylinder=pos/disk_car->geom.heads_per_cylinder;
}

void dup_partition_t(partition_t *dst, const partition_t *src)
{
#if 0
  dst->part_offset=src->part_offset;
  dst->part_size=src->part_size;
  dst->boot_sector=src->boot_sector;
  dst->boot_sector_size=src->boot_sector_size;
  dst->blocksize=src->blocksize;
  dst->part_type_i386=src->part_type_i386;
  dst->part_type_sun=src->part_type_sun;
  dst->part_type_mac=src->part_type_mac;
  dst->part_type_xbox=src->part_type_xbox;
  dst->part_type_gpt=src->part_type_gpt;
  dst->upart_type=src->upart_type;
  dst->status=src->status;
  dst->order=src->order;
  dst->errcode=src->errcode;
  strncpy(dst->info,src->info,sizeof(dst->info));
  strncpy(dst->fsname,src->name,sizeof(dst->fsname));
  strncpy(dst->partname,src->name,sizeof(dst->partname));
  dst->arch=src->arch;
#else
  memcpy(dst, src, sizeof(*src));
#endif
}

/*@
  @ requires valid_list_disk(list_disk);
  @ requires disk!=\null;
  @ requires valid_disk(disk);
  @ assigns \nothing;
  @*/
static disk_t *search_disk(const list_disk_t *list_disk, const disk_t *disk)
{
  const list_disk_t *tmp;
  /*@
    @ loop assigns tmp;
    @*/
  for(tmp=list_disk;tmp!=NULL;tmp=tmp->next)
  {
    if(tmp->disk->device!=NULL && disk->device!=NULL &&
	strcmp(tmp->disk->device, disk->device)==0)
    {
      return tmp->disk;
    }
  }
  return NULL;
}

list_disk_t *insert_new_disk_aux(list_disk_t *list_disk, disk_t *disk, disk_t **the_disk)
{
  list_disk_t *prev=NULL;
  list_disk_t *new_disk;
  disk_t *found;
  if(disk==NULL)
  {
    if(the_disk!=NULL)
    {
      /*@ assert \valid(the_disk); */
      *the_disk=NULL;
    }
    /*@ assert valid_list_disk(list_disk); */
    return list_disk;
  }
  found=search_disk(list_disk, disk);
  /* Do not add a disk already known */
  if(found!=NULL)
  {
    disk->clean(disk);
    if(the_disk!=NULL)
    {
      /*@ assert \valid(the_disk); */
      *the_disk=found;
    }
    /*@ assert valid_list_disk(list_disk); */
    return list_disk;
  }
  /* Add the disk at the end */
  {
    list_disk_t *tmp;
    /*@
      @ loop invariant valid_list_disk(list_disk);
      @ loop invariant tmp==\null || \valid(tmp);
      @ loop assigns tmp,prev;
      @*/
    for(tmp=list_disk;tmp!=NULL;tmp=tmp->next)
      prev=tmp;
  }
  new_disk=(list_disk_t *)MALLOC(sizeof(*new_disk));
  /*@ assert \valid(new_disk); */
  new_disk->disk=disk;
  new_disk->prev=prev;
  new_disk->next=NULL;
  if(prev!=NULL)
  {
    prev->next=new_disk;
  }
  if(the_disk!=NULL)
  {
    /*@ assert \valid(the_disk); */
    *the_disk=disk;
  }
  /*@ assert valid_list_disk(new_disk); */
  /*@ assert valid_list_disk(list_disk); */
  return (list_disk!=NULL?list_disk:new_disk);
}

list_disk_t *insert_new_disk(list_disk_t *list_disk, disk_t *disk)
{
  return insert_new_disk_aux(list_disk, disk, NULL);
}

list_part_t *insert_new_partition(list_part_t *list_part, partition_t *part, const int force_insert, int *insert_error)
{
  list_part_t *prev=NULL;
  list_part_t *next;
  *insert_error=0;
  /*@
    @ loop invariant valid_list_part(list_part);
    @ loop invariant valid_partition(part);
    @ loop invariant \valid(insert_error);
    @*/
  for(next=list_part;;next=next->next)
  { /* prev new next */
    /*@ assert next == \null || (\valid(next) && valid_partition(next->part)); */
    if((next==NULL)||
      (part->part_offset<next->part->part_offset) ||
      (part->part_offset==next->part->part_offset &&
       ((part->part_size<next->part->part_size) ||
	(part->part_size==next->part->part_size && (force_insert==0 || part->sb_offset < next->part->sb_offset)))))
    {
      if(force_insert==0 &&
	(next!=NULL) &&
	(next->part->part_offset==part->part_offset) &&
	(next->part->part_size==part->part_size) &&
	(next->part->part_type_i386==part->part_type_i386) &&
	(next->part->part_type_mac==part->part_type_mac) &&
	(next->part->part_type_sun==part->part_type_sun) &&
	(next->part->part_type_xbox==part->part_type_xbox) &&
	(next->part->upart_type==part->upart_type || part->upart_type==UP_UNK))
      { /*CGR 2004/05/31*/
	if(next->part->status==STATUS_DELETED)
	{
	  next->part->status=part->status;
	}
	*insert_error=1;
	/*@ assert valid_list_part(list_part); */
	return list_part;
      }
      { /* prev new_element next */
	list_part_t *new_element;
	new_element=element_new(part);
	/*@ assert \valid(new_element); */
	new_element->next=next;
	new_element->prev=prev;
	if(next!=NULL)
	  next->prev=new_element;
	if(prev!=NULL)
	{
	  prev->next=new_element;
	  /*@ assert valid_list_part(list_part); */
	  return list_part;
	}
	/*@ assert valid_list_part(new_element); */
	return new_element;
      }
    }
    prev=next;
  }
}

int delete_list_disk(list_disk_t *list_disk)
{
  list_disk_t *element_disk;
  int write_used=0;
  /*@
    @ loop invariant valid_list_disk(element_disk);
    @*/
  for(element_disk=list_disk;element_disk!=NULL;)
  {
    /*@ assert \valid_read(element_disk); */
    list_disk_t *element_disk_next=element_disk->next;
    /*@ assert valid_disk(element_disk->disk); */
    write_used|=element_disk->disk->write_used;
    /*@ assert \valid_read(element_disk->disk); */
    /*@ assert \valid_function(element_disk->disk->clean); */
    element_disk->disk->clean(element_disk->disk);
    free(element_disk);
    element_disk=element_disk_next;
  }
  return write_used;
}

list_part_t *sort_partition_list(list_part_t *list_part)
{
  list_part_t *new_list_part=NULL;
  list_part_t *element;
  list_part_t *next;
  /*@ assert valid_list_part(new_list_part); */
  /*@
    @ loop invariant valid_list_part(list_part);
    @ loop invariant valid_list_part(new_list_part);
    @*/
  for(element=list_part;element!=NULL;element=next)
  {
    int insert_error=0;
    /*@ assert \valid(element); */
    next=element->next;
    new_list_part=insert_new_partition(new_list_part, element->part, 0, &insert_error);
    if(insert_error>0)
      free(element->part);
    free(element);
  }
  /*@ assert valid_list_part(new_list_part); */
  return new_list_part;
}

list_part_t *gen_sorted_partition_list(const list_part_t *list_part)
{
  list_part_t *new_list_part=NULL;
  const list_part_t *element;
  /*@ assert valid_list_part(new_list_part); */
  /*@
    @ loop invariant valid_list_part(list_part);
    @ loop invariant valid_list_part(new_list_part);
    @*/
  for(element=list_part;element!=NULL;element=element->next)
  {
    /*@ assert \valid_read(element); */
    /*@ assert \valid_read(element->part); */
    int insert_error=0;
    if(element->part->status!=STATUS_DELETED)
      new_list_part=insert_new_partition(new_list_part, element->part, 1, &insert_error);
    /*@ assert \valid_read(element); */
  }
  /*@ assert valid_list_part(new_list_part); */
  return new_list_part;
}

/* Delete the list and its content */
void part_free_list(list_part_t *list_part)
{
  list_part_t *element;
  element=list_part;
  /*@ loop invariant valid_list_part(element); */
  while(element!=NULL)
  {
    list_part_t *next=element->next;
    free(element->part);
    free(element);
    element=next;
  }
}

/* Free the list but not its content */
void part_free_list_only(list_part_t *list_part)
{
  list_part_t *element;
  element=list_part;
  /*@ loop invariant valid_list_part(element); */
  while(element!=NULL)
  {
    list_part_t *next=element->next;
    free(element);
    element=next;
  }
}

int is_part_overlapping(const list_part_t *list_part)
{
  const list_part_t *element;
  /* Test overlapping
     Must be space between a primary/logical partition and a logical partition for an extended
  */
  if(list_part==NULL)
    return 0;
  element=list_part;
  /*@
    @ loop invariant \valid_read(element);
    @ loop assigns element;
    @*/
  while(1)
  {
    const partition_t *partition=element->part;
    const list_part_t *next=element->next;
    if(next==NULL)
      return 0;
    /*@ assert \valid_read(partition); */
    /*@ assert \valid_read(next->part); */
    if( (partition->part_offset + partition->part_size - 1 >= next->part->part_offset)		||
	((partition->status==STATUS_PRIM ||
	  partition->status==STATUS_PRIM_BOOT ||
	  partition->status==STATUS_LOG) &&
	 next->part->status==STATUS_LOG &&
	 partition->part_offset + partition->part_size - 1 + 1 >= next->part->part_offset))
      return 1;
    element=next;
  }
}

void  partition_reset(partition_t *partition, const arch_fnct_t *arch)
{
/* partition->lba=0; Don't reset lba, used by search_part */
  partition->part_size=(uint64_t)0;
  partition->sborg_offset=0;
  partition->sb_offset=0;
  partition->sb_size=0;
  partition->blocksize=0;
  partition->part_type_i386=P_NO_OS;
  partition->part_type_sun=PSUN_UNK;
  partition->part_type_mac=PMAC_UNK;
  partition->part_type_xbox=PXBOX_UNK;
  partition->part_type_gpt=(const efi_guid_t)GPT_ENT_TYPE_UNUSED;
#ifndef DISABLED_FOR_FRAMAC
  guid_cpy(&partition->part_uuid, &GPT_ENT_TYPE_UNUSED);
#endif
  partition->upart_type=UP_UNK;
  partition->status=STATUS_DELETED;
  partition->order=NO_ORDER;
  partition->errcode=BAD_NOERR;
  partition->fsname[0]='\0';
  partition->partname[0]='\0';
  partition->info[0]='\0';
  partition->arch=arch;
}

partition_t *partition_new(const arch_fnct_t *arch)
{
  partition_t *partition=(partition_t *)MALLOC(sizeof(*partition));
  /*@ assert \valid(partition); */
  partition_reset(partition, arch);
  /*@ assert valid_partition(partition); */
  return partition;
}

/*@
  @ requires \valid_read(disk_car);
  @ requires \valid_read(list_part);
  @ assigns \nothing;
  @*/
static unsigned int get_geometry_from_list_part_aux(const disk_t *disk_car, const list_part_t *list_part, const int verbose)
{
  const list_part_t *element;
  unsigned int nbr=0;
  /*@
    @ loop assigns element, nbr;
    @ loop invariant valid_list_part(element);
    @*/
  for(element=list_part;element!=NULL;element=element->next)
  {
    CHS_t start;
    CHS_t end;
    /*@ assert \valid_read(element); */
    /*@ assert \valid_read(element->part); */
    offset2CHS(disk_car,element->part->part_offset,&start);
    offset2CHS(disk_car,element->part->part_offset+element->part->part_size-1,&end);
    if(start.sector==1 && start.head<=1)
    {
      nbr++;
      if(end.head==disk_car->geom.heads_per_cylinder-1)
      {
	nbr++;
	/* Doesn't check if end.sector==disk_car->CHS.sector */
      }
    }
  }
#ifndef DISABLED_FOR_FRAMAC
  if(nbr>0)
  {
    log_info("get_geometry_from_list_part_aux head=%u nbr=%u\n",
	disk_car->geom.heads_per_cylinder, nbr);
    if(verbose>1)
    {
      for(element=list_part;element!=NULL;element=element->next)
      {
	CHS_t start;
	CHS_t end;
	offset2CHS(disk_car,element->part->part_offset,&start);
	offset2CHS(disk_car,element->part->part_offset+element->part->part_size-1,&end);
	if(start.sector==1 && start.head<=1 && end.head==disk_car->geom.heads_per_cylinder-1)
	{
	  log_partition(disk_car,element->part);
	}
      }
    }
  }
#endif
  return nbr;
}

unsigned int get_geometry_from_list_part(const disk_t *disk_car, const list_part_t *list_part, const int verbose)
{
  const unsigned int head_list[]={8,16,32,64,128,240,255,0};
  unsigned int best_score;
  unsigned int i;
  unsigned int heads_per_cylinder=disk_car->geom.heads_per_cylinder;
  disk_t new_disk_car;
  memcpy(&new_disk_car,disk_car,sizeof(new_disk_car));
  best_score=get_geometry_from_list_part_aux(&new_disk_car, list_part, verbose);
  /*@ loop assigns i, best_score, heads_per_cylinder, new_disk_car.geom.heads_per_cylinder; */
  for(i=0; head_list[i]!=0; i++)
  {
    unsigned int score;
    new_disk_car.geom.heads_per_cylinder=head_list[i];
    score=get_geometry_from_list_part_aux(&new_disk_car, list_part, verbose);
    if(score >= best_score)
    {
      best_score=score;
      heads_per_cylinder=new_disk_car.geom.heads_per_cylinder;
    }
  }
  return heads_per_cylinder;
}

void size_to_unit(const uint64_t disk_size, char *buffer)
{
#ifdef DISABLED_FOR_FRAMAC
  buffer[0]='\0';
#else
  if(disk_size<(uint64_t)10*1024)
    sprintf(buffer,"%u B", (unsigned)disk_size);
  else if(disk_size<(uint64_t)10*1024*1024)
    sprintf(buffer,"%u KB / %u KiB", (unsigned)(disk_size/1000), (unsigned)(disk_size/1024));
  else if(disk_size<(uint64_t)10*1024*1024*1024)
    sprintf(buffer,"%u MB / %u MiB", (unsigned)(disk_size/1000/1000), (unsigned)(disk_size/1024/1024));
  else if(disk_size<(uint64_t)10*1024*1024*1024*1024)
    sprintf(buffer,"%u GB / %u GiB", (unsigned)(disk_size/1000/1000/1000), (unsigned)(disk_size/1024/1024/1024));
  else
    sprintf(buffer,"%u TB / %u TiB", (unsigned)(disk_size/1000/1000/1000/1000), (unsigned)(disk_size/1024/1024/1024/1024));
#endif
}

void log_disk_list(list_disk_t *list_disk)
{
#ifndef DISABLED_FOR_FRAMAC
  list_disk_t *element_disk;
  /* save disk parameters to rapport */
  log_info("Hard disk list\n");
  /*@
    @ loop invariant valid_list_disk(list_disk);
    @ loop invariant valid_list_disk(element_disk);
    @*/
  for(element_disk=list_disk;element_disk!=NULL;element_disk=element_disk->next)
  {
    disk_t *disk=element_disk->disk;
    log_info("%s, sector size=%u", disk->description(disk), disk->sector_size);
    if(disk->model!=NULL)
      log_info(" - %s", disk->model);
    if(disk->serial_no!=NULL)
      log_info(", S/N:%s", disk->serial_no);
    if(disk->fw_rev!=NULL)
      log_info(", FW:%s", disk->fw_rev);
    log_info("\n");
  }
  log_info("\n");
#endif
}
