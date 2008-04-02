/*

    File: partsun.c

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
#include <ctype.h>      /* tolower */
#include "types.h"
#include "common.h"
#include "testdisk.h"
#include "fnctdsk.h"
//#include "analyse.h"
#include "lang.h"
#include "intrf.h"
#include "intrfn.h"
#include "chgtype.h"
#include "sun.h"
#include "swap.h"
#include "bsd.h"
#include "fat.h"
#include "ntfs.h"
#include "ext2.h"
#include "rfs.h"
#include "lvm.h"
#include "md.h"
#include "jfs_superblock.h"
#include "jfs.h"
#include "savehdr.h"
#include "cramfs.h"
#include "xfs.h"
#include "ufs.h"
#include "log.h"

static int check_part_sun(disk_t *disk_car, const int verbose,partition_t *partition,const int saveheader);
static int get_geometry_from_sunmbr(const unsigned char *buffer, const int verbose, CHS_t *geometry);
static list_part_t *read_part_sun(disk_t *disk_car, const int verbose, const int saveheader);
static int write_part_sun(disk_t *disk_car, const list_part_t *list_part, const int ro , const int verbose, const int align);
static list_part_t *init_part_order_sun(const disk_t *disk_car, list_part_t *list_part);
static list_part_t *add_partition_sun(disk_t *disk_car,list_part_t *list_part, const int verbose, char **current_cmd);
static void set_next_status_sun(const disk_t *disk_car, partition_t *partition);
static int test_structure_sun(list_part_t *list_part);
static int set_part_type_sun(partition_t *partition, unsigned int part_type_sun);
static int is_part_known_sun(const partition_t *partition);
static void init_structure_sun(const disk_t *disk_car,list_part_t *list_part, const int verbose);
static const char *get_partition_typename_sun(const partition_t *partition);
static const char *get_partition_typename_sun_aux(const unsigned int part_type_sun);
static unsigned int get_part_type_sun(const partition_t *partition);

static const struct systypes sun_sys_types[] = {
  {0x00,	 "Empty"        },
  {PSUN_BOOT,	 "Boot"         },
  {PSUN_ROOT,	 "SunOS root"   },
  {PSUN_SWAP,	 "SunOS swap"   },
  {PSUN_USR,	 "SunOS usr"    },
  {PSUN_WHOLE_DISK,	 "Whole disk"   },
  {PSUN_STAND,	 "SunOS stand"  },
  {PSUN_VAR,	 "SunOS var"    },
  {PSUN_HOME,	 "SunOS home"   },
  {PSUN_ALT,	 "SunOS alt."   },
  {PSUN_CACHEFS, "SunOS cachefs"},
  {PSUN_LINSWAP, "Linux swap"   },
  {PSUN_LINUX,	 "Linux native" },
  {PSUN_LVM,	 "Linux LVM"    },
  {PSUN_RAID,	 "Linux raid autodetect" },
  {0, NULL }
};

arch_fnct_t arch_sun=
{
  .part_name="Sun",
  .part_name_option="partition_sun",
  .msg_part_type="                P=Primary  D=Deleted",
  .read_part=read_part_sun,
  .write_part=write_part_sun,
  .init_part_order=init_part_order_sun,
  .get_geometry_from_mbr=get_geometry_from_sunmbr,
  .check_part=check_part_sun,
  .write_MBR_code=NULL,
  .add_partition=add_partition_sun,
  .set_prev_status=set_next_status_sun,
  .set_next_status=set_next_status_sun,
  .test_structure=test_structure_sun,
  .set_part_type=set_part_type_sun,
  .is_part_known=is_part_known_sun,
  .init_structure=init_structure_sun,
  .erase_list_part=NULL,
  .get_partition_typename=get_partition_typename_sun,
  .get_part_type=get_part_type_sun
};

static unsigned int get_part_type_sun(const partition_t *partition)
{
  return partition->part_type_sun;
}

int get_geometry_from_sunmbr(const unsigned char *buffer, const int verbose, CHS_t *geometry)
{
  const sun_partition *sunlabel=(const sun_partition*)buffer;
  if(verbose>1)
  {
    log_trace("get_geometry_from_sunmbr\n");
  }
  geometry->cylinder=0;
  geometry->head=be16(sunlabel->ntrks)-1;
  geometry->sector=be16(sunlabel->nsect);
  if(geometry->sector>0)
  {
    log_info("Geometry from SUN MBR: head=%u sector=%u\n",geometry->head+1,geometry->sector);
  }
  return 0;
}

list_part_t *read_part_sun(disk_t *disk_car, const int verbose, const int saveheader)
{
  unsigned int i;
  sun_partition *sunlabel;
  list_part_t *new_list_part=NULL;
  unsigned char *buffer=MALLOC(disk_car->sector_size);
  screen_buffer_to_log();
  sunlabel=(sun_partition*)buffer;
  if(disk_car->read(disk_car,DEFAULT_SECTOR_SIZE, buffer, (uint64_t)0))
  {
    screen_buffer_add( msg_PART_RD_ERR);
    free(buffer);
    return NULL;
  }
  if (be16(sunlabel->magic) != SUN_LABEL_MAGIC)
  {
    screen_buffer_add("Bad SUN partition\n");
    free(buffer);
    return NULL;
  }
  for(i=0;i<8;i++)
  {
     if (sunlabel->partitions[i].num_sectors > 0
	 && sunlabel->infos[i].id > 0
	 && sunlabel->infos[i].id != PSUN_WHOLE_DISK)
     {
       int insert_error=0;
       partition_t *new_partition=partition_new(&arch_sun);
       new_partition->order=i;
       new_partition->part_type_sun=sunlabel->infos[i].id;
       new_partition->part_offset=be32(sunlabel->partitions[i].start_cylinder)*be16(sunlabel->ntrks)*be16(sunlabel->nsect)*disk_car->sector_size;
       new_partition->part_size=(uint64_t)be32(sunlabel->partitions[i].num_sectors)*disk_car->sector_size;
       new_partition->status=STATUS_PRIM;
       disk_car->arch->check_part(disk_car,verbose,new_partition,saveheader);
       aff_part_buffer(AFF_PART_ORDER|AFF_PART_STATUS,disk_car,new_partition);
       new_list_part=insert_new_partition(new_list_part, new_partition, 0, &insert_error);
       if(insert_error>0)
	 free(new_partition);
     }
  }
  free(buffer);
  return new_list_part;
}

static int write_part_sun(disk_t *disk_car, const list_part_t *list_part, const int ro, const int verbose, const int align)
{ /* TODO: Implement it */
  if(ro==0)
  {
    not_implemented("write_part_sun");
  }
  return 0;
}

static list_part_t *init_part_order_sun(const disk_t *disk_car, list_part_t *list_part)
{
  int insert_error=0;
  int nbr_prim=0;
  partition_t *new_partition;
  list_part_t *element;
  for(element=list_part;element!=NULL;element=element->next)
  {
    switch(element->part->status)
    {
      case STATUS_PRIM:
      case STATUS_PRIM_BOOT:
	if(nbr_prim==2)
	  nbr_prim++;
	element->part->order=nbr_prim++;
	break;
      default:
	log_critical("init_part_order_sun: severe error\n");
	break;
    }
  }
  new_partition=partition_new(&arch_sun);
  new_partition->part_offset=0;
  new_partition->part_size=disk_car->disk_size;
  new_partition->status=STATUS_PRIM;
  new_partition->part_type_sun=PSUN_WHOLE_DISK;
  new_partition->order=2;
  list_part=insert_new_partition(list_part, new_partition, 0, &insert_error);
  if(insert_error>0)
    free(new_partition);
  return list_part;
}

static list_part_t *add_partition_sun_cli(disk_t *disk_car,list_part_t *list_part, const int verbose, char **current_cmd)
{
  CHS_t start,end;
  partition_t *new_partition=partition_new(&arch_sun);
  start.cylinder=0;
  start.head=0;
  start.sector=1;
  end.cylinder=disk_car->CHS.cylinder;
  end.head=disk_car->CHS.head;
  end.sector=disk_car->CHS.sector;
  while(*current_cmd[0]==',')
    (*current_cmd)++;
  while(1)
  {
    if(strncmp(*current_cmd,"c,",2)==0)
    {
      (*current_cmd)+=2;
      start.cylinder=ask_number_cli(current_cmd, start.cylinder,0,disk_car->CHS.cylinder,"Enter the starting cylinder ");
    }
    else if(strncmp(*current_cmd,"C,",2)==0)
    {
      (*current_cmd)+=2;
      end.cylinder=ask_number_cli(current_cmd, end.cylinder,start.cylinder,disk_car->CHS.cylinder,"Enter the ending cylinder ");
    }
    else if(strncmp(*current_cmd,"T,",2)==0)
    {
      (*current_cmd)+=2;
      change_part_type(disk_car,new_partition,current_cmd);
    }
    else if((CHS2offset(disk_car,&end)>new_partition->part_offset) &&
      new_partition->part_type_sun>0)
    {
      int insert_error=0;
      list_part_t *new_list_part=insert_new_partition(list_part, new_partition, 0, &insert_error);
      if(insert_error>0)
      {
	free(new_partition);
	return new_list_part;
      }
      new_partition->status=STATUS_PRIM;
      if(test_structure_sun(list_part)!=0)
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
static list_part_t *add_partition_sun_ncurses(disk_t *disk_car,list_part_t *list_part, const int verbose, char **current_cmd)
{
  CHS_t start,end;
  partition_t *new_partition=partition_new(&arch_sun);
  int position=0;
  start.cylinder=0;
  start.head=0;
  start.sector=1;
  end.cylinder=disk_car->CHS.cylinder;
  end.head=disk_car->CHS.head;
  end.sector=disk_car->CHS.sector;
  {
    int done = FALSE;
    while (done==FALSE) {
      int command;
      static struct MenuItem menuGeometry[]=
      {
	{ 'c', "Cylinders", 	"Change starting cylinder" },
	{ 'C', "Cylinders", 	"Change ending cylinder" },
	{ 'T' ,"Type",		"Change partition type"},
	{ 'd', "Done", "" },
	{ 0, NULL, NULL }
      };
      aff_copy(stdscr);
      wmove(stdscr,4,0);
      wprintw(stdscr,"%s",disk_car->description(disk_car));
      new_partition->part_offset=CHS2offset(disk_car,&start);
      new_partition->part_size=CHS2offset(disk_car,&end) - new_partition->part_offset + disk_car->sector_size;
      wmove(stdscr,10, 0);
      wclrtoeol(stdscr);
      aff_part(stdscr, AFF_PART_BASE, disk_car, new_partition);
      wmove(stdscr,INTER_GEOM_Y, INTER_GEOM_X);
      wclrtoeol(stdscr);
      wrefresh(stdscr);
      command=wmenuSimple(stdscr,menuGeometry, position);
      switch (command) {
	case 'c':
	  wmove(stdscr, INTER_GEOM_Y, INTER_GEOM_X);
	  start.cylinder=ask_number(start.cylinder,0,disk_car->CHS.cylinder,"Enter the starting cylinder ");
	  position=1;
	  break;
	case 'C':
	  wmove(stdscr, INTER_GEOM_Y, INTER_GEOM_X);
	  end.cylinder=ask_number(end.cylinder,start.cylinder,disk_car->CHS.cylinder,"Enter the ending cylinder ");
	  position=2;
	  break;
	case 'T':
	case 't':
	  change_part_type(disk_car, new_partition, current_cmd);
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
  }
  if((CHS2offset(disk_car,&end)>new_partition->part_offset) &&
      new_partition->part_type_sun>0)
  {
    int insert_error=0;
    list_part_t *new_list_part=insert_new_partition(list_part, new_partition, 0, &insert_error);
    if(insert_error>0)
    {
      free(new_partition);
      return new_list_part;
    }
    new_partition->status=STATUS_PRIM;
    if(test_structure_sun(list_part)!=0)
      new_partition->status=STATUS_DELETED;
    return new_list_part;
  }
  free(new_partition);
  return list_part;
}
#endif

static list_part_t *add_partition_sun(disk_t *disk_car,list_part_t *list_part, const int verbose, char **current_cmd)
{
  if(*current_cmd!=NULL)
    return add_partition_sun_cli(disk_car, list_part, verbose, current_cmd);
#ifdef HAVE_NCURSES
  return add_partition_sun_ncurses(disk_car, list_part, verbose, current_cmd);
#else
  return list_part;
#endif
}

static void set_next_status_sun(const disk_t *disk_car, partition_t *partition)
{
  if(partition->status==STATUS_DELETED)
    partition->status=STATUS_PRIM;
  else
    partition->status=STATUS_DELETED;
}

static int test_structure_sun(list_part_t *list_part)
{ /* Return 1 if bad*/
  list_part_t *new_list_part=NULL;
  int res;
  new_list_part=gen_sorted_partition_list(list_part);
  res=is_part_overlapping(new_list_part);
  part_free_list_only(new_list_part);
  return res;
}

static int set_part_type_sun(partition_t *partition, unsigned int part_type_sun)
{
  if(part_type_sun>0 && part_type_sun <= 255)
  {
    partition->part_type_sun=part_type_sun;
    return 0;
  }
  return 1;
}

static int is_part_known_sun(const partition_t *partition)
{
  return (partition->part_type_sun!=PSUN_UNK);
}

static void init_structure_sun(const disk_t *disk_car,list_part_t *list_part, const int verbose)
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

static int check_part_sun(disk_t *disk_car,const int verbose,partition_t *partition, const int saveheader)
{
  int ret=0;
  switch(partition->part_type_sun)
  {
    case PSUN_BOOT:
    case PSUN_ROOT:
    case PSUN_USR:
    case PSUN_STAND:
    case PSUN_VAR:
    case PSUN_HOME:
    case PSUN_ALT:
      ret=check_ufs(disk_car,partition,verbose);
      break;
    case PSUN_LINUX:
      ret=check_JFS(disk_car,partition,verbose);
      if(ret!=0)
      {
	ret=check_rfs(disk_car,partition,verbose);
      }
      if(ret!=0)
      {
	ret=check_EXT2(disk_car,partition,verbose);
      }
      if(ret!=0)
      {
	ret=check_cramfs(disk_car,partition,verbose);
      }
      if(ret!=0)
      {
	ret=check_xfs(disk_car,partition,verbose);
      }
      if(ret!=0)
      { screen_buffer_add("No EXT2, JFS, Reiser, cramfs or XFS marker\n"); }
      break;

    case PSUN_LINSWAP:
      ret=check_Linux_SWAP(disk_car,partition,verbose);
      break;
    default:
      if(verbose>0)
      {
	log_info("check_part_sun %u type %02X: no test\n",partition->order,partition->part_type_sun);
      }
      break;
  }
  if(ret!=0)
  {
    log_error("check_part_sun failed for partition type %02X\n", partition->part_type_sun);
    aff_part_buffer(AFF_PART_ORDER|AFF_PART_STATUS,disk_car,partition);
    if(saveheader>0)
    {
      save_header(disk_car,partition,verbose);
    }
  }
  return ret;
}

static const char *get_partition_typename_sun_aux(const unsigned int part_type_sun)
{
  int i;
  for (i=0; sun_sys_types[i].name!=NULL; i++)
    if (sun_sys_types[i].part_type == part_type_sun)
      return sun_sys_types[i].name;
  return NULL;
}

static const char *get_partition_typename_sun(const partition_t *partition)
{
  return get_partition_typename_sun_aux(partition->part_type_sun);
}
