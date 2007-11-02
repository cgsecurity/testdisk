/*

    File: partmac.c

    Copyright (C) 1998-2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include "lang.h"
#include "intrf.h"
#include "intrfn.h"
#include "chgtype.h"
#include "partmac.h"
#include "savehdr.h"
#include "cramfs.h"
#include "ext2.h"
#include "hfs.h"
#include "hfsp.h"
#include "jfs_superblock.h"
#include "jfs.h"
#include "rfs.h"
#include "xfs.h"
#include "log.h"

static int check_part_mac(disk_t *disk_car, const int verbose,partition_t *partition,const int saveheader);
static list_part_t *read_part_mac(disk_t *disk_car, const int verbose, const int saveheader);
static int write_part_mac(disk_t *disk_car, const list_part_t *list_part, const int ro , const int verbose, const int align);
static list_part_t *init_part_order_mac(const disk_t *disk_car, list_part_t *list_part);
static list_part_t *add_partition_mac(disk_t *disk_car,list_part_t *list_part, const int verbose, char **current_cmd);
static void set_next_status_mac(const disk_t *disk_car, partition_t *partition);
static int test_structure_mac(list_part_t *list_part);
static int set_part_type_mac(partition_t *partition, unsigned int part_type_mac);
static int is_part_known_mac(const partition_t *partition);
static void init_structure_mac(const disk_t *disk_car,list_part_t *list_part, const int verbose);
static const char *get_partition_typename_mac(const partition_t *partition);
static const char *get_partition_typename_mac_aux(const unsigned int part_type_mac);
static unsigned int get_part_type_mac(const partition_t *partition);

static const struct systypes mac_sys_types[] = {
  { PMAC_DRIVER43,  "Driver43"		},
  { PMAC_DRIVERATA,  "Driver_ATA"		},
  { PMAC_DRIVERIO,  "Driver_IOKit"	},
  { PMAC_FREE,  "Free"		},
  { PMAC_FWDRIVER,  "FWDriver"		},
  { PMAC_SWAP, "Swap"		},
  { PMAC_LINUX, "Linux"		},
  { PMAC_HFS, "HFS"		},
  { PMAC_MAP,  "partition_map"	},
  { PMAC_PATCHES,  "Patches"		},
  { PMAC_UNK,  "Unknown"		},
  { PMAC_NewWorld,  "NewWorld"		},
  { PMAC_DRIVER, "Driver"		},
  { PMAC_MFS, "MFS"		},
  { PMAC_PRODOS, "ProDOS"		},
  { PMAC_UNK,		NULL }
};

arch_fnct_t arch_mac=
{
  .part_name="Mac",
  .part_name_option="partition_mac",
  .msg_part_type="                P=Primary  D=Deleted",
  .read_part=read_part_mac,
  .write_part=write_part_mac,
  .init_part_order=init_part_order_mac,
  .get_geometry_from_mbr=NULL,
  .check_part=check_part_mac,
  .write_MBR_code=NULL,
  .add_partition=add_partition_mac,
  .set_prev_status=set_next_status_mac,
  .set_next_status=set_next_status_mac,
  .test_structure=test_structure_mac,
  .set_part_type=set_part_type_mac,
  .is_part_known=is_part_known_mac,
  .init_structure=init_structure_mac,
  .erase_list_part=NULL,
  .get_partition_typename=get_partition_typename_mac,
  .get_part_type=get_part_type_mac
};

static unsigned int get_part_type_mac(const partition_t *partition)
{
  return partition->part_type_mac;
}

list_part_t *read_part_mac(disk_t *disk_car, const int verbose, const int saveheader)
{
  unsigned char buffer[DEFAULT_SECTOR_SIZE];
  list_part_t *new_list_part=NULL;
  unsigned int i;
  unsigned int limit=1;
  aff_buffer(BUFFER_RESET,"Q");
  if(disk_car->read(disk_car,sizeof(buffer), &buffer, 0)!=0)
    return NULL;
  {
    mac_Block0 *maclabel=(mac_Block0*)&buffer;
    if (be16(maclabel->sbSig) != BLOCK0_SIGNATURE)
    {
      aff_buffer(BUFFER_ADD,"\nBad MAC partition, invalid block0 signature\n");
      return NULL;
    }
  }
  for(i=1;i<=limit;i++)
  {
    mac_DPME *dpme=(mac_DPME *)buffer;
    if(disk_car->read(disk_car,sizeof(buffer), &buffer, (uint64_t)i*PBLOCK_SIZE)!=0)
      return new_list_part;
    if(be16(dpme->dpme_signature) != DPME_SIGNATURE)
    {
      aff_buffer(BUFFER_ADD,"\nread_part_mac: bad DPME signature");
      return new_list_part;
    }
    {
      int insert_error=0;
      partition_t *new_partition=partition_new(&arch_mac);
      new_partition->order=i;
      if (strcmp(dpme->dpme_type, "Apple_UNIX_SVR2")==0)
      {
	if (!strcmp(dpme->dpme_name, "Swap") || !strcmp(dpme->dpme_name, "swap"))
	  new_partition->part_type_mac=PMAC_SWAP;
	else
	  new_partition->part_type_mac=PMAC_LINUX;
      }
      else if (strcmp(dpme->dpme_type, "Apple_Bootstrap")==0)
	new_partition->part_type_mac=PMAC_NewWorld;
      else if (strcmp(dpme->dpme_type, "Apple_Scratch")==0)
	new_partition->part_type_mac=PMAC_SWAP;
      else if(strcmp(dpme->dpme_type,"Apple_Driver")==0)
	new_partition->part_type_mac=PMAC_DRIVER;
      else if(strcmp(dpme->dpme_type,"Apple_Driver43")==0)
	new_partition->part_type_mac=PMAC_DRIVER43;
      else if(strcmp(dpme->dpme_type,"Apple_Driver_ATA")==0)
	new_partition->part_type_mac=PMAC_DRIVERATA;
      else if(strcmp(dpme->dpme_type,"Apple_Driver_IOKit")==0)
	new_partition->part_type_mac=PMAC_DRIVERIO;
      else if(strcmp(dpme->dpme_type,"Apple_Free")==0)
	new_partition->part_type_mac=PMAC_FREE;
      else if(strcmp(dpme->dpme_type,"Apple_FWDriver")==0)
	new_partition->part_type_mac=PMAC_FWDRIVER;
      else if(strcmp(dpme->dpme_type,"Apple_partition_map")==0)
	new_partition->part_type_mac=PMAC_MAP;
      else if(strcmp(dpme->dpme_type,"Apple_Patches")==0)
	new_partition->part_type_mac=PMAC_PATCHES;
      else if(strcmp(dpme->dpme_type,"Apple_HFS")==0)
	new_partition->part_type_mac=PMAC_HFS;
      else if(strcmp(dpme->dpme_type,"Apple_MFS")==0)
	new_partition->part_type_mac=PMAC_MFS;
      else if(strcmp(dpme->dpme_type,"Apple_PRODOS")==0)
	new_partition->part_type_mac=PMAC_PRODOS;
      else if(strcmp(dpme->dpme_type,"DOS_FAT_32")==0)
	new_partition->part_type_mac=PMAC_FAT32;
      else
      {
	new_partition->part_type_mac=PMAC_UNK;
	log_error("%s\n",dpme->dpme_type);
      }
      new_partition->part_offset=(uint64_t)be32(dpme->dpme_pblock_start)*PBLOCK_SIZE;
      new_partition->part_size=(uint64_t)be32(dpme->dpme_pblocks)*PBLOCK_SIZE;
      new_partition->status=STATUS_PRIM;
      new_partition->arch->check_part(disk_car,verbose,new_partition,saveheader);
      aff_part_buffer(AFF_PART_ORDER,disk_car,new_partition);
      new_list_part=insert_new_partition(new_list_part, new_partition, 0, &insert_error);
      if(insert_error>0)
	free(new_partition);
    }
    if(i==1)
    {
      limit=be32(dpme->dpme_map_entries);
    }
  }
  return new_list_part;
}

#ifdef HAVE_NCURSES
static void write_part_mac_warning_ncurses(void)
{
  /* not_implemented("write_part_mac"); */
  WINDOW *window=newwin(0,0,0,0);	/* full screen */
  aff_copy(window);
  wmove(window,7,0);
  wprintw(window,"Function write_part_mac not implemented");
  log_warning("Function write_part_mac not implemented\n");
  wmove(window,8,0);
  wprintw(window,"Use pdisk to recreate the missing partition");
  wmove(window,9,0);
  wprintw(window,"using values displayed by TestDisk");
  wmove(window,22,0);
  wattrset(window, A_REVERSE);
  wprintw(window,"[ Abort ]");
  wattroff(window, A_REVERSE);
  wrefresh(window);
  while(wgetch(window)==ERR);
  delwin(window);
  (void) clearok(stdscr, TRUE);
#ifdef HAVE_TOUCHWIN
  touchwin(stdscr);
#endif
}
#endif

static int write_part_mac(disk_t *disk_car, const list_part_t *list_part, const int ro, const int verbose, const int align)
{ /* TODO: Implement it */
  if(ro==0)
  {
#ifdef HAVE_NCURSES
    write_part_mac_warning_ncurses();
#endif
  }
  return 0;
}

static list_part_t *init_part_order_mac(const disk_t *disk_car, list_part_t *list_part)
{
  return list_part;
}

static list_part_t *add_partition_mac_cli(disk_t *disk_car,list_part_t *list_part, const int verbose, char **current_cmd)
{
  partition_t *new_partition=partition_new(&arch_mac);
  new_partition->part_offset=disk_car->sector_size;
  new_partition->part_size=disk_car->disk_size-disk_car->sector_size;
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
	  4096/disk_car->sector_size,
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
    else if(new_partition->part_size>0 && new_partition->part_type_mac>0)
    {
      int insert_error=0;
      list_part_t *new_list_part=insert_new_partition(list_part, new_partition, 0, &insert_error);
      if(insert_error>0)
      {
	free(new_partition);
	return new_list_part;
      }
      new_partition->status=STATUS_PRIM;
      if(test_structure_mac(list_part)!=0)
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
static list_part_t *add_partition_mac_ncurses(disk_t *disk_car,list_part_t *list_part, const int verbose, char **current_cmd)
{
  int position=0;
  int done = FALSE;
  partition_t *new_partition=partition_new(&arch_mac);
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
    wprintw(stdscr,"%s",disk_car->description(disk_car));
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
	      4096/disk_car->sector_size,
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
  if(new_partition->part_size>0 && new_partition->part_type_mac>0)
  {
    int insert_error=0;
    list_part_t *new_list_part=insert_new_partition(list_part, new_partition, 0, &insert_error);
    if(insert_error>0)
    {
      free(new_partition);
      return new_list_part;
    }
    new_partition->status=STATUS_PRIM;
    if(test_structure_mac(list_part)!=0)
      new_partition->status=STATUS_DELETED;
    return new_list_part;
  }
  free(new_partition);
  return list_part;
}
#endif

static list_part_t *add_partition_mac(disk_t *disk_car,list_part_t *list_part, const int verbose, char **current_cmd)
{
  if(*current_cmd!=NULL)
    return add_partition_mac_cli(disk_car, list_part, verbose, current_cmd);
#ifdef HAVE_NCURSES
  return add_partition_mac_ncurses(disk_car, list_part, verbose, current_cmd);
#else
  return list_part;
#endif
}

static void set_next_status_mac(const disk_t *disk_car, partition_t *partition)
{
  if(partition->status==STATUS_DELETED)
    partition->status=STATUS_PRIM;
  else
    partition->status=STATUS_DELETED;
}

static int test_structure_mac(list_part_t *list_part)
{ /* Return 1 if bad*/
  list_part_t *new_list_part;
  int res;
  new_list_part=gen_sorted_partition_list(list_part);
  res=is_part_overlapping(new_list_part);
  part_free_list_only(new_list_part);
  return res;
}

static int set_part_type_mac(partition_t *partition, unsigned int part_type_mac)
{
  if(part_type_mac>0 && part_type_mac <= 255)
  {
    partition->part_type_mac=part_type_mac;
    return 0;
  }
  return 1;
}

static int is_part_known_mac(const partition_t *partition)
{
  return (partition->part_type_mac!=PMAC_UNK);
}

static void init_structure_mac(const disk_t *disk_car,list_part_t *list_part, const int verbose)
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

static int check_part_mac(disk_t *disk_car,const int verbose,partition_t *partition, const int saveheader)
{
  int ret=0;
  switch(partition->part_type_mac)
  {
    case PMAC_DRIVER43:
    case PMAC_DRIVERATA:
    case PMAC_DRIVERIO:
    case PMAC_FREE:
    case PMAC_FWDRIVER:
    case PMAC_SWAP:
    case PMAC_MAP:
    case PMAC_PATCHES:
    case PMAC_UNK:
    case PMAC_NewWorld:
    case PMAC_DRIVER:
    case PMAC_MFS:
    case PMAC_PRODOS:
      break;
    case PMAC_LINUX:
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
      { aff_buffer(BUFFER_ADD,"No EXT2, JFS, Reiser, cramfs or XFS marker\n"); }
      break;
    case PMAC_HFS:
      ret=check_HFSP(disk_car,partition,verbose);
      if(ret!=0)
      {
	ret=check_HFS(disk_car,partition,verbose);
      }
      break;
    case PMAC_FAT32:
      ret=check_FAT(disk_car, partition, verbose);
      break;
    default:
      if(verbose>0)
      {
	log_info("check_part_mac %u type %02X: no test\n",partition->order,partition->part_type_mac);
      }
      break;
  }
  if(ret!=0)
  {
    log_error("check_part_mac failed for partition type %02X\n", partition->part_type_mac);
    aff_part_buffer(AFF_PART_ORDER,disk_car,partition);
    if(saveheader>0)
    {
      save_header(disk_car,partition,verbose);
    }
  }
  return ret;
}

static const char *get_partition_typename_mac_aux(const unsigned int part_type_mac)
{
  int i;
  for (i=0; mac_sys_types[i].name!=NULL; i++)
    if (mac_sys_types[i].part_type == part_type_mac)
      return mac_sys_types[i].name;
  return NULL;
}

static const char *get_partition_typename_mac(const partition_t *partition)
{
  return get_partition_typename_mac_aux(partition->part_type_mac);
}
