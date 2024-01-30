/*

    File: godmode.c

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
 
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <assert.h>
#include "types.h"
#include "common.h"
#include "fnctdsk.h"
#include "analyse.h"
#include "lang.h"
#include "godmode.h"
#include "intrface.h"
#include "ext2.h"
#include "intrf.h"
#include "intrfn.h"
#include "md.h"
#include "ntfs.h"
#include "next.h"
#include "tpartwr.h"
#include "log.h"
#include "log_part.h"
#include "fat32.h"
#include "tntfs.h"
#include "thfs.h"
#include "partgpt.h"
#include "partmacn.h"

#define RO 1
#define RW 0
#define MAX_SEARCH_LOCATION 1024
extern const arch_fnct_t arch_none;
extern const arch_fnct_t arch_gpt;
extern const arch_fnct_t arch_humax;
extern const arch_fnct_t arch_i386;
extern const arch_fnct_t arch_mac;
extern const arch_fnct_t arch_sun;
extern const arch_fnct_t arch_xbox;
#ifdef HAVE_NCURSES
#define ANALYSE_X	0
#define ANALYSE_Y	5
#define INTER_BAD_PART	10
#endif

/* Optimization */
static inline void offset2CHS_inline(const disk_t *disk_car,const uint64_t offset, CHS_t*CHS)
{
  uint64_t pos=offset/disk_car->sector_size;
  CHS->sector=(pos%disk_car->geom.sectors_per_head)+1;
  pos/=disk_car->geom.sectors_per_head;
  CHS->head=pos%disk_car->geom.heads_per_cylinder;
  CHS->cylinder=pos/disk_car->geom.heads_per_cylinder;
}

static inline uint64_t CHS2offset_inline(const disk_t *disk_car,const CHS_t*CHS)
{
  return (((uint64_t)CHS->cylinder*disk_car->geom.heads_per_cylinder+CHS->head)*disk_car->geom.sectors_per_head+CHS->sector-1)*disk_car->sector_size;
}
/* Optimization end */

static unsigned int get_location_boundary(const disk_t *disk)
{
  if(disk->arch==&arch_mac)
    return 4096;
  else if(disk->arch==&arch_sun)
    return disk->geom.heads_per_cylinder * disk->geom.sectors_per_head * disk->sector_size;
  return disk->sector_size;
}

static unsigned int align_structure_aux(const uint64_t offset, const disk_t *disk)
{
  unsigned int tmp;
  if(offset % (1024*1024) == 0)
    return 1024*1024;
  tmp=disk->geom.heads_per_cylinder * disk->geom.sectors_per_head * disk->sector_size;
  if(offset % tmp == 0 || offset % tmp == (uint64_t)disk->geom.sectors_per_head * disk->sector_size)
    return tmp;
  tmp= disk->geom.sectors_per_head * disk->sector_size;
  if(offset % tmp == 0)
    return tmp;
  return disk->sector_size;
}

static void align_structure_i386(list_part_t *list_part, const disk_t *disk, const unsigned int align)
{
  list_part_t *element;
  for(element=list_part; element!=NULL; element=element->next)
  {
    uint64_t partition_end;
    unsigned int location_boundary;
    const partition_t *part=element->part;
    if(align==0)
      location_boundary=disk->sector_size;
    else
      location_boundary=align_structure_aux(part->part_offset, disk);
    partition_end=(part->part_offset+part->part_size-1+location_boundary-1)/location_boundary*location_boundary-1;
    if(align!=0 && element->next!=NULL)
    {
      const partition_t *next_partition=element->next->part;
      if( next_partition->part_offset > part->part_offset + part->part_size -1 &&
	  next_partition->part_offset <= partition_end)
      {
	/* Do not align the partition if it overlaps the next one because of that */
	location_boundary=disk->sector_size;
	partition_end=(part->part_offset + part->part_size-1+location_boundary-1)/location_boundary*location_boundary-1;
      }
    }
    element->part->part_size=partition_end - part->part_offset+1;
  }
}

static void align_structure(list_part_t *list_part, const disk_t *disk, const unsigned int align)
{
  if(disk->arch==&arch_i386)
  {
    align_structure_i386(list_part, disk, align);
    return ;
  }
  {
    list_part_t *element;
    const unsigned int location_boundary=get_location_boundary(disk);
    for(element=list_part; element!=NULL; element=element->next)
    {
      const uint64_t partition_end=(element->part->part_offset+element->part->part_size-1+location_boundary-1)/location_boundary*location_boundary-1;
      element->part->part_size=partition_end-element->part->part_offset+1;
    }
  }
}

void only_one_bootable( list_part_t *list_part, const list_part_t *part_boot)
{
  list_part_t *element;
  if(part_boot->part->status==STATUS_PRIM_BOOT)
    for(element=list_part;element!=NULL;element=element->next)
    {
      if((element!=part_boot)&&(element->part->status==STATUS_PRIM_BOOT))
	element->part->status=STATUS_PRIM;
    }
}

#ifdef HAVE_NCURSES
static int interface_part_bad_ncurses(disk_t *disk_car, list_part_t *list_part)
{
  int quit=0;
  int offset=0;
  int pos_num=0;
  uint64_t disk_size=disk_car->disk_size;
  list_part_t *pos=list_part;
  if(list_part==NULL)
    return 1;
  {
    list_part_t *parts;
    for(parts=list_part;parts!=NULL;parts=parts->next)
    {
      if(disk_size<parts->part->part_offset+parts->part->part_size-1)
	disk_size=parts->part->part_offset+parts->part->part_size-1;
    }
  }
  aff_copy(stdscr);
  wmove(stdscr,4,0);
  wprintw(stdscr,"%s",disk_car->description(disk_car));
  wmove(stdscr,6,0);
  {
    char buffer_disk_size[100];
    char buffer_disk_size_found[100];
    size_to_unit(disk_car->disk_size, buffer_disk_size);
    size_to_unit(disk_size, buffer_disk_size_found);
    wprintw(stdscr,"The hard disk (%s) seems too small! (< %s)",
	buffer_disk_size, buffer_disk_size_found);
  }
  wmove(stdscr,7,0);
  wprintw(stdscr,"Check the hard disk size: HD jumper settings, BIOS detection...");
#if defined(__CYGWIN__) || defined(__MINGW32__)
  if(disk_car->disk_size<=((uint64_t)1<<(28-1)) && disk_size>=((uint64_t)1<<(28-1)))
  {
    wmove(stdscr,8,0);
    wprintw(stdscr,"Hint: update Windows to support LBA48 (minimum: W2K SP4 or XP SP1)");
  }
#endif
  wmove(stdscr,9,0);
  if(list_part->next==NULL)
  {
    wprintw(stdscr,"The following partition can't be recovered:");
  } else {
    wprintw(stdscr,"The following partitions can't be recovered:");
  }
  mvwaddstr(stdscr,10,0,msg_PART_HEADER);
  wmove(stdscr,22,0);
  wattrset(stdscr, A_REVERSE);
  wprintw(stdscr,"[ Continue ]");
  wattroff(stdscr, A_REVERSE);
  do
  {
    int i;
    int car;
    list_part_t *parts;
    for(i=0,parts=list_part;(parts!=NULL) && (i<offset);parts=parts->next,i++);
    for(i=offset;(parts!=NULL) &&((i-offset)<INTER_BAD_PART);i++,parts=parts->next)
    {
      wmove(stdscr,11+i-offset,0);
      wclrtoeol(stdscr);	/* before addstr for BSD compatibility */
      if(parts==pos)
      {
	char buffer_part_size[100];
	wattrset(stdscr, A_REVERSE);
	waddstr(stdscr, ">");
	aff_part(stdscr, AFF_PART_BASE, disk_car, parts->part);
	wattroff(stdscr, A_REVERSE);
	wmove(stdscr,23,0);
	wclrtoeol(stdscr);	/* before addstr for BSD compatibility */
	if(parts->part->info[0]!='\0')
	{
	  wprintw(stdscr,"%s, ",parts->part->info);
	}
	size_to_unit(parts->part->part_size, buffer_part_size);
	wprintw(stdscr,"%s", buffer_part_size);
      } else
      {
	waddstr(stdscr, " ");
	aff_part(stdscr, AFF_PART_BASE, disk_car, parts->part);
      }
    }
    wrefresh(stdscr);
    car=wgetch(stdscr);
    switch(car)
    {
      case 'q':
      case '\r':
      case '\n':
      case KEY_ENTER:
#ifdef PADENTER
      case PADENTER:
#endif
      case 'M':
	quit=1;
	break;
      case KEY_UP:
	if(pos->prev!=NULL)
	{
	  pos=pos->prev;
	  pos_num--;
	}
	break;
      case KEY_DOWN:
	if(pos->next!=NULL)
	{
	  pos=pos->next;
	  pos_num++;
	}
	break;
      case KEY_PPAGE:
	for(i=0; i<INTER_BAD_PART && pos->prev!=NULL; i++)
	{
	  pos=pos->prev;
	  pos_num--;
	}
	break;
      case KEY_NPAGE:
	for(i=0; i<INTER_BAD_PART && pos->next!=NULL; i++)
	{
	  pos=pos->next;
	  pos_num++;
	}
	break;
      default:
	break;
    }
    if(pos_num<offset)
      offset=pos_num;
    if(pos_num>=offset+INTER_BAD_PART)
      offset=pos_num-INTER_BAD_PART+1;
  } while(quit==0);
  return 0;
}
#endif

static int interface_part_bad_log(disk_t *disk_car, list_part_t *list_part)
{
  uint64_t disk_size=disk_car->disk_size;
  if(list_part==NULL)
    return 1;
  {
    list_part_t *parts;
    for(parts=list_part;parts!=NULL;parts=parts->next)
    {
      if(disk_size<parts->part->part_offset+parts->part->part_size-1)
	disk_size=parts->part->part_offset+parts->part->part_size-1;
    }
  }
  log_warning("%s\n",disk_car->description(disk_car));
  log_warning("Check the hard disk size: HD jumper settings, BIOS detection...\n");
#if defined(__CYGWIN__) || defined(__MINGW32__)
  if(disk_car->disk_size<=((uint64_t)1<<(28-1)) && disk_size>=((uint64_t)1<<(28-1)))
  {
    log_warning("Hint: update Windows to support LBA48 (minimum: W2K SP4 or XP SP1)\n");
  }
#endif
  {
    char buffer_disk_size[100];
    char buffer_disk_size_found[100];
    size_to_unit(disk_car->disk_size, buffer_disk_size);
    size_to_unit(disk_size, buffer_disk_size_found);
    log_warning("The hard disk (%s) seems too small! (< %s)\n",
	buffer_disk_size, buffer_disk_size_found);
  }
  if(list_part->next==NULL)
  {
    log_warning("The following partition can't be recovered:\n");
  } else {
    log_warning("The following partitions can't be recovered:\n");
  }
  {
    list_part_t *parts;
    for(parts=list_part;parts!=NULL;parts=parts->next)
      log_partition(disk_car,parts->part);
  }
  return 0;
}

#ifdef HAVE_NCURSES
static void warning_geometry_ncurses(disk_t *disk_car, const unsigned int recommanded_heads_per_cylinder)
{
  aff_copy(stdscr);
  wmove(stdscr,4,0);
  wprintw(stdscr,"%s",disk_car->description(disk_car));
  wmove(stdscr,6,0);
  wprintw(stdscr, "Warning: the current number of heads per cylinder is %u",
      disk_car->geom.heads_per_cylinder);
  wmove(stdscr,7,0);
  wprintw(stdscr,"but the correct value may be %u.",recommanded_heads_per_cylinder);
  wmove(stdscr,8,0);
  wprintw(stdscr,"You can use the Geometry menu to change this value.");
  wmove(stdscr,9,0);
  wprintw(stdscr,"It's something to try if");
  wmove(stdscr,10,0);
  wprintw(stdscr,"- some partitions are not found by TestDisk");
  wmove(stdscr,11,0);
  wprintw(stdscr,"- or the partition table can not be written because partitions overlap.");
  wmove(stdscr,22,0);
  wattrset(stdscr, A_REVERSE);
  wprintw(stdscr,"[ Continue ]");
  wattroff(stdscr, A_REVERSE);
  wrefresh(stdscr);
  while(wgetch(stdscr)==ERR);
}
#endif

static void hint_insert(uint64_t *tab, const uint64_t offset, unsigned int *tab_nbr)
{
  if(*tab_nbr<MAX_SEARCH_LOCATION-1)
  {
    unsigned int i,j;
    for(i=0;i<*tab_nbr && tab[i]<offset;i++);
    if(i<*tab_nbr && tab[i]==offset)
      return;
    (*tab_nbr)++;
    for(j=*tab_nbr;j>i;j--)
      tab[j]=tab[j-1];
    tab[i]=offset;
  }
}

static void search_add_hints(const disk_t *disk, uint64_t *try_offset, unsigned int *try_offset_nbr)
{
  if(disk->arch==&arch_i386)
  {
    /* sometimes users choose Intel instead of GPT */
    hint_insert(try_offset, 2*disk->sector_size+16384, try_offset_nbr);
    /* sometimes users don't choose Vista by mistake */
    hint_insert(try_offset, 2048*512, try_offset_nbr);
    /* try to deal with incorrect geometry */
    /* 0/1/1 */
    hint_insert(try_offset, 32 * disk->sector_size, try_offset_nbr);
    hint_insert(try_offset, 63 * disk->sector_size, try_offset_nbr);
    /* 1/[01]/1 CHS x  16 63 */
    hint_insert(try_offset, 16 * 63 * disk->sector_size, try_offset_nbr);
    hint_insert(try_offset, 17 * 63 * disk->sector_size, try_offset_nbr);
    hint_insert(try_offset, (uint64_t)16 * disk->geom.sectors_per_head * disk->sector_size, try_offset_nbr);
    hint_insert(try_offset, (uint64_t)17 * disk->geom.sectors_per_head * disk->sector_size, try_offset_nbr);
    /* 1/[01]/1 CHS x 240 63 */
    hint_insert(try_offset, 240 * 63 * disk->sector_size, try_offset_nbr);
    hint_insert(try_offset, 241 * 63 * disk->sector_size, try_offset_nbr);
    hint_insert(try_offset, (uint64_t)240 * disk->geom.sectors_per_head * disk->sector_size, try_offset_nbr);
    hint_insert(try_offset, (uint64_t)241 * disk->geom.sectors_per_head * disk->sector_size, try_offset_nbr);
    /* 1/[01]/1 CHS x 255 63 */
    hint_insert(try_offset, 255 * 63 * disk->sector_size, try_offset_nbr);
    hint_insert(try_offset, 256 * 63 * disk->sector_size, try_offset_nbr);
    hint_insert(try_offset, (uint64_t)255 * disk->geom.sectors_per_head * disk->sector_size, try_offset_nbr);
    hint_insert(try_offset, (uint64_t)256 * disk->geom.sectors_per_head * disk->sector_size, try_offset_nbr);
    /* Hints for NTFS backup */
    if(disk->geom.cylinders>1)
    {
      CHS_t start;
      start.cylinder=disk->geom.cylinders-1;
      start.head=disk->geom.heads_per_cylinder-1;
      start.sector=disk->geom.sectors_per_head;
      hint_insert(try_offset, CHS2offset_inline(disk, &start), try_offset_nbr);
      if(disk->geom.cylinders>2)
      {
	start.cylinder--;
	hint_insert(try_offset, CHS2offset_inline(disk, &start), try_offset_nbr);
      }
    }
    hint_insert(try_offset, (disk->disk_size-disk->sector_size)/(2048*512)*(2048*512)-disk->sector_size, try_offset_nbr);
  }
  else if(disk->arch==&arch_gpt)
  {
    /* Hint for NTFS backup */
    const unsigned int gpt_entries_size=128*sizeof(struct gpt_ent);
    const uint64_t hdr_lba_end=le64((disk->disk_size-1 - gpt_entries_size)/disk->sector_size - 1);
    const uint64_t ntfs_backup_offset=(hdr_lba_end-1)*disk->sector_size/(2048*512)*(2048*512)-disk->sector_size;
    hint_insert(try_offset, ntfs_backup_offset, try_offset_nbr);
  }
  else if(disk->arch==&arch_mac)
  {
    /* sometime users choose Mac instead of GPT for i386 Mac */
    hint_insert(try_offset, 2*disk->sector_size+16384, try_offset_nbr);
  }
}

/*
   Intel
   - Display CHS
   - Align: following configuration
   - MinPartOffset: 512
   - Geometry: care
   Mac
   - Display S
   - Align to 4k (not required)
   - MinPartOffset: 512
   - Geometry: don't care
   None
   - Display S
   - Align: none
   - MinPartOffset: 0
   - Geometry: don't care
   Sun
   - Display C
   - Align to C boundaries
   - MinPartOffset: 512
   - Partition need to have H=0, S=1
   - Geometry: required
   XBox
   - Display S
   - Align: none
   - MinPartOffset: 0x800
   - Geometry: don't care
*/
static uint64_t get_min_location(const disk_t *disk)
{
  if(disk->arch==&arch_gpt)
    return 2*disk->sector_size+16384;
  else if(disk->arch==&arch_i386 || disk->arch==&arch_humax)
    return disk->sector_size;
  else if(disk->arch==&arch_mac)
    return 4096;
  else if(disk->arch==&arch_sun)
    return (uint64_t)disk->geom.heads_per_cylinder * disk->geom.sectors_per_head * disk->sector_size;
  else if(disk->arch==&arch_xbox)
    return 0x800;
  /* arch_none */
  return 0;
}

static void search_NTFS_from_backup(disk_t *disk_car, list_part_t *list_part, const int verbose, const int dump_ind, const uint64_t min_location, const uint64_t search_location_max)
{
  unsigned char *buffer_disk;
  const list_part_t *element;
  partition_t *partition;
  buffer_disk=(unsigned char*)MALLOC(16*DEFAULT_SECTOR_SIZE);
  partition=partition_new(disk_car->arch);
  for(element=list_part;element!=NULL;element=element->next)
  {
    if(element->part->upart_type==UP_NTFS && element->part->sb_offset!=0)
    {
      unsigned int i;
      for(i=32;i>0;i--)
      {
	const uint64_t tmp=i * disk_car->sector_size;
	if(element->part->part_offset > tmp)
	{
	  partition_reset(partition, disk_car->arch);
	  partition->part_size=(uint64_t)0;
	  partition->part_offset=element->part->part_offset - tmp;
	  if(disk_car->pread(disk_car, buffer_disk, DEFAULT_SECTOR_SIZE, partition->part_offset)==DEFAULT_SECTOR_SIZE &&
	      recover_NTFS(disk_car, (const struct ntfs_boot_sector*)buffer_disk, partition, verbose, dump_ind, 0)==0)
	  {
	    partition->status=STATUS_DELETED;
	    if(disk_car->arch->is_part_known(partition)!=0 && partition->part_size>1 &&
		partition->part_offset >= min_location &&
		partition->part_offset+partition->part_size-1 <= search_location_max)
	    {
	      int insert_error=0;
	      partition_t *new_partition=partition_new(NULL);
	      dup_partition_t(new_partition,partition);
	      list_part=insert_new_partition(list_part, new_partition, 0, &insert_error);
	      if(insert_error>0)
		free(new_partition);
	    }
	  }
	}
      }
    }
  }
  free(partition);
  free(buffer_disk);
}

typedef enum { INDSTOP_CONTINUE=0, INDSTOP_STOP=1, INDSTOP_SKIP=2, INDSTOP_QUIT=3, INDSTOP_PLUS=4 } indstop_t;

static list_part_t *search_part(disk_t *disk_car, const list_part_t *list_part_org, const int verbose, const int dump_ind, const int fast_mode, char **current_cmd)
{
  unsigned char *buffer_disk;
  unsigned char *buffer_disk0;
  /* TODO use circular buffer for try_offset and try_offset_raid */
  uint64_t try_offset[MAX_SEARCH_LOCATION];
  uint64_t try_offset_raid[MAX_SEARCH_LOCATION];
  const uint64_t min_location=get_min_location(disk_car);
  uint64_t search_location;
  unsigned int try_offset_nbr=0;
  unsigned int try_offset_raid_nbr=0;
#ifdef HAVE_NCURSES
  unsigned int old_cylinder=0;
#endif
  const unsigned int location_boundary=get_location_boundary(disk_car);
  indstop_t ind_stop=INDSTOP_CONTINUE;
  list_part_t *list_part=NULL;
  list_part_t *list_part_bad=NULL;
  partition_t *partition;
  /* It's not a problem to read a little bit more than necessary */
  const uint64_t search_location_max=td_max((disk_car->disk_size /
      ((uint64_t) disk_car->geom.heads_per_cylinder * disk_car->geom.sectors_per_head * disk_car->sector_size) + 1 ) *
      ((uint64_t) disk_car->geom.heads_per_cylinder * disk_car->geom.sectors_per_head * disk_car->sector_size),
      disk_car->disk_real_size);
  assert(disk_car->sector_size>0);
  partition=partition_new(disk_car->arch);
  buffer_disk=(unsigned char*)MALLOC(16*DEFAULT_SECTOR_SIZE);
  buffer_disk0=(unsigned char*)MALLOC(16*DEFAULT_SECTOR_SIZE);
  {
    /* Will search for partition at current known partition location */
    const list_part_t *element;
    for(element=list_part_org;element!=NULL;element=element->next)
    {
      hint_insert(try_offset, element->part->part_offset, &try_offset_nbr);
    }
  }

#ifdef HAVE_NCURSES
  wmove(stdscr,22,0);
  wattrset(stdscr, A_REVERSE);
  waddstr(stdscr,"  Stop  ");
  wattroff(stdscr, A_REVERSE);
#endif
  screen_buffer_reset();
  log_info("\nsearch_part()\n");
  log_info("%s\n",disk_car->description(disk_car));
  search_location=min_location;
  search_add_hints(disk_car, try_offset, &try_offset_nbr);
  /* Not every sector will be examined */
  search_location_init(disk_car, location_boundary, fast_mode);
  /* Scan the disk */
  while(ind_stop!=INDSTOP_QUIT && search_location < search_location_max)
  {
    CHS_t start;
    int ask=0;
    offset2CHS_inline(disk_car,search_location,&start);
#ifdef HAVE_NCURSES
    if(disk_car->geom.heads_per_cylinder>1)
    {
      if(old_cylinder!=start.cylinder)
      {
	old_cylinder=start.cylinder;
	wmove(stdscr,ANALYSE_Y,ANALYSE_X);
	wclrtoeol(stdscr);
	wprintw(stdscr, "Analyse cylinder %5lu/%lu: %02u%%",
	    start.cylinder, disk_car->geom.cylinders-1,
	    (unsigned int)(search_location*100/disk_car->disk_size));
	ask=1;
      }
    }
    else if((start.cylinder & 0x7FFF)==0)
    {
      wmove(stdscr,ANALYSE_Y,ANALYSE_X);
      wclrtoeol(stdscr);
      wprintw(stdscr,"Analyse sector %11llu/%llu: %02u%%",
	  (long long unsigned)(search_location / disk_car->sector_size),
	  (long long unsigned)((disk_car->disk_size-1)/disk_car->sector_size),
	    (unsigned int)(search_location*100/disk_car->disk_size));
      wrefresh(stdscr);
      ask=1;
    }
    if(ask!=0)
    {
      wrefresh(stdscr);
      switch(check_enter_key_or_s(stdscr))
      {
	case 1:
	  if(ask_confirmation("Stop searching for more partitions ? (Y/N)")!=0)
	    ind_stop=INDSTOP_STOP;
	  else
	  {
	    screen_buffer_to_interface();
	  }
	  break;
	case 2:
	  ind_stop=INDSTOP_SKIP;
	  break;
	case 3:
	  ind_stop=INDSTOP_PLUS;
	  break;
      }
    }
#endif
    {
      unsigned int sector_inc=0;
      int test_nbr=0;
      int search_now=0;
      int search_now_raid=0;
      while(try_offset_nbr>0 && try_offset[0]<=search_location)
      {
        unsigned int j;
        if(try_offset[0]==search_location)
          search_now=1;
        for(j=0;j<try_offset_nbr-1;j++)
          try_offset[j]=try_offset[j+1];
        try_offset_nbr--;
      }
      /* PC x/0/1 x/1/1 x/2/1 */
      /* PC Vista 2048 sectors unit */
      if(disk_car->arch==&arch_i386)
        search_now|= (start.sector==1 && fast_mode>1) ||
          (start.sector==1 && start.head<=2) ||
          search_location%(2048*512)==0;
      else
        search_now|= (search_location%location_boundary==0);
      while(try_offset_raid_nbr>0 && try_offset_raid[0]<=search_location)
      {
        unsigned int j;
        if(try_offset_raid[0]==search_location)
          search_now_raid=1;
        for(j=0;j<try_offset_raid_nbr-1;j++)
          try_offset_raid[j]=try_offset_raid[j+1];
        try_offset_raid_nbr--;
      }
      do
      {
        int res=0;
        partition->part_size=(uint64_t)0;
        partition->part_offset=search_location;
        if(test_nbr==0)
        {
          if(search_now_raid>0 || fast_mode>1)
          { /* Search Linux software RAID */
	    if(disk_car->pread(disk_car, buffer_disk, 8 * DEFAULT_SECTOR_SIZE, search_location) == 8 *DEFAULT_SECTOR_SIZE)
            {
              if(recover_MD(disk_car, (const struct mdp_superblock_s*)buffer_disk, partition, verbose, dump_ind)==0)
              {
                const struct mdp_superblock_1 *sb1=(const struct mdp_superblock_1 *)buffer_disk;
		if(le32(sb1->md_magic)==(unsigned int)MD_SB_MAGIC)
		{
		  if(le32(sb1->major_version)==0)
		    partition->part_offset-=(uint64_t)MD_NEW_SIZE_SECTORS(partition->part_size/512)*512;
		  else
		    partition->part_offset-=le64(sb1->super_offset)*512;
		}
		else
		{
		  if(be32(sb1->major_version)==0)
		    partition->part_offset-=(uint64_t)MD_NEW_SIZE_SECTORS(partition->part_size/512)*512;
		  else
		    partition->part_offset-=be64(sb1->super_offset)*512;
		}
                res=1;
              }
              else
                res=0;
            }
          }
          test_nbr++;
        }
        if(res<=0 && test_nbr==1)
	{
	  if((disk_car->arch==&arch_i386 &&
		((start.sector==7 && (start.head<=2 || fast_mode>1)) ||
		 search_location%(2048*512)==(7-1)*512)) ||
	      (disk_car->arch!=&arch_i386 && (search_location%location_boundary==(7-1)*512)) ||
	      (disk_car->arch==&arch_gpt&& (search_location%(2048*512)==(7-1)*512)) ||
	      (disk_car->arch==&arch_none && search_location==(7-1)*512))
	    res=search_FAT_backup(buffer_disk,disk_car,partition,verbose,dump_ind);
	  test_nbr++;
        }
        if(res<=0 && test_nbr==2)
	{
	  if((disk_car->arch==&arch_i386 &&
		((start.sector==13 && (start.head<=2 || fast_mode>1)) ||
		 search_location%(2048*512)==(13-1)*disk_car->sector_size)) ||
	      (disk_car->arch==&arch_gpt&& (search_location%(2048*512)==(13-1)*512)) ||
	      (disk_car->arch!=&arch_i386 && (search_location%location_boundary==(13-1)*disk_car->sector_size)))
	    res=search_exFAT_backup(buffer_disk, disk_car, partition);
	  test_nbr++;
	}
        if(res<=0 && test_nbr==3)
        {
          if((disk_car->arch==&arch_i386 &&
                ((start.sector==disk_car->geom.sectors_per_head &&
		  (start.head==disk_car->geom.heads_per_cylinder-1 || fast_mode>1)) ||
                 search_location%(2048*512)==(2048-1)*512)) ||
	      (disk_car->arch==&arch_gpt&& (search_location%(2048*512)==(2048-1)*512)) ||
              (disk_car->arch!=&arch_i386 && search_location%location_boundary==(location_boundary-512) &&
               search_location>0))
            res=search_NTFS_backup(buffer_disk,disk_car,partition,verbose,dump_ind);
          test_nbr++;
        }
        if(res<=0 && test_nbr==4)
        {
          if((disk_car->arch==&arch_i386 &&
                ((start.sector==disk_car->geom.sectors_per_head &&
		  (start.head==disk_car->geom.heads_per_cylinder-1 || fast_mode>1)) ||
		 search_location%(2048*512)==(2048-1)*512)) ||
              (disk_car->arch!=&arch_i386 && search_location%location_boundary==(location_boundary-512) &&
               search_location>0))
            res=search_HFS_backup(buffer_disk,disk_car,partition,verbose,dump_ind);
          test_nbr++;
        }
        if(res<=0 && test_nbr==5)
        {
          int s_log_block_size;
          /* try backup superblock */
          /* It must be in fast_mode>0 because it can hide otherwise other partition type */
          /* Block size: 1024, 2048 or 4096 bytes (8192 bytes on Alpha systems) */
          /* From e2fsprogs-1.34/lib/ext2fs/initialize.c: set_field(s_first_data_block, super->s_log_block_size ? 0 : 1); */
          /* Assumes that TestDisk is not running under Alpha and s_blocks_per_group=8 * block size */
          for(s_log_block_size=0;(s_log_block_size<=2)&&(res<=0);s_log_block_size++)
          {
            /* sparse superblock feature: The groups chosen are 0, 1 and powers of 3, 5 and 7. */
            /* Checking group 3 */
            const uint64_t hd_offset=3*(EXT2_MIN_BLOCK_SIZE<<s_log_block_size)*8*(EXT2_MIN_BLOCK_SIZE<<s_log_block_size)+(s_log_block_size==0?2*DEFAULT_SECTOR_SIZE:0);
            if(search_location>=hd_offset)
            {
              CHS_t start_ext2;
              offset2CHS_inline(disk_car,search_location-hd_offset,&start_ext2);
              if((disk_car->arch==&arch_i386 && start_ext2.sector==1 &&  (start_ext2.head<=2 || fast_mode>1)) ||
		  (disk_car->arch==&arch_i386 && (search_location-hd_offset)%(2048*512)==0) ||
		  (disk_car->arch!=&arch_i386 && (search_location-hd_offset)%location_boundary==0))
	      {
		if(disk_car->pread(disk_car, buffer_disk, 1024, search_location)==1024)
		{
		  const struct ext2_super_block *sb=(const struct ext2_super_block*)buffer_disk;
		  if(le16(sb->s_magic)==EXT2_SUPER_MAGIC && le16(sb->s_block_group_nr)>0 &&
		      recover_EXT2(disk_car, sb, partition, verbose, dump_ind)==0)
		    res=1;
		}
	      }
            }
          }
          test_nbr++;
        }
        if(res<=0 && test_nbr==6)
        {
	  if(search_now==0)
            test_nbr=14;
	  else
	  {
	    if(disk_car->pread(disk_car, buffer_disk0, 16 * DEFAULT_SECTOR_SIZE, partition->part_offset) == 16 * DEFAULT_SECTOR_SIZE)
	      res=search_type_2(buffer_disk0,disk_car,partition,verbose,dump_ind);
	    else
	      res=-1;
	    test_nbr++;
	  }
        }
        if(res<=0 && test_nbr==7)
        {
	  if(res==0)
	    res=search_type_1(buffer_disk0, disk_car,partition,verbose,dump_ind);
	  test_nbr++;
        }
        if(res<=0 && test_nbr==8)
        {
	  if(res==0)
	    res=search_type_0(buffer_disk0,disk_car,partition,verbose,dump_ind);
          test_nbr++;
        }
        if(res<=0 && test_nbr==9)
        {
          res=search_type_8(buffer_disk,disk_car,partition,verbose,dump_ind);
          test_nbr++;
        }
        if(res<=0 && test_nbr==10)
        {
          /* Try to catch disklabel before BSD FFS partition */
          res=search_type_16(buffer_disk,disk_car,partition,verbose,dump_ind);
          test_nbr++;
        }
        if(res<=0 && test_nbr==11)
        {
          res=search_type_64(buffer_disk,disk_car,partition,verbose,dump_ind);
          test_nbr++;
        }
        if(res<=0 && test_nbr==12)
        {
          /* read to fill the cache */
          disk_car->pread(disk_car, buffer_disk, 8 * DEFAULT_SECTOR_SIZE,
	      partition->part_offset + (63 + 16) * 512);
          /* Try to catch disklabel before BSD FFS partition */
          res=search_type_128(buffer_disk,disk_car,partition,verbose,dump_ind);
          test_nbr++;
        }
	if(res<=0 && test_nbr==13)
	{
          res=search_type_2048(buffer_disk,disk_car,partition,verbose,dump_ind);
          test_nbr++;
	}
        if(test_nbr>=14)
        {
          sector_inc=1;
          test_nbr=0;
        }
        if(res<0)
        {
#ifdef HAVE_NCURSES
	  wmove(stdscr,ANALYSE_Y+1,ANALYSE_X);
	  wclrtoeol(stdscr);
	  wprintw(stdscr, "Read error at %lu/%u/%u (lba=%lu)\n", start.cylinder,start.head,start.sector,(unsigned long)(partition->part_offset/disk_car->sector_size));
#endif
	  /* Stop reading after the end of the disk */
	  if(search_location >= disk_car->disk_real_size)
	    search_location = search_location_max;
        }
        else if(res>0)
        {
          partition->status=STATUS_DELETED;
          log_partition(disk_car,partition);
          aff_part_buffer(AFF_PART_BASE, disk_car,partition);
#ifdef HAVE_NCURSES
	  screen_buffer_to_interface();
#endif
          if(disk_car->arch->is_part_known(partition)!=0 &&
              partition->part_size>1 &&
              partition->part_offset>=min_location)
          {
            const uint64_t pos_fin=partition->part_offset+partition->part_size-1;
            if(partition->upart_type!=UP_MD && partition->upart_type!=UP_MD1 &&
	      ind_stop==INDSTOP_CONTINUE)
            { /* Detect Linux md 0.9 software raid */
              unsigned int disk_factor;
              for(disk_factor=6; disk_factor>=1;disk_factor--)
              { /* disk_factor=1, detect Raid 0/1 */
                /* disk_factor>1, detect Raid 5 */
		unsigned int help_factor;
                for(help_factor=0; help_factor<=MD_MAX_CHUNK_SIZE/MD_RESERVED_BYTES+3; help_factor++)
                {
                  const uint64_t offset=(uint64_t)MD_NEW_SIZE_SECTORS((partition->part_size/disk_factor+help_factor*MD_RESERVED_BYTES-1)/MD_RESERVED_BYTES*MD_RESERVED_BYTES/512)*512;
                  hint_insert(try_offset_raid, partition->part_offset+offset, &try_offset_raid_nbr);
                }
              }
              /* TODO: Detect Linux md 1.0 software raid */
            }
            /* */
            if(pos_fin <= search_location_max)
            {
              {
                int insert_error=0;
                partition_t *new_partition=partition_new(NULL);
                dup_partition_t(new_partition,partition);
                list_part=insert_new_partition(list_part, new_partition, 0, &insert_error);
                if(insert_error>0)
                  free(new_partition);
              }
              {
                const uint64_t next_part_offset=partition->part_offset+partition->part_size-1+1;
                const uint64_t head_size=(uint64_t)disk_car->geom.sectors_per_head * disk_car->sector_size;
                hint_insert(try_offset, next_part_offset, &try_offset_nbr);
                hint_insert(try_offset, next_part_offset+head_size, &try_offset_nbr);
                if(next_part_offset%head_size!=0)
                {
                  hint_insert(try_offset, (next_part_offset+head_size-1)/head_size*head_size, &try_offset_nbr);
                  hint_insert(try_offset, (next_part_offset+head_size-1)/head_size*head_size+head_size, &try_offset_nbr);
                }
              }
              if((fast_mode==0) && (partition->part_offset+partition->part_size-disk_car->sector_size > search_location))
              {
                search_location=partition->part_offset+partition->part_size-disk_car->sector_size;
                test_nbr=0;
                sector_inc=1;
              }
            }
            else
            {
              {
                int insert_error=0;
                partition_t *new_partition=partition_new(NULL);
                dup_partition_t(new_partition,partition);
                list_part_bad=insert_new_partition(list_part_bad, new_partition, 0, &insert_error);
                if(insert_error>0)
                  free(new_partition);
              }
              if(verbose>0)
                log_warning("This partition ends after the disk limits. (start=%llu, size=%llu, end=%llu, disk end=%llu)\n",
                    (unsigned long long)(partition->part_offset/disk_car->sector_size),
                    (unsigned long long)(partition->part_size/disk_car->sector_size),
                    (unsigned long long)(pos_fin/disk_car->sector_size),
                    (unsigned long long)(disk_car->disk_size/disk_car->sector_size));
              else
                log_warning("This partition ends after the disk limits.\n");
            }
          }
          else
          {
            if(verbose>0)
            {
              log_warning("Partition not added.\n");
            }
          }
          partition_reset(partition, disk_car->arch);
        }
      }
      while(sector_inc==0);
    }
    if(ind_stop==INDSTOP_SKIP)
    {
      ind_stop=INDSTOP_CONTINUE;
      if(try_offset_nbr>0 && search_location < try_offset[0])
	search_location=try_offset[0];
    }
    else if(ind_stop==INDSTOP_PLUS)
    {
      ind_stop=INDSTOP_CONTINUE;
      search_location += search_location_max / 20 / (1024 * 1024) * (1024 * 1014);
    }
    else if(ind_stop==INDSTOP_STOP)
    {
      if(try_offset_nbr>0 && search_location < try_offset[0])
	search_location=try_offset[0];
      else
	ind_stop=INDSTOP_QUIT;
    }
    else
    { /* Optimized "search_location+=disk_car->sector_size;" */
      uint64_t min=search_location_update(search_location);
      if(try_offset_nbr>0 && min>try_offset[0])
        min=try_offset[0];
      if(try_offset_raid_nbr>0 && min>try_offset_raid[0])
        min=try_offset_raid[0];
      if(min==(uint64_t)-1 || min<=search_location)
        search_location+=disk_car->sector_size;
      else
        search_location=min;
    }
  }
  /* Search for NTFS partition near the supposed partition beginning
     given by the NTFS backup boot sector */
  if(fast_mode>0)
    search_NTFS_from_backup(disk_car, list_part, verbose, dump_ind, min_location, search_location_max);
  free(partition);
  if(ind_stop!=INDSTOP_CONTINUE)
    log_info("Search for partition aborted\n");
  if(list_part_bad!=NULL)
  {
    interface_part_bad_log(disk_car,list_part_bad);
#ifdef HAVE_NCURSES
    if(*current_cmd==NULL)
      interface_part_bad_ncurses(disk_car,list_part_bad);
#endif
  }
  part_free_list(list_part_bad);
  free(buffer_disk0);
  free(buffer_disk);
  return list_part;
}

#ifdef HAVE_NCURSES
static void ask_mbr_order_i386(disk_t *disk_car,list_part_t *list_part)
{
  partition_t *table[4];
  int nbr_prim=0;
  int i,pos=0;
  int res;
  int quit=0;
  list_part_t *element;
  /* Initialisation */
  aff_copy(stdscr);
  wmove(stdscr,4,0);
  wprintw(stdscr,"%s",disk_car->description(disk_car));
  mvwaddstr(stdscr,5,0,msg_MBR_ORDER);
  mvwaddstr(stdscr,6,0,msg_PART_HEADER_LONG);
  for(element=list_part;element!=NULL;element=element->next)
  {
    if((element->part->order>0) && (element->part->order<5))
      table[nbr_prim++]=element->part;
  }
  /* */
  log_info("\nSelect primary partition\n");
  for(i=0;i<nbr_prim;i++)
      log_partition(disk_car,table[i]);
  /* */
  do
  {
    partition_t *table2[4];
    int car;
    unsigned int order;
    /* sort table into table2 */
    int part=0;
    res=0;
    for(order=1;order<=4;order++)
    {
      int nbr=0;
      for(i=0;i<nbr_prim;i++)
	if(table[i]->order==order)
	{
	  table2[part++]=table[i];
	  nbr++;
	}
      res|=(nbr>1);
    }
    if(part!=nbr_prim)
    {
      log_critical("\nBUG part %d, nbr_prim %d\n", part, nbr_prim);
    }
    for(i=0;i<nbr_prim;i++)
    {
      wmove(stdscr,5+2+i,0);
      wclrtoeol(stdscr);
      if(i==pos)
	standout();
      aff_part(stdscr,AFF_PART_ORDER|AFF_PART_STATUS,disk_car,table2[i]);
      if(i==pos)
	standend();
    }
    wmove(stdscr,20,0);
    if(res)
      wprintw(stdscr,msg_MBR_ORDER_BAD);
    else
      wprintw(stdscr,msg_MBR_ORDER_GOOD);
    wrefresh(stdscr);
    car=wgetch(stdscr);
    quit=0;
    switch(car)
    {
      case KEY_UP:
	if(--pos<0)
	  pos=nbr_prim-1;
	break;
      case KEY_DOWN:
	if(++pos>=nbr_prim)
	  pos=0;
	break;
      case KEY_PPAGE:
	pos=0;
	break;
      case KEY_NPAGE:
	pos=nbr_prim-1;
	break;
      case '1':
      case '2':
      case '3':
      case '4':
	table2[pos]->order=car-'0';
	break;
      case KEY_RIGHT:
      case ' ':
      case '+':
	if(++table2[pos]->order>4)
	  table2[pos]->order=1;
	break;
      case KEY_LEFT:
      case '-':
	if(--table2[pos]->order<1)
	  table2[pos]->order=4;
	break;
      case 'q':
      case '\r':
      case '\n':
      case KEY_ENTER:
#ifdef PADENTER
      case PADENTER:
#endif
      case 'M':
	quit=1;
	break;
    }
    wrefresh(stdscr);
  } while(res!=0 || quit==0);
}
#endif

static list_part_t *reduce_structure(const list_part_t *list_part_org)
{

  const list_part_t *element;
  list_part_t *list_part=NULL;
  for(element=list_part_org; element!=NULL; element=element->next)
  {
    if(element->part->status!=STATUS_DELETED)
    {
      int insert_error=0;
      partition_t *new_partition=partition_new(NULL);
      dup_partition_t(new_partition, element->part);
      list_part=insert_new_partition(list_part, new_partition, 0, &insert_error);
      if(insert_error>0)
	free(new_partition);
    }
  }
  return list_part;
}

static list_part_t *add_ext_part_i386(const disk_t *disk, list_part_t *list_part, const int max_ext, const int verbose)
{
  /* list_part need to be sorted! */
  /* All extended partitions of an P_EXTENDX are P_EXTENDED */
  int insert_error=0;
  list_part_t *element;
  list_part_t *deb=NULL;
  list_part_t *fin=NULL;
  int nbr_entries=0;
  partition_t *new_partition;
  unsigned int order=0;
  uint64_t part_extended_offset=0;
  uint64_t part_extended_end=0;
  for(element=list_part;element!=NULL;)
  {
    if(element->part->status==STATUS_EXT)
    {
      /* remove already existing extended partition */
      list_part_t *next=element->next;
      if(element->prev!=NULL)
	element->prev->next=element->next;
      if(element->next!=NULL)
	element->next->prev=element->prev;
      order=element->part->order;
      if(element==list_part)
	list_part=next;
      free(element->part);
      free(element);
      element=next;
    }
    else
    {
      if(element->part->status==STATUS_LOG)
      {
	if(deb==NULL)
	{
	  deb=element;
	  nbr_entries++;
	}
	fin=element;
      }
      else
	nbr_entries++;
      element=element->next;
    }
  }
  if(deb==NULL)
    return list_part;
  assert(fin!=NULL);
  if(nbr_entries==4 || max_ext!=0)
  {
    if(verbose>0)
    {
      log_info("add_ext_part_i386: max\n");
    }
    if(deb->prev==NULL)
    {
      uint64_t tmp;
      part_extended_offset=deb->part->part_offset - disk->sector_size;
      if(deb->part->part_offset%(1024*1024)==0)
	tmp=1024*1024;
      else
	tmp=(uint64_t)disk->geom.sectors_per_head * disk->sector_size;
      if(tmp < part_extended_offset)
	part_extended_offset=tmp;
    }
    else
    {
      uint64_t tmp;
      part_extended_offset=deb->prev->part->part_offset + deb->prev->part->part_size;
      /* round up part_extended_offset */
      if(deb->part->part_offset%(1024*1024)==0)
      {
	tmp=(part_extended_offset+1024*1024-1)/(1024*1024)*(1024*1024);
      }
      else
      {
	CHS_t start;
	start.cylinder=offset2cylinder(disk, part_extended_offset-1)+1;
	start.head=0;
	start.sector=1;
	tmp=CHS2offset_inline(disk, &start);
      }
      if(tmp < deb->part->part_offset &&
	  (deb->prev==NULL || tmp >= deb->prev->part->part_offset + deb->prev->part->part_size))
	part_extended_offset=tmp;
    }
    if(fin->next==NULL)
    {
      part_extended_end=fin->part->part_offset + fin->part->part_size - disk->sector_size;
      /* In some weird cases, a partition may end after the end of the disk */
      if(part_extended_end < disk->disk_size - disk->sector_size)
	part_extended_end=disk->disk_size - disk->sector_size;
    }
    else
      part_extended_end=fin->next->part->part_offset - disk->sector_size;
    /* round down part_extended_end */
    if(part_extended_offset%(1024*1024)==0)
    {
      const uint64_t tmp=part_extended_end/(1024*1024)*(1024*1024) - disk->sector_size;
      if(fin->part->part_offset + fin->part->part_size - disk->sector_size <= tmp)
	part_extended_end=tmp;
    }
    else
    {
      uint64_t tmp;
      CHS_t end;
      end.cylinder=offset2cylinder(disk, part_extended_end)-1;
      end.head=disk->geom.heads_per_cylinder-1;
      end.sector=disk->geom.sectors_per_head;
      tmp=CHS2offset_inline(disk, &end);
      if(fin->part->part_offset + fin->part->part_size - disk->sector_size <= tmp)
	part_extended_end=tmp;
    }
  }
  else
  {
    uint64_t tmp;
    if(verbose>0)
    {
      log_info("add_ext_part_i386: min\n");
    }
    part_extended_offset=deb->part->part_offset - disk->sector_size;
    /* round down part_extended_offset */
    if(deb->part->part_offset%(1024*1024)==0)
    {
      tmp=part_extended_offset/(1024*1024)*(1024*1024);
    }
    else
    {
      CHS_t start;
      start.cylinder=offset2cylinder(disk, part_extended_offset);
      if(start.cylinder==0)
	start.head=1;
      else
	start.head=0;
      start.sector=1;
      tmp=CHS2offset_inline(disk, &start);
    }
    if(tmp > 0 && tmp < deb->part->part_offset &&
	(deb->prev==NULL || tmp >= deb->prev->part->part_offset + deb->prev->part->part_size))
      part_extended_offset=tmp;

    part_extended_end=fin->part->part_offset + fin->part->part_size - disk->sector_size;
    /* round up part_extended_end */
    if(part_extended_offset%(1024*1024)==0)
    {
      tmp=(part_extended_end+1024*1024-1)/(1024*1024)*(1024*1024) - disk->sector_size;
    }
    else
    {
      CHS_t end;
      offset2CHS_inline(disk, part_extended_end, &end);
      end.head=disk->geom.heads_per_cylinder-1;
      end.sector=disk->geom.sectors_per_head;
      tmp=CHS2offset_inline(disk, &end);
    }
    if(tmp < disk->disk_size)
      part_extended_end=tmp;
  }
  new_partition=partition_new(disk->arch);
  new_partition->order=order;
  new_partition->part_type_i386=(offset2cylinder(disk, part_extended_end) > 1023?P_EXTENDX:P_EXTENDED);
  new_partition->status=STATUS_EXT;
  new_partition->part_offset=part_extended_offset;
  new_partition->part_size=part_extended_end - new_partition->part_offset + disk->sector_size;
  list_part=insert_new_partition(list_part, new_partition, 0, &insert_error);
  if(insert_error>0)
    free(new_partition);
  return list_part;
}

static int use_backup(disk_t *disk_car, const list_part_t *list_part, const int verbose,const int dump_ind, const unsigned int expert, char**current_cmd)
{
  const list_part_t *element;
  if(verbose>1)
  {
    log_trace("use_backup\n");
  }
  for(element=list_part;element!=NULL;element=element->next)
  {
    if(element->part->sb_offset!=0)
    {
      switch(element->part->upart_type)
      {
	case UP_FAT32:
	  fat32_boot_sector(disk_car, element->part, verbose, dump_ind, expert,current_cmd);
	  break;
	case UP_NTFS:
	  ntfs_boot_sector(disk_car, element->part, verbose, expert, current_cmd);
	  break;
	case UP_HFS:
	case UP_HFSP:
	case UP_HFSX:
	  HFS_HFSP_boot_sector(disk_car, element->part, verbose, current_cmd);
	  break;
	default:
	  log_warning("Need to fix\n");
	  log_partition(disk_car,element->part);
	  break;
      }
    }
  }
  return 0;
}

static void warning_geometry(const list_part_t *list_part, disk_t *disk, const int verbose, char **current_cmd)
{
  if(list_part!=NULL && (disk->arch==&arch_i386 || disk->arch==&arch_sun))
  { /* Correct disk geometry is necessary for successfull Intel and Sun partition recovery */
    const unsigned int heads_per_cylinder=get_geometry_from_list_part(disk, list_part, verbose);
    if(disk->geom.heads_per_cylinder!=heads_per_cylinder)
    {
      log_warning("Warning: the current number of heads per cylinder is %u but the correct value may be %u.\n",
	  disk->geom.heads_per_cylinder, heads_per_cylinder);
#ifdef HAVE_NCURSES
      if(*current_cmd==NULL)
      {
	warning_geometry_ncurses(disk, heads_per_cylinder);
      }
#endif
    }
  }
}

/*@
  @ requires valid_list_part(list_part_org);
  @ requires valid_disk(disk_car);
  @ requires \valid(current_cmd);
  @ requires \valid(menu);
  @ requires \valid(fast_mode);
  @*/
static int ask_write_partition_table(const list_part_t *list_part_org, disk_t *disk_car, const int verbose, const int dump_ind, const int ask_part_order, const unsigned int expert, char **current_cmd, unsigned int *menu, int *fast_mode)
{
  int res_interface_write;
  int do_again=0;
  int max_ext=0;
  int can_ask_minmax_ext=0;
  int no_confirm=0;
  list_part_t *list_part;
  list_part=reduce_structure(list_part_org);
  /* sort list_part */
  list_part=sort_partition_list(list_part);
  /* Create PC/Intel Extended partition */
  /* if(disk_car->arch==&arch_i386) */
  {
    list_part_t *parts;
    uint64_t partext_offset=0;
    uint64_t partext_size=0;
    list_part=add_ext_part_i386(disk_car, list_part, !max_ext, verbose);
    for(parts=list_part;parts!=NULL;parts=parts->next)
      if(parts->part->status==STATUS_EXT)
      {
	partext_offset=parts->part->part_offset;
	partext_size=parts->part->part_size;
      }
    if(partext_offset>0)
    {
      list_part=add_ext_part_i386(disk_car, list_part, max_ext, verbose);
      for(parts=list_part;parts!=NULL;parts=parts->next)
	if(parts->part->status==STATUS_EXT)
	{
	  if(partext_offset!=parts->part->part_offset || partext_size!=parts->part->part_size)
	    can_ask_minmax_ext=1;
	}
    }
  }
  list_part=disk_car->arch->init_part_order(disk_car,list_part);
  if(ask_part_order!=0)
  {
    /* Demande l'ordre des entrees dans le MBR */
#ifdef HAVE_NCURSES
    ask_mbr_order_i386(disk_car,list_part);
#endif
    /* Demande l'ordre des partitions etendues */
  }
  do
  {
    do_again=0;
    res_interface_write=interface_write(disk_car,list_part,((*fast_mode)<1),can_ask_minmax_ext, &no_confirm, current_cmd, menu);
    switch(res_interface_write)
    {
      case 'W':
	if(disk_car->arch == &arch_mac)
	{
#ifdef HAVE_NCURSES
	  write_part_mac_warning_ncurses();
#endif
	}
	else if(disk_car->arch == &arch_sun)
	{
#ifdef HAVE_NCURSES
	  not_implemented("write_part_sun");
#endif
	}
	else if(disk_car->arch == &arch_xbox)
	{
#ifdef HAVE_NCURSES
	  not_implemented("write_part_xbox");
#endif
	}
	else if(disk_car->arch->write_part!=NULL)
	{
	  if(no_confirm!=0
#ifdef HAVE_NCURSES
	      || ask_confirmation("Write partition table, confirm ? (Y/N)")!=0
#endif
	    )
	  {
	    log_info("write!\n");
	    if(disk_car->arch->write_part(disk_car, list_part, RW, verbose))
	    {
	      display_message(msg_PART_WR_ERR);
	    }
	    else
	    {
	      use_backup(disk_car,list_part,verbose,dump_ind,expert,current_cmd);
	      if(no_confirm==0)
		display_message("You will have to reboot for the change to take effect.\n");
	    }
	  }
	  else
	    log_info("Don't write, no confirmation\n");
	}
	break;
      case 0:
	if(disk_car->arch->write_part!=NULL)
	{
	  log_info("simulate write!\n");
	  disk_car->arch->write_part(disk_car, list_part, RO, verbose);
	}
	break;
      case 'S':
	if((*fast_mode) < 2)
	  (*fast_mode)++;
	break;
      case 'E':
	max_ext=!max_ext;
	list_part=add_ext_part_i386(disk_car, list_part, max_ext, verbose);
	do_again=1;
	break;
    }
  }
  while(do_again==1);
  part_free_list(list_part);
  return res_interface_write;
}

int interface_recovery(disk_t *disk_car, const list_part_t *list_part_org, const int verbose, const int dump_ind, const int align, const int ask_part_order, const unsigned int expert, char **current_cmd)
{
  int res_interface_write;
  int fast_mode=0;
  do
  {
    list_part_t *list_part;
    const list_part_t *element;
    unsigned int menu=0;
    if(fast_mode==0)
      menu=4;	/* Search! */
#ifdef HAVE_NCURSES
    aff_copy(stdscr);
    wmove(stdscr,4,0);
    wprintw(stdscr,"%s",disk_car->description(disk_car));
    wmove(stdscr,5,0);
#endif
    list_part=search_part(disk_car, list_part_org, verbose, dump_ind, fast_mode, current_cmd);
    warning_geometry(list_part, disk_car, verbose, current_cmd);
    align_structure(list_part, disk_car, align);

    disk_car->arch->init_structure(disk_car,list_part,verbose);
    if(verbose>0)
    {
#ifdef TARGET_LINUX
      unsigned int i=0;
#endif
      /* Write found partitions in the log file */
      log_info("\nResults\n");
      for(element=list_part;element!=NULL;element=element->next)
	log_partition(disk_car,element->part);
#ifdef TARGET_LINUX
      if(list_part!=NULL)
	log_info("\nHint for advanced users: dmsetup may be used if you prefer to avoid rewriting the partition table for the moment:\n");
      for(element=list_part;element!=NULL;element=element->next)
      {
	const partition_t *partition=element->part;
	log_info("echo \"0 %llu linear %s %llu\" | dmsetup create test%u\n",
	    (long long unsigned)(partition->part_size/512),
	    disk_car->device,
	    (long long unsigned)(partition->part_offset/512),
	    i++);
      }
#endif
    }
    log_flush();
    do
    {
      list_part=ask_structure(disk_car,list_part,verbose,current_cmd);
      if(disk_car->arch->test_structure(list_part)==0)
      {
	res_interface_write=ask_write_partition_table(list_part, disk_car, verbose, dump_ind, ask_part_order, expert, current_cmd, &menu, &fast_mode);
      }
      else
      {
	display_message("Invalid partition structure.\n");
	res_interface_write=0;
      }
    } while(res_interface_write == 'R');
    part_free_list(list_part);
  } while(res_interface_write=='S');
  return 0;
}
