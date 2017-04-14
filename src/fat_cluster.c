/*

    File: fat_cluster.c

    Copyright (C) 1998-2009 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include "types.h"
#include "common.h"
#include "intrf.h"
#include "intrfn.h"
#include "log.h"
#include "fat_cluster.h"
#include "fat.h"
#include "fat_common.h"

/* Using a couple of inodes of "." directory entries, get the cluster size and where the first cluster begins.
 * */
int find_sectors_per_cluster(disk_t *disk_car, partition_t *partition, const int verbose, const int dump_ind, unsigned int *sectors_per_cluster, uint64_t *offset_org, const upart_type_t upart_type)
{
  unsigned int nbr_subdir=0;
  sector_cluster_t sector_cluster[10];
  uint64_t offset;
  uint64_t skip_offset;
  int ind_stop=0;
  unsigned char *buffer=(unsigned char *)MALLOC(disk_car->sector_size);
#ifdef HAVE_NCURSES
  wmove(stdscr,22,0);
  wattrset(stdscr, A_REVERSE);
  waddstr(stdscr,"  Stop  ");
  wattroff(stdscr, A_REVERSE);
#endif
  /* 2 fats, maximum cluster size=128 */
  skip_offset=(uint64_t)((partition->part_size-32*disk_car->sector_size)/disk_car->sector_size/128*3/2/disk_car->sector_size*2)*disk_car->sector_size;
  if(verbose>0)
  {
    log_verbose("find_sectors_per_cluster skip_sectors=%lu (skip_offset=%lu)\n",
	(unsigned long)(skip_offset/disk_car->sector_size),
	(unsigned long)skip_offset);
  }
  for(offset=skip_offset;
      offset<partition->part_size && !ind_stop && nbr_subdir<10;
      offset+=disk_car->sector_size)
  {
#ifdef HAVE_NCURSES
    if((offset&(1024*disk_car->sector_size-1))==0)
    {
      wmove(stdscr,9,0);
      wclrtoeol(stdscr);
      wprintw(stdscr,"Search subdirectory %10lu/%lu %u",(unsigned long)(offset/disk_car->sector_size),(unsigned long)(partition->part_size/disk_car->sector_size),nbr_subdir);
      wrefresh(stdscr);
      ind_stop|=check_enter_key_or_s(stdscr);
    }
#endif
    if((unsigned)disk_car->pread(disk_car, buffer, disk_car->sector_size, partition->part_offset + offset) == disk_car->sector_size)
    {
      if(buffer[0]=='.' && is_fat_directory(buffer))
      {
	const unsigned long int cluster=fat_get_cluster_from_entry((const struct msdos_dir_entry *)buffer);
	log_info("sector %lu, cluster %lu\n",
	    (unsigned long)(offset/disk_car->sector_size), cluster);
	sector_cluster[nbr_subdir].cluster=cluster;
	sector_cluster[nbr_subdir].sector=offset/disk_car->sector_size;
	nbr_subdir++;
#ifdef HAVE_NCURSES
	if(dump_ind>0)
	  dump_ncurses(buffer,disk_car->sector_size);
#endif
      }
    }
  }
  free(buffer);
  return find_sectors_per_cluster_aux(sector_cluster,nbr_subdir,sectors_per_cluster,offset_org,verbose,partition->part_size/disk_car->sector_size, upart_type);
}

int find_sectors_per_cluster_aux(const sector_cluster_t *sector_cluster, const unsigned int nbr_sector_cluster,unsigned int *sectors_per_cluster, uint64_t *offset, const int verbose, const unsigned long int part_size_in_sectors, const upart_type_t upart_type)
{
  cluster_offset_t *cluster_offset;
  unsigned int i,j;
  unsigned int nbr_sol=0;
  if(nbr_sector_cluster<2)
    return 0;
  cluster_offset=(cluster_offset_t *)MALLOC(nbr_sector_cluster*nbr_sector_cluster*sizeof(cluster_offset_t));
  log_info("find_sectors_per_cluster_aux\n");
  for(i=0;i<nbr_sector_cluster-1;i++)
  {
    for(j=i+1;j<nbr_sector_cluster;j++)
    {
      if(sector_cluster[j].cluster > sector_cluster[i].cluster)
      {
        unsigned int sectors_per_cluster_tmp=(sector_cluster[j].sector-sector_cluster[i].sector)/(sector_cluster[j].cluster-sector_cluster[i].cluster);
        switch(sectors_per_cluster_tmp)
        {
          case 1:
          case 2:
          case 4:
          case 8:
          case 16:
          case 32:
          case 64:
          case 128:
            if(sector_cluster[i].sector > (uint64_t)(sector_cluster[i].cluster-2) * sectors_per_cluster_tmp)
            {
              unsigned int sol_cur;
              unsigned int found=0;
              uint64_t offset_tmp=sector_cluster[i].sector-(uint64_t)(sector_cluster[i].cluster-2)*sectors_per_cluster_tmp;
              for(sol_cur=0;sol_cur<nbr_sol && !found;sol_cur++)
              {
                if(cluster_offset[sol_cur].sectors_per_cluster==sectors_per_cluster_tmp &&
                    cluster_offset[sol_cur].offset==offset_tmp)
                {
                  if(cluster_offset[sol_cur].first_sol==i)
                  {
                    cluster_offset[sol_cur].nbr++;
                  }
                  /* log_debug("sectors_per_cluster=%u offset=%lu nbr=%u\n",cluster_offset[sol_cur].sectors_per_cluster,cluster_offset[sol_cur].offset,cluster_offset[sol_cur].nbr); */
                  found=1;
                }
              }
              if(!found)
              {
                cluster_offset[nbr_sol].sectors_per_cluster=sectors_per_cluster_tmp;
                cluster_offset[nbr_sol].offset=offset_tmp;
                cluster_offset[nbr_sol].nbr=1;
                cluster_offset[nbr_sol].first_sol=i;
                nbr_sol++;
              }
            }
            break;
        }
      }
    }
  }
  /* Show results */
  {
    unsigned int nbr_max=0;
    for(i=0;i<nbr_sol;i++)
    {
      const upart_type_t upart_type_new=no_of_cluster2part_type((part_size_in_sectors-cluster_offset[i].offset)/cluster_offset[i].sectors_per_cluster);
      if(verbose>0)
      {
        log_verbose("sectors_per_cluster=%u offset=%lu nbr=%u ",
            cluster_offset[i].sectors_per_cluster,
            cluster_offset[i].offset,
            cluster_offset[i].nbr);
        switch(upart_type_new)
        {
          case UP_FAT12:
            log_info("FAT : 12\n");
            break;
          case UP_FAT16:
            log_info("FAT : 16\n");
            break;
          case UP_FAT32:
            log_info("FAT : 32\n");
            break;
          default:	/* No compiler warning */
            break;
        }
      }
      if((upart_type==UP_UNK || upart_type==upart_type_new) &&
	  cluster_offset[i].nbr>nbr_max)
      {
	nbr_max=cluster_offset[i].nbr;
	*sectors_per_cluster=cluster_offset[i].sectors_per_cluster;
	*offset=cluster_offset[i].offset;
      }
    }
    free(cluster_offset);
    if(nbr_max==0)
      return 0;
    log_info("Selected: sectors_per_cluster=%u, cluster 2 at sector %lu, nbr=%u\n",
	*sectors_per_cluster, (long unsigned int)(*offset), nbr_max);
    return 1;
  }
}

upart_type_t no_of_cluster2part_type(const unsigned long int no_of_cluster)
{
  if(no_of_cluster<65525)
  {
    if(no_of_cluster<4085)
      return UP_FAT12;
    else
      return UP_FAT16;
  }
  return UP_FAT32;
}

