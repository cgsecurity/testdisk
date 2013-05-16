/*

    File: phnc.c

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

#ifdef HAVE_NCURSES
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include "types.h"
#include "common.h"
#include "intrf.h"
#include "intrfn.h"
#include "filegen.h"
#include "photorec.h"
#include "phnc.h"

void photorec_info(WINDOW *window, const file_stat_t *file_stats)
{
  unsigned int i;
  unsigned int nbr;
  unsigned int others=0;
  file_stat_t *new_file_stats;
  for(i=0;file_stats[i].file_hint!=NULL;i++);
  nbr=i;
  if(nbr==0)
    return ;
  new_file_stats=(file_stat_t*)MALLOC(nbr*sizeof(file_stat_t));
  memcpy(new_file_stats, file_stats, nbr*sizeof(file_stat_t));
  qsort(new_file_stats, nbr, sizeof(file_stat_t), sorfile_stat_ts);
  for(i=0; i<10 && i<nbr && new_file_stats[i].recovered>0; i++)
  {
    wmove(window,11+i,0);
    wclrtoeol(window);
    wprintw(window, "%s: %u recovered\n",
	(new_file_stats[i].file_hint->extension!=NULL?
	 new_file_stats[i].file_hint->extension:""),
	new_file_stats[i].recovered);
  }
  for(;i<nbr && new_file_stats[i].recovered>0;i++)
    others+=new_file_stats[i].recovered;
  if(others>0)
  {
    wmove(window,11+10,0);
    wclrtoeol(window);
    wprintw(window, "others: %u recovered\n", others);
  }
  free(new_file_stats);
}

pstatus_t photorec_progressbar(WINDOW *window, const unsigned int pass, const struct ph_param *params, const uint64_t offset, const time_t current_time)
{
  const partition_t *partition=params->partition;
  const unsigned int sector_size=params->disk->sector_size;
  wmove(window,9,0);
  wclrtoeol(window);
  if(params->status==STATUS_EXT2_ON_BF || params->status==STATUS_EXT2_OFF_BF)
  {
    wprintw(window,"Bruteforce %10lu sectors remaining (test %u), ",
        (unsigned long)((offset-partition->part_offset)/sector_size),
	pass);
  }
  else
  {
    wprintw(window,"Pass %u - Reading sector %10llu/%llu, ",
	pass,
	(unsigned long long)((offset-partition->part_offset)/sector_size),
	(unsigned long long)(partition->part_size/sector_size));
  }
  if(params->status==STATUS_FIND_OFFSET)
    wprintw(window,"%u/10 headers found\n", params->file_nbr);
  else
    wprintw(window,"%u files found\n", params->file_nbr);
  wmove(window,10,0);
  wclrtoeol(window);
  if(current_time > params->real_start_time)
  {
    const time_t elapsed_time=current_time - params->real_start_time;
    wprintw(window,"Elapsed time %uh%02um%02us",
	(unsigned)(elapsed_time/60/60),
	(unsigned)(elapsed_time/60%60),
	(unsigned)(elapsed_time%60));
    if(offset > partition->part_offset && params->status!=STATUS_EXT2_ON_BF && params->status!=STATUS_EXT2_OFF_BF)
    {
      const time_t eta=(partition->part_offset+partition->part_size-1-offset)*elapsed_time/(offset-partition->part_offset);
      wprintw(window," - Estimated time to completion %uh%02um%02u\n",
	  (unsigned)(eta/3600),
	  (unsigned)((eta/60)%60),
	  (unsigned)(eta%60));
    }
  }
  photorec_info(window, params->file_stats);
  wrefresh(window);
  return(check_enter_key_or_s(window)==0?PSTATUS_OK:PSTATUS_STOP);
}
#endif
