/*

    File: partauto.c

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
#include <stdio.h>
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include "types.h"
#include "common.h"
#include "list.h"
#include "fnctdsk.h"
#include "partauto.h"
#include "log.h"

extern const arch_fnct_t arch_none;
#if !defined(SINGLE_PARTITION_TYPE) || defined(SINGLE_PARTITION_GPT)
extern const arch_fnct_t arch_gpt;
#endif
#if !defined(SINGLE_PARTITION_TYPE) || defined(SINGLE_PARTITION_HUMAX)
extern const arch_fnct_t arch_humax;
#endif
#if !defined(SINGLE_PARTITION_TYPE) || defined(SINGLE_PARTITION_I386)
extern const arch_fnct_t arch_i386;
#endif
#if !defined(SINGLE_PARTITION_TYPE) || defined(SINGLE_PARTITION_MAC)
extern const arch_fnct_t arch_mac;
#endif
#if !defined(SINGLE_PARTITION_TYPE) || defined(SINGLE_PARTITION_SUN)
extern const arch_fnct_t arch_sun;
#endif
#if !defined(SINGLE_PARTITION_TYPE) || defined(SINGLE_PARTITION_XBOX)
extern const arch_fnct_t arch_xbox;
#endif

void autodetect_arch(disk_t *disk, const arch_fnct_t *arch)
{
  list_part_t *list_part=NULL;
#ifdef DEBUG_PARTAUTO
  const int verbose=2;
#else
  const int verbose=0;
  unsigned int old_levels;
  old_levels=log_set_levels(0);
#endif
  {
    disk->arch=&arch_none;
    list_part=arch_none.read_part(disk,verbose,0);
    /*@ assert valid_list_part(list_part); */
    if(list_part!=NULL && list_part->part!=NULL && list_part->part->upart_type==UP_UNK)
    {
      part_free_list(list_part);
      list_part=NULL;
    }
  }
#if !defined(SINGLE_PARTITION_TYPE) || defined(SINGLE_PARTITION_XBOX)
  if(list_part==NULL)
  {
    disk->arch=&arch_xbox;
    list_part=arch_xbox.read_part(disk,verbose,0);
    /*@ assert valid_list_part(list_part); */
  }
#endif
#if !defined(SINGLE_PARTITION_TYPE) || defined(SINGLE_PARTITION_GPT)
  if(list_part==NULL)
  {
    disk->arch=&arch_gpt;
    list_part=arch_gpt.read_part(disk,verbose,0);
    /*@ assert valid_list_part(list_part); */
  }
#endif
#if !defined(SINGLE_PARTITION_TYPE) || defined(SINGLE_PARTITION_HUMAX)
  if(list_part==NULL)
  {
    disk->arch=&arch_humax;
    list_part=arch_humax.read_part(disk,verbose,0);
    /*@ assert valid_list_part(list_part); */
  }
#endif
#if !defined(SINGLE_PARTITION_TYPE) || defined(SINGLE_PARTITION_I386)
  if(list_part==NULL)
  {
    disk->arch=&arch_i386;
    list_part=arch_i386.read_part(disk,verbose,0);
    /*@ assert valid_list_part(list_part); */
  }
#endif
#if !defined(SINGLE_PARTITION_TYPE) || defined(SINGLE_PARTITION_SUN)
  if(list_part==NULL)
  {
    disk->arch=&arch_sun;
    list_part=arch_sun.read_part(disk,verbose,0);
    /*@ assert valid_list_part(list_part); */
  }
#endif
#if !defined(SINGLE_PARTITION_TYPE) || defined(SINGLE_PARTITION_MAC)
  if(list_part==NULL)
  {
    disk->arch=&arch_mac;
    list_part=arch_mac.read_part(disk,verbose,0);
    /*@ assert valid_list_part(list_part); */
  }
#endif
#ifndef DEBUG_PARTAUTO
  log_set_levels(old_levels);
#endif
  if(list_part!=NULL)
  {
    disk->arch_autodetected=disk->arch;
    log_info("Partition table type (auto): %s\n", disk->arch->part_name);
    part_free_list(list_part);
    return ;
  }
  disk->arch_autodetected=NULL;
  if(arch!=NULL)
  {
    disk->arch=arch;
  }
  else
  {
#ifdef DISABLED_FOR_FRAMAC
    disk->arch=&arch_none;
#elif defined(TARGET_SOLARIS) && (!defined(SINGLE_PARTITION_TYPE) || defined(SINGLE_PARTITION_SUN))
    disk->arch=&arch_sun;
#elif defined(__APPLE__) && defined(TESTDISK_LSB) && (!defined(SINGLE_PARTITION_TYPE) || defined(SINGLE_PARTITION_GPT))
    disk->arch=&arch_gpt;
#elif defined(__APPLE__) && !defined(TESTDISK_LSB) && (!defined(SINGLE_PARTITION_TYPE) || defined(SINGLE_PARTITION_MAC))
    disk->arch=&arch_mac;
#else
#if defined(__CYGWIN__) || defined(__MINGW32__)
    if(disk->device[0]=='\\' && disk->device[1]=='\\' && disk->device[2]=='.' && disk->device[3]=='\\' && disk->device[5]==':')
      disk->arch=&arch_none;
    else
#endif
#if !defined(SINGLE_PARTITION_TYPE) || (defined(SINGLE_PARTITION_I386) && defined(SINGLE_PARTITION_GPT))
    /* PC/Intel partition table is limited to 2 TB, 2^32 512-bytes sectors */
    if(disk->disk_size < ((uint64_t)1<<(32+9)))
      disk->arch=&arch_i386;
    else
      disk->arch=&arch_gpt;
#else
    disk->arch=&arch_none;
#endif
#endif
  }
  log_info("Partition table type defaults to %s\n", disk->arch->part_name);
}
