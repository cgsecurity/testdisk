/*

    File: file_fits.c

    Copyright (C) 2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fits)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#include <stdio.h>
#include "types.h"
#include "filegen.h"
#ifdef DEBUG_FITS
#include "log.h"
#endif

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_fits(file_stat_t *file_stat);

const file_hint_t file_hint_fits= {
  .extension="fits",
  .description="Flexible Image Transport System",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_fits
};

/* FITS is the standard data format used in astronomy, it's also used in quantic physics
 * Image metadata is store in an ASCII header
 * Specification can be found at http://fits.gsfc.nasa.gov/ 	*/

/*@
  @ requires \valid_read(str + (0 .. 80-1));
  @ terminates \true;
  @ assigns \nothing;
  @*/
static uint64_t fits_get_val(const unsigned char *str)
{
  unsigned int i;
  uint64_t val=0;
  /*@
    @ loop assigns i;
    @ loop variant 80 - i;
    @*/
  for(i=0;i<80 && str[i]!='=';i++);
  i++;
  /*@
    @ loop assigns i;
    @ loop variant 80 - i;
    @*/
  for(;i<80 && str[i]==' ';i++);
  if(i<80 && str[i]=='-')
    i++;
  /*@
    @ loop invariant val < PHOTOREC_MAX_FILE_SIZE;
    @ loop assigns i,val;
    @ loop variant 80 - i;
    @*/
  for(;i<80 && str[i]>='0' && str[i]<='9';i++)
  {
    val=val*10+(str[i]-'0');
    if(val >= PHOTOREC_MAX_FILE_SIZE)
      return val;
  }
  return val;
}

/*@
  @ requires buffer_size > 0;
  @ requires \valid_read(buffer + (0 .. buffer_size-1));
  @ requires \valid(file_recovery);
  @ requires \valid(i_pointer);
  @ requires \separated(buffer+(..), file_recovery, i_pointer);
  @ requires *i_pointer < buffer_size;
  @ assigns *i_pointer, file_recovery->time;
  @ ensures \old(*i_pointer) == *i_pointer || (\old(*i_pointer) <= *i_pointer < buffer_size + 80);
  @*/
static uint64_t fits_info(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery, unsigned int *i_pointer)
{
  uint64_t naxis_size=1;
  unsigned int i=*i_pointer;
  if( i+80 >= buffer_size)
    return 1;
  /*@ assert *i_pointer == i; */
  /* Header is composed of 80 character fixed-length strings */
  /*@
    @ loop invariant *i_pointer <= i;
    @ loop invariant i < buffer_size + 80;
    @ loop assigns i, naxis_size, file_recovery->time;
    @ loop variant buffer_size + 80 - i;
    @*/
  for(; i+80 < buffer_size &&
      memcmp(&buffer[i], "END ", 4)!=0;
      i+=80)
  {
    if(naxis_size > PHOTOREC_MAX_FILE_SIZE)
      naxis_size=0;
    /*@ assert naxis_size <= PHOTOREC_MAX_FILE_SIZE; */
    if(memcmp(&buffer[i], "BITPIX",6)==0)
    {
      const uint64_t tmp=fits_get_val(&buffer[i]);
      if(tmp > PHOTOREC_MAX_FILE_SIZE)
	naxis_size=0;
      else if(tmp>0)
      { /* FIXME overflow */
	naxis_size*=(tmp+8-1)/8;
      }
    }
    else if(memcmp(&buffer[i], "NAXIS ",6)==0)
    {
      /* NAXIS - range [0:999] */
      if(fits_get_val(&buffer[i])==0)
	naxis_size=0;
    }
    else if(memcmp(&buffer[i], "NAXIS",5)==0)
    {
      /* NAXISn */
      const uint64_t naxis_val=fits_get_val(&buffer[i]);
      if(naxis_val > PHOTOREC_MAX_FILE_SIZE)
	naxis_size=0;
      else
      { /* FIXME overflow */
	naxis_size*=naxis_val;
      }
    }
    else if(memcmp(&buffer[i], "CREA_DAT=", 9)==0)
    {
      /*	  CREA_DAT= '2007-08-29T16:22:09' */
      /*	             0123456789012345678  */
      unsigned int j;
      /*@
        @ loop assigns j;
	@ loop variant 80 - j;
	@*/
      for(j=0;j<80 && buffer[i+j]!='\'';j++);
      if(j<60 && buffer[i+j]=='\'')
      {
	file_recovery->time=get_time_from_YYYY_MM_DD_HH_MM_SS(&buffer[i+j+1]);
      }
    }
  }
  /*@ assert *i_pointer <= i < buffer_size + 80; */
  *i_pointer=i;
  return naxis_size;
}

/*@
  @ requires file_recovery->data_check==&data_check_fits;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ assigns file_recovery->calculated_file_size, file_recovery->time;
  @*/
static data_check_t data_check_fits(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@
    @ loop assigns file_recovery->calculated_file_size, file_recovery->time;
    @ loop variant file_recovery->file_size + buffer_size/2 - (file_recovery->calculated_file_size + 8);
    @*/
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 8 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size + buffer_size/2 - file_recovery->file_size;
    /*@ assert 0 <= i < buffer_size - 8; */
    /*@ assert \valid_read(&buffer[i] + (0 .. 8-1)); */
    if(memcmp(&buffer[i], "XTENSION", 8)!=0)
      break;
    {
      unsigned int new_i=i;
      /*@ assert i==new_i; */
      const uint64_t tmp=fits_info(buffer, buffer_size, file_recovery, &new_i);
      /*@ assert (i==new_i && i < buffer_size - 8) || (i <= new_i < buffer_size + 80); */
      /*@ assert i<=new_i; */
      const unsigned int diff=new_i-i;
#ifdef DEBUG_FITS
      log_info("data_check_fits cfr=%llu fs=%llu i=%u buffer_size=%u\n",
	  (long long unsigned)file_recovery->calculated_file_size,
	  (long long unsigned)file_recovery->file_size,
	  new_i, buffer_size);
#endif
      if(tmp==0)
      {
	file_recovery->data_check=NULL;
	file_recovery->file_check=NULL;
	return DC_CONTINUE;
      }
      /*@ assert diff < buffer_size + 80; */
      file_recovery->calculated_file_size+=(uint64_t)(diff+2880-1)/2880*2880+(tmp+2880-1)/2880*2880;
    }
  }
  if(file_recovery->file_size + buffer_size/2 >= file_recovery->calculated_file_size)
    return DC_STOP;
  return DC_CONTINUE;
}

/*@
  @ requires buffer_size >= 10;
  @ requires separation: \separated(&file_hint_fits, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_fits(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  unsigned int i=0;
  uint64_t naxis_size_max=0;
  if(file_recovery_new->blocksize >= 80)
    naxis_size_max=fits_info(buffer, buffer_size, file_recovery_new, &i);
  if(naxis_size_max > PHOTOREC_MAX_FILE_SIZE)
    return 0;
  if(naxis_size_max !=0 && naxis_size_max < 2880)
    return 0;
  reset_file_recovery(file_recovery_new);
#ifdef DJGPP
  file_recovery_new->extension="fts";
#else
  file_recovery_new->extension=file_hint_fits.extension;
#endif
  file_recovery_new->min_filesize=2880;
  if(naxis_size_max==0)
    return 1;
  /* File is composed of several 2880-bytes blocks */
  file_recovery_new->data_check=&data_check_fits;
  file_recovery_new->file_check=&file_check_size;
  file_recovery_new->calculated_file_size=(i+2880-1)/2880*2880+(naxis_size_max+2880-1)/2880*2880;
  /*@ assert valid_file_recovery(file_recovery_new); */
  return 1;
}

static void register_header_check_fits(file_stat_t *file_stat)
{
  register_header_check(0, "SIMPLE  =", 9, &header_check_fits, file_stat);
}
#endif
