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

static void register_header_check_fits(file_stat_t *file_stat);
static int header_check_fits(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_fits= {
  .extension="fits",
  .description="Flexible Image Transport System",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_fits
};

/* FITS is the standard data format used in astronomy, it's also used in quantic physics
 * Image metadata is store in an ASCII header
 * Specification can be found at http://fits.gsfc.nasa.gov/ 	*/

static uint64_t fits_get_val(const unsigned char *str)
{
  unsigned int i;
  uint64_t val=0;
  for(i=0;i<80 && str[i]!='=';i++);
  i++;
  for(;i<80 && str[i]==' ';i++);
  if(i<80 && str[i]=='-')
    i++;
  for(;i<80 && str[i]>='0' && str[i]<='9';i++)
    val=val*10+str[i]-'0';
  return val;
}

static uint64_t fits_info(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery, unsigned int *i_pointer)
{
  uint64_t naxis_size=1;
  unsigned int i=*i_pointer;
  /* Header is composed of 80 character fixed-length strings */
  for(; i<buffer_size &&
      memcmp(&buffer[i], "END ", 4)!=0;
      i+=80)
  {
    if(memcmp(&buffer[i], "BITPIX",6)==0)
    {
      const uint64_t tmp=fits_get_val(&buffer[i]);
      if(tmp>=8)
	naxis_size*=tmp/8;
    }
    else if(memcmp(&buffer[i], "NAXIS ",6)==0)
    {
      if(fits_get_val(&buffer[i])==0)
	naxis_size=0;
    }
    else if(memcmp(&buffer[i], "NAXIS",5)==0)
    {
      const uint64_t naxis_val=fits_get_val(&buffer[i]);
      naxis_size*=naxis_val;
    }
    else if(memcmp(&buffer[i], "CREA_DAT=", 9)==0)
    {
      /*	  CREA_DAT= '2007-08-29T16:22:09' */
      /*	             0123456789012345678  */
      const unsigned char *date_asc;
      unsigned int j;
      for(j=0,date_asc=&buffer[i];j<80 && *date_asc!='\'';j++,date_asc++);
      if(j<60 && *date_asc=='\'')
      {
	struct tm tm_time;
	memset(&tm_time, 0, sizeof(tm_time));
	date_asc++;
	tm_time.tm_sec=(date_asc[17]-'0')*10+(date_asc[18]-'0');      /* seconds 0-59 */
	tm_time.tm_min=(date_asc[14]-'0')*10+(date_asc[15]-'0');      /* minutes 0-59 */
	tm_time.tm_hour=(date_asc[11]-'0')*10+(date_asc[12]-'0');     /* hours   0-23*/
	tm_time.tm_mday=(date_asc[8]-'0')*10+(date_asc[9]-'0');	/* day of the month 1-31 */
	tm_time.tm_mon=(date_asc[5]-'0')*10+(date_asc[6]-'0')-1;	/* month 0-11 */
	tm_time.tm_year=(date_asc[0]-'0')*1000+(date_asc[1]-'0')*100+
	  (date_asc[2]-'0')*10+(date_asc[3]-'0')-1900;        	/* year */
	tm_time.tm_isdst = -1;	/* unknown daylight saving time */
	file_recovery->time=mktime(&tm_time);
      }
    }
  }
  *i_pointer=i;
  return naxis_size;
}

static data_check_t data_check_fits(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 8 < file_recovery->file_size + buffer_size/2)
  {
    unsigned int i=file_recovery->calculated_file_size - file_recovery->file_size + buffer_size/2;
    if(memcmp(&buffer[i], "XTENSION", 8)!=0)
    break;
    {
      const unsigned int i_org=i;
      const uint64_t tmp=fits_info(buffer, buffer_size, file_recovery, &i);
#ifdef DEBUG_FITS
      log_info("data_check_fits cfr=%llu fs=%llu i=%u buffer_size=%u\n",
	  (long long unsigned)file_recovery->calculated_file_size,
	  (long long unsigned)file_recovery->file_size,
	  i, buffer_size);
#endif
      if(tmp==0)
      {
	file_recovery->data_check=NULL;
	file_recovery->file_check=NULL;
	return DC_CONTINUE;
      }
      file_recovery->calculated_file_size+=(i-i_org+2880-1)/2880*2880+(tmp+2880-1)/2880*2880;
    }
  }
  if(file_recovery->file_size + buffer_size/2 >= file_recovery->calculated_file_size)
    return DC_STOP;
  return DC_CONTINUE;
}

static int header_check_fits(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  unsigned int i=0;
  uint64_t naxis_size_max=0;
  reset_file_recovery(file_recovery_new);
#ifdef DJGPP
  file_recovery_new->extension="fts";
#else
  file_recovery_new->extension=file_hint_fits.extension;
#endif
  file_recovery_new->min_filesize=2880;
  if(file_recovery_new->blocksize < 80)
    return 1;
  {
    const uint64_t tmp=fits_info(buffer, buffer_size, file_recovery_new, &i);
    if(tmp==0)
      return 1;
    if(naxis_size_max < tmp && tmp > 1)
      naxis_size_max=tmp;
  }
  /* File is composed of several 2880-bytes blocks */
  file_recovery_new->data_check=&data_check_fits;
  file_recovery_new->file_check=&file_check_size;
  file_recovery_new->calculated_file_size=(i+2880-1)/2880*2880+(naxis_size_max+2880-1)/2880*2880;
  return 1;
}

static void register_header_check_fits(file_stat_t *file_stat)
{
  register_header_check(0, "SIMPLE  =", 9, &header_check_fits, file_stat);
}
