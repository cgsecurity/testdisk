/*

    File: file_mpg.c

    Copyright (C) 1998-2005,2007-2009 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include <stdio.h>
#include "types.h"
#include "filegen.h"


static void register_header_check_mpg(file_stat_t *file_stat);
static int header_check_mpg(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);
static int data_check_mpg(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery);

const file_hint_t file_hint_mpg= {
  .extension="mpg",
  .description="Moving Picture Experts Group video",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_mpg
};

static const unsigned char mpg_header[3]= {0x00, 0x00, 0x01};

static void register_header_check_mpg(file_stat_t *file_stat)
{
  register_header_check(0, mpg_header,sizeof(mpg_header), &header_check_mpg, file_stat);
}

static int header_check_mpg(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(file_recovery!=NULL && file_recovery->file_stat!=NULL && file_recovery->file_stat->file_hint==&file_hint_mpg)
    return 0;
  /* MPEG-1 http://andrewduncan.ws/MPEG/MPEG-1.ps
   * MPEG-2 Program stream http://neuron2.net/library/mpeg2/iso13818-1.pdf
   */
  /*	MPEG-2
       pack_start_code=0x000001BA                     32
       '01'                                            2
       system_clock_reference_base [32..30]            3
       marker_bit                                      1
       system_clock_reference_base [29..15]           15
       marker_bit                                      1
       system_clock_reference_base [14..0]            15
       marker_bit                                      1
       system_clock_reference_extension                9 uimsbf
       marker_bit                                      1
       program_mux_rate                               22 uimsbf
       marker_bit                                      1
       marker_bit                                      1
       reserved                                        5
       pack_stuffing_length                            3 uimsbf
       ...
  */
  /*   ISO/IEC INTERNATIONAL 13818-1 STANDARD
  	system_header_start_code           32
	header_length                      16
	marker_bit                          1
	rate_bound                         22
	marker_bit                          1
	audio_bound                         6
	fixed_flag                          1
	CSPS_flag                           1
	system_audio_lock_flag              1
	system_video_lock_flag              1
	marker_bit                          1
	video_bound                         5
	packet_rate_restriction_flag        1
	reserved_bits                       7
  */

  if(buffer[0]==0x00 && buffer[1]==0x00 && buffer[2]==0x01 &&
    (
     /* MPEG-1 system header start code, several per file */
     (buffer[3]==0xBA && (buffer[4]&0xF1)==0x21) ||
     /* MPEG2 system header start code, several per file */
     (buffer[3]==0xBA && (buffer[4]&0xc4)==0x44) ||
     /* MPEG-1 system header start code */
     (buffer[3]==0xBB && (buffer[6]&0x80)==0x80 && (buffer[8]&0x01)==0x01) ||
     /* MPEG-1 sequence header code, horizontal size>0 && vertical size>0, aspect_ratio!=0 */
     (buffer[3]==0xB3 &&
      (buffer[4]<<4)+(buffer[5]>>4)>0 &&
      ((buffer[5]&&0x0f)<<8)+buffer[6]>0 &&
      (buffer[7]>>4)!=0 && (buffer[7]>>4)!=15) ||
     /* ISO/IEC 14496-2 (MPEG-4 video) ELEMENTARY VIDEO HEADER - visual object sequence start code */
     /* (buffer[3]==0xB0) || */
     /* ISO/IEC 14496-2 (MPEG-4 video) ELEMENTARY VIDEO HEADER - visual object start code */
     (buffer[3]==0xB5 && (buffer[4]&0xf0)==0x80)
    )
    )
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_mpg.extension;
    file_recovery_new->data_check=&data_check_mpg;
    file_recovery_new->file_check=&file_check_size;
    return 1;
  }
  return 0;
}

static int data_check_mpg(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  const unsigned char padding_iso_end[8]=     {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x01, 0xB9};
  const unsigned char sequence_end_iso_end[8]={0x00, 0x00, 0x01, 0xB7, 0x00, 0x00, 0x01, 0xB9};
  unsigned int i;
  /* search padding + end code */
  if(buffer_size>=8 && memcmp(&buffer[buffer_size/2-4], padding_iso_end, sizeof(padding_iso_end))==0)
  {
    file_recovery->calculated_file_size=file_recovery->file_size+4;
    return 2;
  }
  /* search video sequence end followed by iso end code*/
  if(buffer_size>=14)
  {
    for(i=buffer_size/2-7; i<buffer_size-7; i++)
    {
      if(buffer[i]==0x00 && memcmp(&buffer[i], sequence_end_iso_end, sizeof(sequence_end_iso_end))==0)
      {
	file_recovery->calculated_file_size=file_recovery->file_size+i+sizeof(sequence_end_iso_end)-buffer_size/2;
	return 2;
      }
    }
  }
  /* some files don't end by iso end code, so continue... */
  file_recovery->calculated_file_size=file_recovery->file_size+(buffer_size/2);
  return 1;
}
