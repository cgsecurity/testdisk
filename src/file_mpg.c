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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_mpg)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "common.h"
#include "filegen.h"
#include "log.h"

/*@
  @ requires valid_register_header_check(file_stat);
  @*/
static void register_header_check_mpg(file_stat_t *file_stat);

const file_hint_t file_hint_mpg= {
  .extension="mpg",
  .description="Moving Picture Experts Group video",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_mpg
};

/*@
  @ requires \valid_read(buffer + (0 .. 13));
  @ terminates \true;
  @ assigns \nothing;
  @*/
static unsigned int calculate_packet_size(const unsigned char *buffer)
{
  /* http://dvd.sourceforge.net/dvdinfo/mpeghdrs.html */
  if(buffer[0]!=0 || buffer[1]!=0 || buffer[2]!=1)
    return 0;
  switch(buffer[3])
  {
    /* Pack header: */
    case 0xBA:
      if((buffer[4]&0xc4)==0x44 && (buffer[6]&4)==4 && (buffer[8]&4)==4 &&
	  (buffer[9]&1)==1 && (buffer[12]&3)==3)
	return (buffer[13] & 0x7) + 14;
      if((buffer[4]&0xF1)==0x21 && (buffer[6]&1)==1 && (buffer[8]&1)==1 &&
	  (buffer[9]&0x80)==0x80 && (buffer[11]&1)==1)
	return 12;
      return 0;
      /* Sequence Header */
    case 0xB3:
      if((buffer[10]&0x20)==0x20)
      {
	if((buffer[11]&3)!=0)
	  return 12+64;	/* quantiser matrix */
	return 12;
      }
      return 0;
      /* Extension */
    case 0xB5:
      /* Sequence_Extension */
      if((buffer[4]&0xF0)==0x10 && (buffer[7]&1)==1)
	return 10;
      /* Sequence_Display_Extension without color description */
      if((buffer[4]&0xF0)==0x20 && (buffer[4]&1)==0 && (buffer[6]&2)==2)
	return 9;
      /* Sequence_Display_Extension with color description */
      if((buffer[4]&0xF0)==0x20 && (buffer[4]&1)==1 && (buffer[9]&2)==2)
	return 12;
      /* Picture_Coding_Extension */
      if((buffer[4]&0xF0)==0x40)
      {
	if((buffer[8]&0x40)==0)
	  return 9;
	else
	  return 11;
      }
      return 0;
    case 0xB8: /* Group of Pictures */
      if((buffer[5]&0x40)==0x40)
	return 8;
      return 0;
    case 0xB9: /* EOC */
      return 4;
    case 0xBD:		/* Private stream 1 (non MPEG audio, subpictures) */
    case 0xC0 ... 0xDF: /* Mpeg Audio stream */
    case 0xE0 ... 0xEF: /* Mpeg Video stream */
#if 0
      {
	uint32_t pts = 0;
	// This is mpeg 2:
	if((buffer[6] & 0xC0) == 0x80 &&
	    // PTS DTS flags
	    (buffer[7] >> 7)==1)
	{
	  pts = ((buffer[13] | (buffer[12] << 8) ) >> 1) |
	    ((buffer[11] | (buffer[10] << 8) ) >> 1) << 15;

	  //      log_debug("MPG2 (%u - 0x%02X)PTS is 0x%08X\n", current->id,buffer[3], pts);
	  // This is mpeg 1. The PTS goes right after the header and must
	  // have the bits 0x21 set:
	}
	else if((buffer[6] & 0x21)==0x21)
	{
	  pts = ((buffer[10] | (buffer[9] << 8) ) >> 1) | ((buffer[8] | (buffer[7] << 8) ) >> 1) << 15;
	  //log_debug("MPG1 (%u - 0x%02X)PTS is 0x%08X\n", current->id,buffer[3], pts);
	};
      }
#endif
      return (buffer[4] << 8) + buffer[5] + 6;
    case 0xBB:	/* System header */
    case 0xBE:	/* Padding stream */
    case 0xBF:	/* Private Stream 2 */
      return (buffer[4] << 8) + buffer[5] + 6;
    case 0:
      return 0;
    default:
#ifdef DEBUG_MPG
      log_info("I dont know how to handle 0x%02X\n", buffer[3]);
#endif
      return 0;
  }
}

/*@
  @ requires file_recovery->data_check==&data_check_mpg;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ terminates \true;
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ assigns file_recovery->calculated_file_size;
  @*/
static data_check_t data_check_mpg(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@
    @ loop assigns file_recovery->calculated_file_size;
    @ loop variant file_recovery->file_size + buffer_size/2 - (file_recovery->calculated_file_size + 14);
    @*/
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 14 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size + buffer_size/2 - file_recovery->file_size;
    /*@ assert i < buffer_size - 14; */
    const unsigned int ret=calculate_packet_size(&buffer[i]);
#ifdef DEBUG_MPG
    log_info("data_check_mpg %llu 0x%02x %u\n", (long long unsigned)file_recovery->calculated_file_size, buffer[i+3], ret);
#endif
    if(ret==0)
      return DC_STOP;
    /*@ assert ret > 0; */
    file_recovery->calculated_file_size+=ret;
  }
  return DC_CONTINUE;
}

/*@
  @ requires \valid(file_recovery_new);
  @ terminates \true;
  @ ensures  valid_file_recovery(file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_mpg_found(file_recovery_t *file_recovery_new)
{
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_mpg.extension;
  if(file_recovery_new->blocksize < 14)
    return 1;
  file_recovery_new->data_check=&data_check_mpg;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

/*@
  @ requires buffer_size >= 13;
  @ requires \valid_read(buffer+(0..buffer_size-1));
  @ terminates \true;
  @ assigns \nothing;
  @*/
static int is_valid_packet_size(const unsigned char *buffer, const unsigned int buffer_size)
{
  unsigned int i=0;
  /*@
    @ loop assigns i;
    @ loop variant 512 - (i+14);
    @*/
  while(i+14 < td_min(buffer_size,512U))
  {
    /*@ assert i < buffer_size - 14; */
    const unsigned int ret=calculate_packet_size(&buffer[i]);
    if(ret==0)
      return 0;
    /*@ assert ret > 0; */
    i+=ret;
  }
  return 1;
}

/*@
  @ requires buffer_size >= 13;
  @ requires separation: \separated(&file_hint_mpg, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @*/
static int header_check_mpg_Pack(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(is_valid_packet_size(buffer, buffer_size)==0)
    return 0;
  /* MPEG-1 http://andrewduncan.ws/MPEG/MPEG-1.ps */
  /* pack start code 0x1BA + MPEG-1 + SCR=0 */
  if((buffer[4]&0xF1)==0x21 && (buffer[6]&1)==1 && (buffer[8]&1)==1 &&
      (buffer[9]&0x80)==0x80 && (buffer[11]&1)==1)
  {
    if(buffer[5]==0 && buffer[6]==1 && buffer[7]==0 && buffer[8]==1)
    {
      return header_mpg_found(file_recovery_new);
    }
    if(file_recovery->file_stat!=NULL &&
	file_recovery->file_check!=NULL &&
	file_recovery->file_stat->file_hint==&file_hint_mpg)
    {
      header_ignored(file_recovery_new);
      return 0;
    }
    return header_mpg_found(file_recovery_new);
  }
  /* MPEG-2 Program stream http://neuron2.net/library/mpeg2/iso13818-1.pdf */
  /* MPEG2 system header start code, several per file */
  if((buffer[4]&0xc4)==0x44 && (buffer[6]&4)==4 && (buffer[8]&4)==4 && (buffer[9]&1)==1 && (buffer[12]&3)==3)
  {
    /*
     *       '01'                                            2	01
     system_clock_reference_base [32..30]            3	00 0
     marker_bit                                      1	1
     system_clock_reference_base [29..15]           15	00		buffer[4]=0x44
     0000 0000	buffer[5]=0x00
     0000 0
     marker_bit                                      1	1
     system_clock_reference_base [14..0]            15	00		buffer[6]=0x04

     0000 0000	buffer[7]=0x00
     0000
     0
     marker_bit                                      1	1
     system_clock_reference_extension                9 uimsbf
     marker_bit                                      1
     => 0100 0100
     */

    if(buffer[4]==0x44 && buffer[5]==0 && buffer[6]==4 && buffer[7]==0 && (buffer[8]&0xfc)==4)
    { /* SCR=0 */
      return header_mpg_found(file_recovery_new);
    }
    if(file_recovery->file_stat!=NULL &&
	file_recovery->file_check!=NULL &&
	file_recovery->file_stat->file_hint==&file_hint_mpg)
    {
      header_ignored(file_recovery_new);
      return 0;
    }
    return header_mpg_found(file_recovery_new);
  }
  return 0;
}

/*@
  @ requires buffer_size >= 12;
  @ requires separation: \separated(&file_hint_mpg, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @*/
static int header_check_mpg_System(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /* MPEG-1 http://andrewduncan.ws/MPEG/MPEG-1.ps */
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

  /* MPEG-1 system header start code */
  if((buffer[6]&0x80)==0x80 && (buffer[8]&0x01)==0x01 && buffer[11]==0xff)
  {
    if(is_valid_packet_size(buffer, buffer_size)==0)
      return 0;
    if(file_recovery->file_stat!=NULL &&
	file_recovery->file_check!=NULL &&
	file_recovery->file_stat->file_hint==&file_hint_mpg)
    {
      header_ignored(file_recovery_new);
      return 0;
    }
    return header_mpg_found(file_recovery_new);
  }
  return 0;
}

/*@
  @ requires buffer_size >= 11;
  @ requires separation: \separated(&file_hint_mpg, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @*/
static int header_check_mpg_Sequence(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /* MPEG-1 sequence header code 0x1B3 */
  /* horizontal size>0 */
  if((buffer[4]<<4)+(buffer[5]>>4)>0 &&
      /* vertical size>0 */
      ((buffer[5]&0x0f)<<8)+buffer[6]>0 &&
      /* aspect_ratio */
      (buffer[7]>>4)!=0 && (buffer[7]>>4)!=15 &&
      /* picture rate*/
      (buffer[7]&0x0f)!=0 && (buffer[7]&0xf)!=15 &&
      /* bit rate */
      (buffer[8]!=0 || buffer[9]!=0 || (buffer[10]&0xc0)!=0) &&
      /* marker */
      (buffer[10]&0x20)==0x20)
  {
    if(is_valid_packet_size(buffer, buffer_size)==0)
      return 0;
    if(file_recovery->file_stat!=NULL &&
	file_recovery->file_check!=NULL &&
	file_recovery->file_stat->file_hint==&file_hint_mpg)
    {
      header_ignored(file_recovery_new);
      return 0;
    }
    return header_mpg_found(file_recovery_new);
  }
  return 0;
}

/*@
  @ requires buffer_size >= 6;
  @ requires separation: \separated(&file_hint_mpg, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ terminates \true;
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @*/
static int header_check_mpg4_ElemVideo(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /* ISO/IEC 14496-2 (MPEG-4 video) ELEMENTARY VIDEO HEADER - visual object start code */
  /* is_visual_object_identifier */
  if((buffer[4]&0xf0)==0x80 &&
      /* visual_object_verid */
      (((buffer[4]>>3)&0x0f)==1 || ((buffer[4]>>3)&0x0f)==2) &&
      /* visual_object_priority */
      (buffer[4]&0x7)!=0 &&
      /* visual_object_type */
      (buffer[5]>>4)!=0 && (buffer[5]>>4)!=0x0f
    )
  {
    if(is_valid_packet_size(buffer, buffer_size)==0)
      return 0;
    if(file_recovery->file_stat!=NULL &&
	file_recovery->file_check!=NULL &&
	file_recovery->file_stat->file_hint==&file_hint_mpg)
    {
      header_ignored(file_recovery_new);
      return 0;
    }
    return header_mpg_found(file_recovery_new);
  }
  return 0;
}

static void register_header_check_mpg(file_stat_t *file_stat)
{
  static const unsigned char mpg_header_B3[4]= {0x00, 0x00, 0x01, 0xB3};
  static const unsigned char mpg_header_B5[4]= {0x00, 0x00, 0x01, 0xB5};
  static const unsigned char mpg_header_BA[4]= {0x00, 0x00, 0x01, 0xBA};
  static const unsigned char mpg_header_BB[4]= {0x00, 0x00, 0x01, 0xBB};
  register_header_check(0, mpg_header_B3,sizeof(mpg_header_B3), &header_check_mpg_Sequence, file_stat);
  register_header_check(0, mpg_header_B5,sizeof(mpg_header_B5), &header_check_mpg4_ElemVideo, file_stat);
  register_header_check(0, mpg_header_BA,sizeof(mpg_header_BA), &header_check_mpg_Pack, file_stat);
  register_header_check(0, mpg_header_BB,sizeof(mpg_header_BB), &header_check_mpg_System, file_stat);
}
#endif
