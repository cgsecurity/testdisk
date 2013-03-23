/*

    File: file_ddf.c

    Copyright (C) 2011 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#include "types.h"
#include "filegen.h"
#include "common.h"

static void register_header_check_ddf(file_stat_t *file_stat);

const file_hint_t file_hint_ddf= {
  .extension="ddf",
  .description="Didson Data File",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_ddf
};

struct MasterHeader
{
  uint32_t m_nVersion; // VERSION_DDF_03 = 0x03464444
  uint32_t m_nFrameTotal;
  uint32_t m_nFrameRate; // requested frame rate...actual rate may differ
  uint32_t m_bHighResolution;
  uint32_t m_nNumRawBeams; // Std HF = 96, Std LF and LR HF/LF = 48, may be 64 or 128 if v5
  float    m_fSampleRate; // dependent on Window Length
  uint32_t m_nSamplesPerChannel; // always 512
  uint32_t m_nReceiverGain; // relative value, 0-40 dB
  uint32_t m_nWindowStart; // code: value in master header is initial value
  uint32_t m_nWindowLength; // code: value in master header is initial value
  uint32_t m_bReverse; // TRUE if lens down orientation
  uint32_t m_nSN; // serial number of sonar
  char     m_cDate[32]; // date string
  char     m_cHeaderID[256]; // annotation string
  int32_t  m_iUserID1; // Four user ID values displayed in header pane
  int32_t  m_iUserID2; // These values are inserted by user external via
  int32_t  m_iUserID3; // the Edit->Header ID command
  int32_t  m_iUserID4;
  uint32_t m_nStartFrame; // for snippet or truncated file, from source file
  uint32_t m_nEndFrame; // for snippet or truncated file, from source file
  uint32_t m_bTimeLapse; // flag for time lapse data recording
  uint32_t m_nRecordInterval; // interval between saved frames (N seconds)
  int32_t  m_iRadioSeconds; // 0 = N frames interval, 1 = N seconds interval
  uint32_t m_nFrameInterval; // interval between saved frames (N frames)
  uint32_t m_nFlags; // save displayed processing flags (see Table 1)
  uint32_t m_nAuxFlags; // types of aux information present (see Table 2)
  uint32_t m_nSspd; // sound velocity in water from DidsonV6.ini
  uint32_t m_n3DFlags; // reserved...currently unused
  /* Fields for v4 are added here*/
  char	   m_cRsvdData[120]; // (120) pad to 512 bytes
} __attribute__ ((__packed__));

static int header_check_aux(const unsigned char *buffer, file_recovery_t *file_recovery_new)
{
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_ddf.extension;
  if(buffer[0x43]=='-' && buffer[0x46]=='-' && buffer[0x49]=='_')
  {
    struct tm tm_time;
    memset(&tm_time, 0, sizeof(tm_time));
    tm_time.tm_sec=(buffer[0x4e]-'0')*10+(buffer[0x4f]-'0');      /* seconds 0-59 */
    tm_time.tm_min=(buffer[0x4c]-'0')*10+(buffer[0x4d]-'0');      /* minutes 0-59 */
    tm_time.tm_hour=(buffer[0x4a]-'0')*10+(buffer[0x4b]-'0');      /* hours   0-23*/
    tm_time.tm_mday=(buffer[0x47]-'0')*10+(buffer[0x48]-'0');	/* day of the month 1-31 */
    tm_time.tm_mon=(buffer[0x44]-'0')*10+(buffer[0x45]-'0')-1;	/* month 0-11 */
    tm_time.tm_year=(buffer[0x3f]-'0')*1000+(buffer[0x40]-'0')*100+
      (buffer[0x41]-'0')*10+(buffer[0x42]-'0')-1900;        	/* year */
    tm_time.tm_isdst = -1;		/* unknown daylight saving time */
    file_recovery_new->time=mktime(&tm_time);
  }
  return 1;
}

static int header_check_ddf3(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct MasterHeader *h=(const struct MasterHeader *)buffer;
  if(le32(h->m_nNumRawBeams)!=96 && le32(h->m_nNumRawBeams)!=48)
    return 0;
  if(le32(h->m_nSamplesPerChannel)!=512)
    return 0;
  return header_check_aux(buffer, file_recovery_new);
}

static int header_check_ddf4(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct MasterHeader *h=(const struct MasterHeader *)buffer;
  if(le32(h->m_nNumRawBeams)!=96 && le32(h->m_nNumRawBeams)!=48)
    return 0;
  if(le32(h->m_nSamplesPerChannel)!=512)
    return 0;
  return header_check_aux(buffer, file_recovery_new);
}

static int header_check_ddf5(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct MasterHeader *h=(const struct MasterHeader *)buffer;
  switch(le32(h->m_nNumRawBeams))
  {
    case 48:
    case 96:
    case 64:
    case 128:
      break;
    default:
      return 0;
  }
  if(le32(h->m_nSamplesPerChannel)<512 || le32(h->m_nSamplesPerChannel)>4096)
    return 0;
  return header_check_aux(buffer, file_recovery_new);
}

static void register_header_check_ddf(file_stat_t *file_stat)
{
  static const unsigned char ddf3_header[4]=  { 'D' , 'D' , 'F' , 0x03 };
  static const unsigned char ddf4_header[4]=  { 'D' , 'D' , 'F' , 0x04 };
  static const unsigned char ddf5_header[4]=  { 'D' , 'D' , 'F' , 0x05 };
  register_header_check(0, ddf3_header, sizeof(ddf3_header), &header_check_ddf3, file_stat);
  register_header_check(0, ddf4_header, sizeof(ddf4_header), &header_check_ddf4, file_stat);
  register_header_check(0, ddf5_header, sizeof(ddf5_header), &header_check_ddf5, file_stat);
}
