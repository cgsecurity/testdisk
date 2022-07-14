/*

    File: file_sp3.c

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_sp3)
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
#include "file_sp3.h"
#include "common.h"

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_sp3(file_stat_t *file_stat);

const file_hint_t file_hint_sp3= {
  .extension="sp3",
  .description="Sisporto SP3/SPM",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_sp3
};

/*@ assigns \nothing; */
static uint64_t file_offset_end(const uint32_t offset, const uint32_t len)
{
  return(offset==0 && len==0?0:(uint64_t)offset+len-1);
}

/*@
  @ requires \valid_read(h);
  @ assigns  \nothing;
  @*/
static time_t get_time_from_sp3(const struct SP3FileInfo *h)
{
  const unsigned int DataExameAno=le16(h->DataExameAno);
  if(DataExameAno>1960 && DataExameAno<2100 &&
      h->DataExameMes>=1 && h->DataExameMes<=12 &&
      h->DataExameDia>=1 && h->DataExameDia<=31)
  {
    /*@ assert DataExameAno>1960; */
    struct tm tm_time;
//    memset(&tm_time, 0, sizeof(tm_time));
    tm_time.tm_sec=h->DataExameSegundos;
    tm_time.tm_min=h->DataExameMinutos;
    tm_time.tm_hour=h->DataExameHora;
    tm_time.tm_mday=h->DataExameDia-1;
    tm_time.tm_mon=h->DataExameMes-1;
    tm_time.tm_year=DataExameAno-1900;
    tm_time.tm_isdst = -1;	/* unknown daylight saving time */
    return mktime(&tm_time);
  }
  return (time_t)0;
}

/*@
  @ requires \valid_read(h);
  @ assigns  \nothing;
  @*/
static uint64_t get_size_from_sp3(const struct SP3FileInfo *h)
{
  uint64_t filesize=10240;
  filesize=td_max(filesize, file_offset_end(le32(h->TimeBaseDelta_POS), le32(h->TimeBaseDelta_LEN)));
  filesize=td_max(filesize, file_offset_end(le32(h->ExtraInfoFlag_POS), le32(h->ExtraInfoFlag_LEN)));
  filesize=td_max(filesize, file_offset_end(le32(h->FHRa_POS), le32(h->FHRa_LEN)));
  filesize=td_max(filesize, file_offset_end(le32(h->FHRb_POS), le32(h->FHRb_LEN)));
  filesize=td_max(filesize, file_offset_end(le32(h->UC_POS), le32(h->UC_LEN)));
  filesize=td_max(filesize, file_offset_end(le32(h->FM_POS), le32(h->FM_LEN)));
  filesize=td_max(filesize, file_offset_end(le32(h->MHR_POS), le32(h->MHR_LEN)));
  filesize=td_max(filesize, file_offset_end(le32(h->Fetal_SpO2_POS_POS), le32(h->Fetal_SpO2_POS_LEN)));
  filesize=td_max(filesize, file_offset_end(le32(h->Fetal_SpO2_POS), le32(h->Fetal_SpO2_LEN)));
  filesize=td_max(filesize, file_offset_end(le32(h->Pressure_POS_POS), le32(h->Pressure_POS_LEN)));
  filesize=td_max(filesize, file_offset_end(le32(h->Pressure_Systolic_BP_POS), le32(h->Pressure_Systolic_BP_LEN)));
  filesize=td_max(filesize, file_offset_end(le32(h->Pressure_Diastolic_BP_POS), le32(h->Pressure_Diastolic_BP_LEN)));
  filesize=td_max(filesize, file_offset_end(le32(h->Pressure_Mean_BP_POS), le32(h->Pressure_Mean_BP_LEN)));
  filesize=td_max(filesize, file_offset_end(le32(h->Pressure_NIBP_MHR_POS), le32(h->Pressure_NIBP_MHR_LEN)));
  filesize=td_max(filesize, file_offset_end(le32(h->Maternal_POS_POS), le32(h->Maternal_POS_LEN)));
  filesize=td_max(filesize, file_offset_end(le32(h->Maternal_SpO2_POS), le32(h->Maternal_SpO2_LEN)));
  filesize=td_max(filesize, file_offset_end(le32(h->Maternal_HR_POS), le32(h->Maternal_HR_LEN)));
  filesize=td_max(filesize, file_offset_end(le32(h->Event_POS_POS), le32(h->Event_POS_LEN)));
  filesize=td_max(filesize, file_offset_end(le32(h->Event_TYPE_POS), le32(h->Event_TYPE_LEN)));
  filesize=td_max(filesize, file_offset_end(le32(h->Event_DESC_POS), le32(h->Event_DESC_LEN)));
  filesize=td_max(filesize, file_offset_end(le32(h->TQRS_POS_POS), le32(h->TQRS_POS_LEN)));
  filesize=td_max(filesize, file_offset_end(le32(h->TQRS_Status_POS), le32(h->TQRS_Status_LEN)));
  filesize=td_max(filesize, file_offset_end(le32(h->TQRS_Value_POS), le32(h->TQRS_Value_LEN)));
  filesize=td_max(filesize, file_offset_end(le32(h->TQRS_Biphasic_POS), le32(h->TQRS_Biphasic_LEN)));
  filesize=td_max(filesize, file_offset_end(le32(h->Error_POS_POS), le32(h->Error_POS_LEN)));
  filesize=td_max(filesize, file_offset_end(le32(h->Error_TYPE_POS), le32(h->Error_TYPE_LEN)));
  filesize=td_max(filesize, file_offset_end(le32(h->Error_DESC_POS), le32(h->Error_DESC_LEN)));
  filesize=td_max(filesize, file_offset_end(le32(h->CommBUFFER_POS), le32(h->CommBUFFER_LEN)));
  filesize=td_max(filesize, file_offset_end(le32(h->Prove_FHRa_POS), le32(h->Prove_FHRa_LEN)));
  filesize=td_max(filesize, file_offset_end(le32(h->Prove_FHRb_POS), le32(h->Prove_FHRb_LEN)));
  filesize=td_max(filesize, file_offset_end(le32(h->Prove_UC_POS), le32(h->Prove_UC_LEN)));
  return filesize;
}

/*@
  @ requires buffer_size >= sizeof(struct SP3FileInfo);
  @ requires separation: \separated(&file_hint_sp3, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_sp3(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct SP3FileInfo *h=(const struct SP3FileInfo *)buffer;
  /*@ assert \valid_read(h); */
  const time_t file_time=get_time_from_sp3(h);
  if(file_time==0 || file_time==-1)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_sp3.extension;
  file_recovery_new->min_filesize=10240;
  file_recovery_new->time=file_time;
  file_recovery_new->calculated_file_size=get_size_from_sp3(h);
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  return 1;
}

static void register_header_check_sp3(file_stat_t *file_stat)
{
  static const unsigned char sp31_header[8]=  { 0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  static const unsigned char sp32_header[8]=  { 0x03, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  register_header_check(0, sp31_header,  sizeof(sp31_header),  &header_check_sp3, file_stat);
#ifndef DISABLED_FOR_FRAMAC
  register_header_check(0, sp32_header,  sizeof(sp32_header),  &header_check_sp3, file_stat);
#endif
}
#endif
