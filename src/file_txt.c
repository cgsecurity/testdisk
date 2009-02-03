/*

    File: file_txt.c

    Copyright (C) 2005-2008 Christophe GRENIER <grenier@cgsecurity.org>

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
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#include <ctype.h>      /* tolower */
#include <stdio.h>
#include "types.h"
#include "common.h"
#include "filegen.h"
#include "log.h"
#include "memmem.h"

extern const file_hint_t file_hint_doc;
extern const file_hint_t file_hint_jpg;
extern const file_hint_t file_hint_pdf;
extern const file_hint_t file_hint_zip;

static inline int filtre(unsigned char car);
static inline int UTF2Lat(unsigned char *buffer_lower, const unsigned char *buffer, const int buf_len);

static void register_header_check_txt(file_stat_t *file_stat);
static int header_check_txt(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);
static void register_header_check_fasttxt(file_stat_t *file_stat);
static int header_check_fasttxt(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

static int data_check_txt(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery);
static void file_check_emlx(file_recovery_t *file_recovery);
static void file_check_ers(file_recovery_t *file_recovery);
static void file_check_html(file_recovery_t *file_recovery);
static void file_check_xml(file_recovery_t *file_recovery);

const file_hint_t file_hint_fasttxt= {
  .extension="tx?",
  .description="Text files with header: rtf,xml,xhtml,imm,pm,ram,reg,sh,slk,stp",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_fasttxt
};

const file_hint_t file_hint_txt= {
  .extension="txt",
  .description="Other text files: txt,html,asp,bat,C,jsp,perl,php,py/emlx... scripts",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_txt
};

static const unsigned char header_adr[25]	= "Opera Hotlist version 2.0";
static const unsigned char header_bash[11]  	= "#!/bin/bash";
static const unsigned char header_cls[24]	= {'V','E','R','S','I','O','N',' ','1','.','0',' ','C','L','A','S','S','\r','\n','B','E','G','I','N'};
static const unsigned char header_cue[10]	= "REM GENRE ";
static const unsigned char header_dc[6]		= "SC V10";
static const unsigned char header_dif[12]	= { 'T', 'A', 'B', 'L', 'E', '\r', '\n', '0', ',', '1', '\r', '\n'};
static const unsigned char header_ers[19]	= "DatasetHeader Begin";
static const unsigned char header_ics[15]	= "BEGIN:VCALENDAR";
static const unsigned char header_imm[13]	= {'M','I','M','E','-','V','e','r','s','i','o','n',':'};
static const unsigned char header_lyx[7]	= {'#', 'L', 'y', 'X', ' ', '1', '.'};
static const unsigned char header_m3u[7]	= {'#','E','X','T','M','3','U'};
static const unsigned char header_mail[5]	= {'F','r','o','m',' '};
static const unsigned char header_msf[19]	= "// <!-- <mdb:mork:z";
static const unsigned char header_perlm[7] 	= "package";
static const unsigned char header_ram[7]	= "rtsp://";
static const unsigned char header_ReceivedFrom[14]= {'R','e','c','e','i','v','e','d',':',' ','f','r','o','m'};
static const unsigned char header_reg[8]  	= "REGEDIT4";
static const unsigned char header_ReturnPath[13]= {'R','e','t','u','r','n','-','P','a','t','h',':',' '};
static const unsigned char header_rpp[16]	= { '<', 'R', 'E', 'A', 'P', 'E', 'R', '_', 'P', 'R', 'O', 'J', 'E', 'C', 'T', ' '};
static const unsigned char header_rtf[5]	= { '{','\\','r','t','f'};
static const unsigned char header_sh[9]  	= "#!/bin/sh";
static const unsigned char header_slk[10]  	= "ID;PSCALC3";
static const unsigned char header_stl[6]	= "solid ";
static const unsigned char header_stp[13]  	= "ISO-10303-21;";
static const unsigned char header_wpl[21]	= { '<', '?', 'w', 'p', 'l', ' ', 'v', 'e', 'r', 's', 'i', 'o', 'n', '=', '"', '1', '.', '0', '"', '?', '>' };
static const unsigned char header_xml[14]	= "<?xml version=";

static void register_header_check_txt(file_stat_t *file_stat)
{
  register_header_check(0, NULL,0, &header_check_txt, file_stat);
}

static void register_header_check_fasttxt(file_stat_t *file_stat)
{
  register_header_check(0, header_adr, sizeof(header_adr), &header_check_fasttxt, file_stat);
  register_header_check(0, header_bash,sizeof(header_bash), &header_check_fasttxt, file_stat);
  register_header_check(0, header_cls,sizeof(header_cls), &header_check_fasttxt, file_stat);
  register_header_check(0, header_cue,sizeof(header_cue), &header_check_fasttxt, file_stat);
  register_header_check(4, header_dc, sizeof(header_dc), &header_check_fasttxt, file_stat);
  register_header_check(0, header_dif, sizeof(header_dif), &header_check_fasttxt, file_stat);
  register_header_check(0, header_ers,sizeof(header_ers), &header_check_fasttxt, file_stat);
  register_header_check(0, header_ics, sizeof(header_ics), &header_check_fasttxt, file_stat);
  register_header_check(0, header_imm,sizeof(header_imm), &header_check_fasttxt, file_stat);
  register_header_check(0, header_lyx,sizeof(header_lyx), &header_check_fasttxt, file_stat);
  register_header_check(0, header_m3u, sizeof(header_m3u), &header_check_fasttxt, file_stat);
  register_header_check(0, header_mail,sizeof(header_mail), &header_check_fasttxt, file_stat);
  register_header_check(0, header_msf, sizeof(header_msf), &header_check_fasttxt, file_stat);
  register_header_check(0, header_perlm,sizeof(header_perlm), &header_check_fasttxt, file_stat);
  register_header_check(0, header_ram,sizeof(header_ram), &header_check_fasttxt, file_stat);
  register_header_check(0, header_reg,sizeof(header_reg), &header_check_fasttxt, file_stat);
  register_header_check(0, header_ReturnPath,sizeof(header_ReturnPath), &header_check_fasttxt, file_stat);
  register_header_check(0, header_rpp,sizeof(header_rpp), &header_check_fasttxt, file_stat);
  register_header_check(0, header_rtf,sizeof(header_rtf), &header_check_fasttxt, file_stat);
  register_header_check(0, header_sh,sizeof(header_sh), &header_check_fasttxt, file_stat);
  register_header_check(0, header_slk,sizeof(header_slk), &header_check_fasttxt, file_stat);
  register_header_check(0, header_stl,sizeof(header_stl), &header_check_fasttxt, file_stat);
  register_header_check(0, header_stp,sizeof(header_stp), &header_check_fasttxt, file_stat);
  register_header_check(0, header_wpl,sizeof(header_wpl), &header_check_fasttxt, file_stat);
  register_header_check(0, header_xml,sizeof(header_xml), &header_check_fasttxt, file_stat);
}

// #define DEBUG_FILETXT

/* return 1 if char can be found in text file */
static int filtre(unsigned char car)
{
  switch(car)
  {
    case 0x7c:  /* similar to | */
    case 0x80:
    case 0x92:
    case 0x99:
    case 0x9c:	/* 'œ' */
    case 0xa0:  /* nonbreaking space */
    case 0xa1:  /* '¡' */
    case 0xa2:
    case 0xa3:	/* '£' */
    case 0xa7:	/* '§' */
    case 0xa8:
    case 0xa9:	/* '©' */
    case 0xab:	/* '«' */
    case 0xb0:	/* '°' */
    case 0xb4:  /* '´' */
    case 0xb7:
    case 0xbb:  /* '»' */
    case 0xc0:  /* 'À' */
    case 0xc7:  /* 'Ç' */
    case 0xc9:  /* 'É' */
    case 0xd6:  /* 'Ö' */
    case 0xd7:
    case 0xd9:  /* 'Ù' */
    case 0xdf:
    case 0xe0: 	/* 'à' */
    case 0xe1: 	/* 'á' */
    case 0xe2: 	/* 'â' */
    case 0xe3:  /* 'ã' */
    case 0xe4: 	/* 'ä' */
    case 0xe6:  /* 'æ' */
    case 0xe7: 	/* 'ç' */
    case 0xe8: 	/* 'è' */
    case 0xe9: 	/* 'é' */
    case 0xea: 	/* 'ê' */
    case 0xeb: 	/* 'ë' */
    case 0xed:  /* 'í' */
    case 0xee: 	/* 'î' */
    case 0xef: 	/* 'ï' */
    case 0xf4: 	/* 'ô' */
    case 0xf6: 	/* 'ö' */
    case 0xf8:  /* 'ø' */
    case 0xf9: 	/* 'ù' */
    case 0xfa:  /* 'ú' */
    case 0xfb: 	/* 'û' */
    case 0xfc: 	/* 'ü' */
      return 1;
  }
  if((car=='\b')||(car=='\t')||(car=='\r')||(car=='\n')
    ||((car>=' ')&&(car<='~'))
    ||((car>=0x82)&&(car<=0x8d))
    ||((car>=0x93)&&(car<=0x98))
    )
    return 1;
  return 0;
}

/* destination should have an extra byte available for null terminator
   return read size */
static int UTF2Lat(unsigned char *buffer_lower, const unsigned char *buffer, const int buf_len)
{
  const unsigned char *p; 	/* pointers to actual position in source buffer */
  unsigned char *q;	/* pointers to actual position in destination buffer */
  int i; /* counter of remaining bytes available in destination buffer */
  for (i = buf_len, p = buffer, q = buffer_lower; p-buffer<buf_len && i > 0 && *p!='\0';) 
  {
    const unsigned char *p_org=p;
    if((*p & 0xf0)==0xe0 && (*(p+1) & 0xc0)==0x80 && (*(p+2) & 0xc0)==0x80)
    { /* UTF8 l=3 */
#ifdef DEBUG_TXT
      log_info("UTF8 l=3 0x%02x 0x%02x 0x02x\n", *p, *(p+1),*(p+2));
#endif
      *q = '\0';
      switch (*p)
      {
        case 0xE2 : 
          switch (*(p+1))
          { 
            case 0x80 : 
              switch (*(p+2))
              { 
                case 0x93 : (*q) = 150; break;
                case 0x94 : (*q) = 151; break;
                case 0x98 : (*q) = 145; break;
                /* case 0x99 : (*q) = 146; break; */
                case 0x99 : (*q) = '\''; break;
                case 0x9A : (*q) = 130; break;
                case 0x9C : (*q) = 147; break;
                case 0x9D : (*q) = 148; break;
                case 0x9E : (*q) = 132; break;
                case 0xA0 : (*q) = 134; break;
                case 0xA1 : (*q) = 135; break;
                case 0xA2 : (*q) = 149; break;
                case 0xA6 : (*q) = 133; break;
                case 0xB0 : (*q) = 137; break;
                case 0xB9 : (*q) = 139; break;
                case 0xBA : (*q) = 155; break;
              }
              break;
            case 0x82 : 
              switch (*(p+2))
              { 
                case 0xAC : (*q) = 128; break;
              }
              break;
            case 0x84 : 
              switch (*(p+2))
              { 
                case 0xA2 : (*q) = 153; break;
              }
              break;
          }
          break;
      }
      p+=3;
    }
    else if((*p & 0xe0)==0xc0 && (*(p+1) & 0xc0)==0x80)
    { /* UTF8 l=2 */
      *q = '\0';
      switch (*p)
      {
        case 0xC2 : 
          (*q) = ((*(p+1)) | 0x80) & 0xBF; /* A0-BF and a few 80-9F */
          if((*q)==0xA0)
            (*q)=' ';
          break;
        case 0xC3 : 
          switch (*(p+1))
	  { 
	    case 0xB3 : (*q) = 162; break;
	    default:
			(*q) = (*(p+1)) | 0xC0; /* C0-FF */
			break;
	  }
          break;
        case 0xC5 : 
          switch (*(p+1)) { 
            case 0x92 : (*q) = 140; break;
            case 0x93 : (*q) = 156; break;
            case 0xA0 : (*q) = 138; break;
            case 0xA1 : (*q) = 154; break;
            case 0xB8 : (*q) = 143; break;
            case 0xBD : (*q) = 142; break;
            case 0xBE : (*q) = 158; break;
          }
          break;
        case 0xC6: 
          switch (*(p+1)) { 
            case 0x92 : (*q) = 131; break;
          }
          break;
        case 0xCB : 
          switch (*(p+1)) { 
            case 0x86 : (*q) = 136; break;
            case 0x9C : (*q) = 152; break;
          }
          break;
      }
      p+=2;
    }
    else
    { /* Ascii UCS */
#ifdef DEBUG_TXT
      log_info("UTF8 Ascii UCS 0x%02x\n", *p);
#endif
      *q = tolower(*p++);
    }
    if (*q=='\0' || filtre(*q)==0)
    {
#ifdef DEBUG_TXT
      log_warning("UTF2Lat reject 0x%x\n",*q);
#endif
      *q = '\0';
      return(p_org-buffer);
    }
    q++;
    i--;
  }
  *q = '\0';
  return(p-buffer);
}

static int header_check_fasttxt(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const char sign_grisbi[14]		= "Version_grisbi";
  const char sign_fst[5]                = "QBFSD";
  const char sign_html[5]		= "<html";
  static const unsigned char spaces[16]={
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ' };
  if(memcmp(buffer,header_cls,sizeof(header_cls))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->data_check=&data_check_txt;
    file_recovery_new->file_check=&file_check_size;
    file_recovery_new->extension="cls";
    return 1;
  }
  /* Incredimail has .imm extension but this extension isn't frequent */
  if(memcmp(buffer,header_imm,sizeof(header_imm))==0 ||
      memcmp(buffer,header_ReturnPath,sizeof(header_ReturnPath))==0 ||
      memcmp(buffer,header_mail,sizeof(header_mail))==0)
  {
    if(file_recovery!=NULL && file_recovery->file_stat!=NULL &&
        file_recovery->file_stat->file_hint==&file_hint_fasttxt &&
        strcmp(file_recovery->extension,"imm")==0)
      return 0;
    reset_file_recovery(file_recovery_new);
    file_recovery_new->data_check=NULL;
    file_recovery_new->extension="imm";
    return 1;
  }
  if(memcmp(buffer,header_perlm,sizeof(header_perlm))==0 &&
      (buffer[sizeof(header_perlm)]==' ' || buffer[sizeof(header_perlm)]=='\t'))
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->data_check=&data_check_txt;
    file_recovery_new->file_check=&file_check_size;
    file_recovery_new->extension="pm";
    return 1;
  }
  if(memcmp(buffer,header_rpp,sizeof(header_rpp))==0)
  {
    /* Reaper Project */
    reset_file_recovery(file_recovery_new);
    file_recovery_new->data_check=&data_check_txt;
    file_recovery_new->file_check=&file_check_size;
    file_recovery_new->extension="rpp";
    return 1;
  }
  if(memcmp(buffer,header_rtf,sizeof(header_rtf))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->data_check=&data_check_txt;
    file_recovery_new->file_check=&file_check_size;
    file_recovery_new->extension="rtf";
    return 1;
  }
  if(memcmp(buffer,header_reg,sizeof(header_reg))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->data_check=&data_check_txt;
    file_recovery_new->file_check=&file_check_size;
    file_recovery_new->extension="reg";
    return 1;
  }
  if(memcmp(buffer,header_sh,sizeof(header_sh))==0 ||
      memcmp(buffer,header_bash,sizeof(header_bash))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->data_check=&data_check_txt;
    file_recovery_new->file_check=&file_check_size;
    file_recovery_new->extension="sh";
    return 1;
  }
  if(memcmp(buffer,header_slk,sizeof(header_slk))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->data_check=&data_check_txt;
    file_recovery_new->file_check=&file_check_size;
    file_recovery_new->extension="slk";
    return 1;
  }
  if(memcmp(buffer, header_stl, sizeof(header_stl))==0 &&
      memcmp(buffer+0x40, spaces, sizeof(spaces))!=0)
  {
    /* StereoLithography - STL Ascii format
     * http://www.ennex.com/~fabbers/StL.asp	*/
    reset_file_recovery(file_recovery_new);
    file_recovery_new->data_check=&data_check_txt;
    file_recovery_new->file_check=&file_check_size;
    file_recovery_new->extension="stl";
    return 1;
  }
  if(memcmp(buffer, header_ers, sizeof(header_ers))==0)
  {
    /* ER Mapper Rasters (ERS) */
    reset_file_recovery(file_recovery_new);
    file_recovery_new->data_check=&data_check_txt;
    file_recovery_new->file_check=&file_check_ers;
    file_recovery_new->extension="ers";
    return 1;
  }
  if(memcmp(buffer,header_stp,sizeof(header_stp))==0)
  {
    /* ISO 10303 is an ISO standard for the computer-interpretable
     * representation and exchange of industrial product data.
     * - Industrial automation systems and integration - Product data representation and exchange
     * - Standard for the Exchange of Product model data.
     * */
    reset_file_recovery(file_recovery_new);
    file_recovery_new->data_check=&data_check_txt;
    file_recovery_new->file_check=&file_check_size;
    file_recovery_new->extension="stp";
    return 1;
  }
  if(memcmp(buffer,header_wpl,sizeof(header_wpl))==0)
  {
    /* Windows Play List*/
    reset_file_recovery(file_recovery_new);
    file_recovery_new->data_check=&data_check_txt;
    file_recovery_new->file_check=&file_check_size;
    file_recovery_new->extension="wpl";
    return 1;
  }
  if(memcmp(buffer,header_ram,sizeof(header_ram))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->data_check=&data_check_txt;
    file_recovery_new->file_check=&file_check_size;
    file_recovery_new->extension="ram";
    return 1;
  }
  if(memcmp(buffer,header_xml,sizeof(header_xml))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->data_check=&data_check_txt;
    if(td_memmem(buffer, buffer_size, sign_grisbi, sizeof(sign_grisbi))!=NULL)
    {
      /* Grisbi - Personal Finance Manager XML data */
      file_recovery_new->extension="gsb";
    }
    else if(td_memmem(buffer, buffer_size, sign_fst, sizeof(sign_fst))!=NULL)
      file_recovery_new->extension="fst";
    else if(td_memmem(buffer, buffer_size, sign_html, sizeof(sign_html))!=NULL)
    {
      file_recovery_new->extension="html";
      file_recovery_new->file_check=&file_check_html;
    }
    else
      file_recovery_new->extension="xml";
    file_recovery_new->file_check=&file_check_xml;
    return 1;
  }
  if(buffer[0]=='0' && buffer[1]=='0' && memcmp(&buffer[4],header_dc,sizeof(header_dc))==0)
  { /*
       TSCe Survey Controller DC v10.0
     */
    reset_file_recovery(file_recovery_new);
    file_recovery_new->data_check=&data_check_txt;
    file_recovery_new->file_check=&file_check_size;
    file_recovery_new->extension="dc";
    return 1;
  }
  if(memcmp(buffer,header_dif,sizeof(header_dif))==0)
  { /*
       Lotus Data Interchange Format
     */
    reset_file_recovery(file_recovery_new);
    file_recovery_new->data_check=&data_check_txt;
    file_recovery_new->file_check=&file_check_size;
    file_recovery_new->extension="dif";
    return 1;
  }
  if(memcmp(buffer, header_ics, sizeof(header_ics))==0)
  {
    const char *date_asc;
    char *buffer2;
    reset_file_recovery(file_recovery_new);
    file_recovery_new->data_check=&data_check_txt;
    file_recovery_new->file_check=&file_check_size;
    file_recovery_new->extension="ics";
    /* DTSTART:19970714T133000            ;Local time
     * DTSTART:19970714T173000Z           ;UTC time
     * DTSTART;TZID=US-Eastern:19970714T133000    ;Local time and time
     */
    buffer2=(char *)MALLOC(buffer_size+1);
    buffer2[buffer_size]='\0';
    memcpy(buffer2, buffer, buffer_size);
    date_asc=strstr(buffer2, "DTSTART");
    if(date_asc!=NULL)
      date_asc=strchr(date_asc, ':');
    if(date_asc!=NULL && date_asc-buffer2<=buffer_size-14)
    {
      struct tm tm_time;
      memset(&tm_time, 0, sizeof(tm_time));
      date_asc++;
      tm_time.tm_sec=(date_asc[13]-'0')*10+(date_asc[14]-'0');      /* seconds 0-59 */
      tm_time.tm_min=(date_asc[11]-'0')*10+(date_asc[12]-'0');      /* minutes 0-59 */
      tm_time.tm_hour=(date_asc[9]-'0')*10+(date_asc[10]-'0');      /* hours   0-23*/
      tm_time.tm_mday=(date_asc[6]-'0')*10+(date_asc[7]-'0');	/* day of the month 1-31 */
      tm_time.tm_mon=(date_asc[4]-'0')*10+(date_asc[5]-'0')-1;	/* month 0-11 */
      tm_time.tm_year=(date_asc[0]-'0')*1000+(date_asc[1]-'0')*100+
	(date_asc[2]-'0')*10+(date_asc[3]-'0')-1900;        	/* year */
      tm_time.tm_isdst = -1;		/* unknown daylight saving time */
      file_recovery_new->time=mktime(&tm_time);
    }
    free(buffer2);
    return 1;
  }
  /* Lyx http://www.lyx.org */
  if(memcmp(buffer, header_lyx, sizeof(header_lyx))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->data_check=&data_check_txt;
    file_recovery_new->file_check=&file_check_size;
    file_recovery_new->extension="lyx";
    return 1;
  }
  /* Moving Picture Experts Group Audio Layer 3 Uniform Resource Locator */
  if(memcmp(buffer, header_m3u, sizeof(header_m3u))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->data_check=&data_check_txt;
    file_recovery_new->file_check=&file_check_size;
    file_recovery_new->extension="m3u";
    return 1;
  }
  /* Mozilla, firefox, thunderbird msf (Mail Summary File) */
  if(memcmp(buffer, header_msf, sizeof(header_msf))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->data_check=&data_check_txt;
    file_recovery_new->file_check=&file_check_size;
    file_recovery_new->extension="msf";
    return 1;
  }
  /* Opera Hotlist bookmark/contact list/notes */
  if(memcmp(buffer, header_adr, sizeof(header_adr))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->data_check=&data_check_txt;
    file_recovery_new->file_check=&file_check_size;
    file_recovery_new->extension="adr";
    return 1;
  }
  /* Cue sheet often begins by the music genre
   * http://wiki.hydrogenaudio.org/index.php?title=Cue_sheet */
  if(memcmp(buffer, header_cue, sizeof(header_cue))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->data_check=&data_check_txt;
    file_recovery_new->file_check=&file_check_size;
    file_recovery_new->extension="cue";
    return 1;
  }
  return 0;
}

static int header_check_txt(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  static char *buffer_lower=NULL;
  static unsigned int buffer_lower_size=0;
  unsigned int l=0;
  const unsigned char header_asp[22]	= "<%@ language=\"vbscript";
  const unsigned char header_bat[9]  	= "@echo off";
  const unsigned char header_vcf[11]	= "begin:vcard";
  const unsigned char header_sig_perl[4] = "perl";
  const unsigned char header_sig_python[6] = "python";
  const unsigned char header_sig_ruby[4] = "ruby";
  const char sign_asp[]			= "<% ";
  const char sign_c[]			= "#include";
  const char sign_h[]			= "/*";
  const char sign_jsp[]			= "<%@";
  const char sign_jsp2[]		= "<%=";
  const char sign_php[]			= "<?php";
  const char sign_tex[]			= "\\begin{";
  const char sign_html[]		= "<html";
  const char sign_cue[6]		= { 'F', 'I', 'L', 'E', ' ', '"'};
  const unsigned int buffer_size_test=(buffer_size < 2048 ? buffer_size : 2048);
  {
    unsigned int i;
    unsigned int tmp=0;
    for(i=0;i<10 && isdigit(buffer[i]);i++)
      tmp=tmp*10+buffer[i]-'0';
    if(buffer[i]==0x0a &&
      (memcmp(buffer+i+1, header_ReturnPath, sizeof(header_ReturnPath))==0 ||
       memcmp(buffer+i+1, header_ReceivedFrom, sizeof(header_ReceivedFrom))==0) &&
        !(file_recovery!=NULL && file_recovery->file_stat!=NULL &&
          file_recovery->file_stat->file_hint==&file_hint_fasttxt &&
          strcmp(file_recovery->extension,"imm")==0))
    {
      reset_file_recovery(file_recovery_new);
      file_recovery_new->calculated_file_size=tmp+i+1;
      file_recovery_new->data_check=NULL;
      file_recovery_new->file_check=&file_check_emlx;
      file_recovery_new->extension="emlx";
      return 1;
    }
  }
  /* Cue sheet can begin by the filename 
   * http://wiki.hydrogenaudio.org/index.php?title=Cue_sheet */
  if(memcmp(buffer, sign_cue, sizeof(sign_cue))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->data_check=&data_check_txt;
    file_recovery_new->file_check=&file_check_size;
    file_recovery_new->extension="cue";
    return 1;
  }
  if(buffer_lower_size<buffer_size_test+16)
  {
    free(buffer_lower);
    buffer_lower=NULL;
  }
  /* Don't malloc/free memory every time, small memory leak */
  if(buffer_lower==NULL)
  {
    buffer_lower_size=buffer_size_test+16;
    buffer_lower=(char *)MALLOC(buffer_lower_size);
  }
  l=UTF2Lat((unsigned char*)buffer_lower, buffer, buffer_size_test);
  /* strncasecmp */
  if(memcmp(buffer_lower,header_bat,sizeof(header_bat))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->data_check=&data_check_txt;
    file_recovery_new->file_check=&file_check_size;
    file_recovery_new->extension="bat";
    return 1;
  }
  if(memcmp(buffer_lower,header_asp,sizeof(header_asp))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->data_check=&data_check_txt;
    file_recovery_new->file_check=&file_check_size;
    file_recovery_new->extension="asp";
    return 1;
  }
  if(memcmp(buffer_lower,header_vcf,sizeof(header_vcf))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->data_check=&data_check_txt;
    file_recovery_new->file_check=&file_check_size;
    file_recovery_new->extension="vcf";
    return 1;
  }
  if(buffer[0]=='#' && buffer[1]=='!')
  {
    unsigned int ll=l-2;
    const unsigned char *haystack=(const unsigned char *)buffer_lower+2;
    const unsigned char *res;
    res=(const unsigned char *)memchr(haystack,'\n',ll);
    if(res!=NULL)
      ll=res-haystack;
    if(td_memmem(haystack, ll, header_sig_perl, sizeof(header_sig_perl)) != NULL)
    {
      reset_file_recovery(file_recovery_new);
      file_recovery_new->data_check=&data_check_txt;
      file_recovery_new->file_check=&file_check_size;
      file_recovery_new->extension="pl";
      return 1;
    }
    if(td_memmem(haystack, ll, header_sig_python, sizeof(header_sig_python)) != NULL)
    {
      reset_file_recovery(file_recovery_new);
      file_recovery_new->data_check=&data_check_txt;
      file_recovery_new->file_check=&file_check_size;
      file_recovery_new->extension="py";
      return 1;
    }
    if(td_memmem(haystack, ll, header_sig_ruby, sizeof(header_sig_ruby)) != NULL)
    {
      reset_file_recovery(file_recovery_new);
      file_recovery_new->data_check=&data_check_txt;
      file_recovery_new->file_check=&file_check_size;
      file_recovery_new->extension="rb";
      return 1;
    }
  }
  if(safe_header_only!=0)
  {
    return 0;
  }
  /* Don't search text in the beginning of JPG or inside pdf */
  if(file_recovery!=NULL && file_recovery->file_stat!=NULL &&
      ((file_recovery->file_stat->file_hint==&file_hint_jpg && file_recovery->file_size < file_recovery->min_filesize) ||
       file_recovery->file_stat->file_hint==&file_hint_pdf))
  {
    return 0;
  }
  {
    const char *ext=NULL;
    /* ind=~0: random
     * ind=~1: constant	*/
    double ind=1;
    unsigned int nbrf=0;
    unsigned int is_csv=1;
    /* Detect Fortran */
    {
      char *str=buffer_lower;
      while((str=strstr(str, "\n      "))!=NULL)
      {
	nbrf++;
	str++;
      }
    }
    /* Detect csv */
    {
      unsigned int csv_per_line_current=0;
      unsigned int csv_per_line=0;
      unsigned int line_nbr=0;
      unsigned int i;
      for(i=0;i<l && is_csv>0;i++)
      {
	if(buffer_lower[i]==';')
	{
	  csv_per_line_current++;
	}
	else if(buffer_lower[i]=='\n')
	{
	  if(line_nbr==0)
	    csv_per_line=csv_per_line_current;
	  if(csv_per_line_current!=csv_per_line)
	    is_csv=0;
	  line_nbr++;
	  csv_per_line_current=0;
	}
      }
      if(csv_per_line<1 || line_nbr<10)
	is_csv=0;
    }
    if(l>1)
    {
      unsigned int stats[256];
      unsigned int i;
      memset(&stats, 0, sizeof(stats));
      for(i=0;i<l;i++)
        stats[(unsigned char)buffer_lower[i]]++;
      ind=0;
      for(i=0;i<256;i++)
        if(stats[i]>0)
          ind+=stats[i]*(stats[i]-1);
      ind=ind/l/(l-1);
    }
    if(nbrf>10 && ind<0.9)
      ext="f";
    else if(is_csv>0)
      ext="csv";
    /* Detect LaTeX, C, PHP, JSP, ASP, HTML, C header */
    else if(strstr(buffer_lower, sign_tex)!=NULL)
      ext="tex";
    else if(strstr(buffer_lower, sign_c)!=NULL)
      ext="c";
    else if(strstr(buffer_lower, sign_php)!=NULL)
      ext="php";
    else if(strstr(buffer_lower, sign_jsp)!=NULL)
      ext="jsp";
    else if(strstr(buffer_lower, sign_jsp2)!=NULL)
      ext="jsp";
    else if(strstr(buffer_lower, sign_asp)!=NULL)
      ext="asp";
    else if(strstr(buffer_lower, sign_html)!=NULL)
      ext="html";
    else if(strstr(buffer_lower, sign_h)!=NULL && l>50)
      ext="h";
    else if(l<100 || ind<0.03 || ind>0.90)
      ext=NULL;
    else
      ext=file_hint_txt.extension;
    if(ext!=NULL && strcmp(ext,"txt")==0 &&
        (strstr(buffer_lower,"<br>")!=NULL || strstr(buffer_lower,"<p>")!=NULL))
    {
      ext="html";
    }
    if(ext!=NULL && file_recovery!=NULL && file_recovery->file_stat!=NULL)
    {
      const unsigned char zip_header[4]  = { 'P', 'K', 0x03, 0x04};
      if(strcmp(ext,"html")==0 &&
          file_recovery->file_stat->file_hint==&file_hint_txt &&
          strstr(file_recovery->filename,"")!=NULL)
      {
        return 0;
      }

      /* Special case: doc, texte files
Unix: \n (0xA)
Dos: \r\n (0xD 0xA)
Doc: \r (0xD)
       */
      if(file_recovery->file_stat->file_hint==&file_hint_doc &&
          strstr(file_recovery->filename,".doc")!=NULL)
      {
        unsigned int i;
        unsigned int txt_nl=0;
        for(i=0;i<l-1;i++)
          if(buffer_lower[i]=='\r' && buffer_lower[i+1]!='\n')
          {
            return 0;
          }
        for(i=0;i<l && i<512;i++)
          if(buffer_lower[i]=='\n')
            txt_nl=1;
        if(txt_nl==1)
        {
          /* log_trace(">%s<\ndoc => %s\n",buffer_lower,ext); */
          reset_file_recovery(file_recovery_new);
          file_recovery_new->data_check=&data_check_txt;
          file_recovery_new->file_check=&file_check_size;
          file_recovery_new->extension=ext;
          return 1;
        }
      }
      buffer_lower[511]='\0';
      /* Special case: two consecutive HTML files */
      if((strcmp(ext,"html")==0 &&
            strstr(buffer_lower,sign_html)!=NULL &&
            strstr(file_recovery->filename,".html")!=NULL) ||
          /* Text should not be found in JPEG */
          (file_recovery->file_stat->file_hint==&file_hint_jpg &&
           td_memmem(buffer, buffer_size_test, "8BIM", 4)==NULL &&
           td_memmem(buffer, buffer_size_test, "adobe", 5)==NULL) ||
          /* Text should not be found in zip because of compression */
          (file_recovery->file_stat->file_hint==&file_hint_zip &&
	  td_memmem(buffer, buffer_size_test, zip_header, 4)==NULL))
      {
        reset_file_recovery(file_recovery_new);
        file_recovery_new->data_check=&data_check_txt;
        file_recovery_new->file_check=&file_check_size;
        file_recovery_new->extension=ext;
        return 1;
      }
      return 0;
    }
    /*    log_trace("ext=%s\n",ext); */
    if(ext!=NULL)
    {
      reset_file_recovery(file_recovery_new);
      file_recovery_new->extension=ext;
      file_recovery_new->data_check=&data_check_txt;
      file_recovery_new->file_check=&file_check_size;
      return 1;
    }
  }
  return 0;
}

static int data_check_txt(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  unsigned int i;
  char *buffer_lower=(char *)MALLOC(buffer_size+16);
  i=UTF2Lat((unsigned char*)buffer_lower, &buffer[buffer_size/2], buffer_size/2);
  if(i<buffer_size/2)
  {
    const char sign_html_end[]	= "</html>";
    const char *pos;
    pos=strstr(buffer_lower,sign_html_end);
    if(strstr(file_recovery->filename,".html")!=NULL && pos!=NULL && i<((pos-buffer_lower)+sizeof(sign_html_end))-1+10)
    {
      file_recovery->calculated_file_size+=(pos-buffer_lower)+sizeof(sign_html_end)-1;
    }
    else if(i>=10)
      file_recovery->calculated_file_size=file_recovery->file_size+i;
    free(buffer_lower);
    return 2;
  }
  free(buffer_lower);
  file_recovery->calculated_file_size=file_recovery->file_size+(buffer_size/2);
  return 1;
}

static void file_check_html(file_recovery_t *file_recovery)
{
  const unsigned char html_footer[7]= {'<', '/', 'h', 't', 'm', 'l', '>'};
  file_search_lc_footer(file_recovery, html_footer,sizeof(html_footer));
  if(file_recovery->file_size==0)
    log_warning("%s: no footer\n",file_recovery->filename);
  else
  {
    const int read_size=1024;
    int taille;
    char *buffer_lower;
    int i;
    if(fseek(file_recovery->handle,0,SEEK_SET)<0)
      return;
    buffer_lower=(char *)MALLOC(read_size);
    taille=fread(buffer_lower,1,read_size,file_recovery->handle);
    if(taille<0)
    {
      free(buffer_lower);
      return;
    }
    buffer_lower[taille<read_size?taille:read_size-1]='\0';
    /* TODO: use strcasestr if available */
    for(i=0;i<taille;i++)
      buffer_lower[i]=tolower(buffer_lower[i]);
    if(strstr(buffer_lower, "<html")==NULL)
    {
      log_warning("%s: no header\n",file_recovery->filename);
      file_recovery->file_size=0;
    }
    free(buffer_lower);
  }
}

static void file_check_emlx(file_recovery_t *file_recovery)
{
  const unsigned char emlx_footer[9]= {'<', '/', 'p', 'l', 'i', 's', 't', '>', 0x0a};
  if(file_recovery->file_size < file_recovery->calculated_file_size)
    file_recovery->file_size=0;
  else
  {
    if(file_recovery->file_size > file_recovery->calculated_file_size+2048)
      file_recovery->file_size=file_recovery->calculated_file_size+2048;
    file_search_footer(file_recovery, emlx_footer,sizeof(emlx_footer));
  }
}

static void file_check_xml(file_recovery_t *file_recovery)
{
  const unsigned char xml_footer[1]= { '>'};
  file_search_footer(file_recovery, xml_footer, sizeof(xml_footer));
  file_allow_nl(file_recovery, NL_BARENL|NL_CRLF|NL_BARECR);
}

static void file_check_ers(file_recovery_t *file_recovery)
{
  const unsigned char ers_footer[17]= "DatasetHeader End";
  file_search_footer(file_recovery, ers_footer, sizeof(ers_footer));
  file_allow_nl(file_recovery, NL_BARENL|NL_CRLF|NL_BARECR);
}
