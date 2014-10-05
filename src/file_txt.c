/*

    File: file_txt.c

    Copyright (C) 2005-2012 Christophe GRENIER <grenier@cgsecurity.org>

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
#include "file_txt.h"

extern const file_hint_t file_hint_doc;
extern const file_hint_t file_hint_jpg;
extern const file_hint_t file_hint_pdf;
extern const file_hint_t file_hint_tiff;
extern const file_hint_t file_hint_zip;

static inline int filtre(unsigned int car);

static void register_header_check_txt(file_stat_t *file_stat);
static int header_check_txt(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);
static void register_header_check_fasttxt(file_stat_t *file_stat);
static int header_check_fasttxt(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);
#ifdef UTF16
static int header_check_le16_txt(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);
#endif

const file_hint_t file_hint_fasttxt= {
  .extension="tx?",
  .description="Text files with header: rtf,xml,xhtml,mbox/imm,pm,ram,reg,sh,slk,stp,jad,url",
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

static unsigned char ascii_char[256];

static void register_header_check_txt(file_stat_t *file_stat)
{
  unsigned int i;
  for(i=0; i<256; i++)
    ascii_char[i]=i;
  for(i=0; i<256; i++)
  {
    if(filtre(i) || i==0xE2 || i==0xC2 || i==0xC3 || i==0xC5 || i==0xC6 || i==0xCB)
      register_header_check(0, &ascii_char[i], 1, &header_check_txt, file_stat);
  }
#ifdef UTF16
  register_header_check(1, &ascii_char[0], 1, &header_check_le16_txt, file_stat);
#endif
}

typedef struct
{
  const char *string;
  const unsigned int len;
  const char *extension;
} txt_header_t;

static const txt_header_t fasttxt_headers[] = {
  /* Unix shell */
  { "#!/bin/bash", 					11, "sh"},
  { "#!/bin/ksh",					10, "sh"},
  { "#!/bin/sh",					 9, "sh"},
  /* Opera Hotlist bookmark/contact list/notes */
  { "Opera Hotlist version 2.0",			25, "adr"},
  /* Microsoft VB Class module */
  { "VERSION 1.0 CLASS\r\nBEGIN",			24, "cls"},
  /* Cue sheet often begins by the music genre
   * or by the filename
   * http://wiki.hydrogenaudio.org/index.php?title=Cue_sheet */
  { "REM GENRE ",					10, "cue"},
  { "FILE \"",						 6, "cue"},
  /* Lotus Data Interchange Format */
  { "TABLE\r\n0,1\r\n",					12, "dif"},
  /* Designer, a Photobook Designer Software */
  { "vSg4q7j8GLrtf",					13, "dp"},
  /* EMKA IOX file */
  { "1\t\t\t\t\tthis file\t", 				16,
#ifdef DJGPP
    "emk"
#else
    "emka"
#endif
  },
  /* ENVI */
  { "ENVI\r\ndescription",				17, "hdr"},
  /* Java Application Descriptor
   * http://en.wikipedia.org/wiki/JAD_%28file_format%29 */
  { "MIDlet-1:",					 9, "jad"},
  { "{\"title\":\"\",\"id\":1,\"dateAdded\":",		31, "json"},
  /* Lyx http://www.lyx.org */
  { "#LyX 1.", 						 7, "lyx"},
  /* LilyPond http://lilypond.org*/
  { "\n\\version \"", 					11, "ly"},
  /* Moving Picture Experts Group Audio Layer 3 Uniform Resource Locator */
  { "#EXTM3U",						 7, "m3u"},
  /* http://www.mnemosyne-proj.org/
   * flash-card program to help you memorise question/answer pairs */
  { "--- Mnemosyne Data Base --- Format Version 2 ---", 48, "mem"},
  /* Mozilla, firefox, thunderbird msf (Mail Summary File) */
  { "// <!-- <mdb:mork:z", 				19, "msf"},
  /* MySQL, phpMyAdmin, PostgreSQL dump */
  { "-- MySQL dump ",					14, "sql"},
  { "-- phpMyAdmin SQL Dump",				22, "sql"},
  { "--\n-- PostgreSQL database cluster dump",		38, "sql"},
  { "--\r\n-- PostgreSQL database cluster dump",	39, "sql"},
  /* PTGui,  panoramic stitching software */
  { "# ptGui project file",				20, "pts"},
  /* Quantum GIS  */
  { "<!DOCTYPE qgis ",					15, "qgs"},
  /* Real Media  */
  { "rtsp://",						 7, "ram"},
  /* Windows registry config file */
  { "REGEDIT4",						 8, "reg"},
  /*  Reaper Project */
  { "<REAPER_PROJECT ",					16, "rpp"},
  /* Olfaction SeeNez subtitle */
  { "#SeeNez ",						 8, "SeeNezSST"},
  /* Sylk, Multiplan Symbolic Link Interchange  */
  { "ID;PSCALC3",					10, "slk"},
  /* Olfaction SeeNez odorama */
  { "DEFAULT\n",					 8, "snz"},
  { "DEFAULT\r\n",					 9, "snz"},
  /* ISO 10303 is an ISO standard for the computer-interpretable
   * representation and exchange of industrial product data.
   * - Industrial automation systems and integration - Product data representation and exchange
   * - Standard for the Exchange of Product model data.
   * */
  { "ISO-10303-21;",					13, "stp"},
  /* URL / Internet Shortcut */
  { "[InternetShortcut]",				18, "url"},
  /* Veeam Backup Metadata */
  { "<BackupMeta Id=\"",				16, "vbm"},
  /* Windows Play List*/
  {"<?wpl version=\"1.0\"?>",				21, "wpl"},
  /* Windows URL / Internet Shortcut */
  {"BEGIN:VBKM",					10, "url"},
  /* firefox session store */
  { "({\"windows\":[{\"tabs\":[{\"entries\":[{\"url\":\"", 42,
#ifdef DJGPP
    "js"
#else
      "sessionstore.js"
#endif
  },
  /* Mathlab Model .mdl */
  { "Model {", 7, "mdl"},
  {NULL, 0, NULL}
};


// #define DEBUG_FILETXT

/* return 1 if char can be found in text file */
static int filtre(unsigned int car)
{
  switch(car)
  {
    case 0x7c:  /* similar to | */
    case 0x80:	/* '€' */
    case 0x92:	/* '’' */
    case 0x99:	/* '™' */
    case 0x9c:	/* 'œ' */
    case 0xa0:  /* nonbreaking space */
    case 0xa1:  /* '¡' */
    case 0xa2:	/* '¢' */
    case 0xa3:	/* '£' */
    case 0xa7:	/* '§' */
    case 0xa8:	/* '¨' */
    case 0xa9:	/* '©' */
    case 0xab:	/* '«' */
    case 0xae:	/* '®' */
    case 0xb0:	/* '°' */
    case 0xb4:  /* '´' */
    case 0xb7:	/* '·' */
    case 0xbb:  /* '»' */
    case 0xc0:  /* 'À' */
    case 0xc7:  /* 'Ç' */
    case 0xc9:  /* 'É' */
    case 0xd6:  /* 'Ö' */
    case 0xd7:	/* '×' */
    case 0xd9:  /* 'Ù' */
    case 0xdf:	/* 'ß' */
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
  if(car=='\b' || car=='\t' || car=='\r' || car=='\n' ||
      (car >=  ' ' && car <=  '~') ||
      (car >= 0x82 && car <= 0x8d) ||
      (car >= 0x93 && car <= 0x98))
    return 1;
  return 0;
}

/* destination should have an extra byte available for null terminator
   return read size */
int UTF2Lat(unsigned char *buffer_lower, const unsigned char *buffer, const int buf_len)
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
      log_info("UTF8 l=3 0x%02x 0x%02x 0x%02x\n", *p, *(p+1),*(p+2));
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

static int UTFsize(const unsigned char *buffer, const unsigned int buf_len)
{
  const unsigned char *p=buffer; 	/* pointers to actual position in source buffer */
  unsigned int i=0;
  while(i<buf_len && *p!='\0')
  {
    /* Reject some invalid UTF-8 sequences */
    if(*p==0xc0 || *p==0xc1 || *p==0xf7 || *p>=0xfd)
      return i;
    if((*p & 0xf0)==0xe0 && i+3 <= buf_len && (*(p+1) & 0xc0)==0x80 && (*(p+2) & 0xc0)==0x80)
    { /* UTF8 l=3 */
      const unsigned int car=(((*p)&0x1f)<<12) | (((*(p+1))&0x3f)<<6) | ((*(p+2))&0x3f);
      if(filtre(car)==0)
	return i;
      p+=3;
      i+=3;
    }
    else if((*p & 0xe0)==0xc0 && i+2 <= buf_len && (*(p+1) & 0xc0)==0x80)
    { /* UTF8 l=2 */
      const unsigned int car=(((*p)&0x1f)<<6) | ((*(p+1))&0x3f);
      if(filtre(car)==0)
	return i;
      p+=2;
      i+=2;
    }
    else
    { /* Ascii UCS */
      if(filtre(*p)==0)
	return i;
      p++;
      i++;
    }
  }
  return i;
}

static data_check_t data_check_html(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  const char sign_html_end[]	= "</html>";
  const unsigned int i=UTFsize(&buffer[buffer_size/2], buffer_size/2);
  unsigned int j;
  for(j=(buffer_size/2>sizeof(sign_html_end)?buffer_size/2-sizeof(sign_html_end):0);
      j+sizeof(sign_html_end)-1 < buffer_size;
      j++)
  {
    if(buffer[j]=='<' && strncasecmp((const char *)&buffer[j], sign_html_end, sizeof(sign_html_end)-1)==0)
    {
      file_recovery->calculated_file_size+=j-buffer_size/2+sizeof(sign_html_end)-1;
      return DC_STOP;
    }
  }
  if(i<buffer_size/2)
  {
    if(i>=10)
      file_recovery->calculated_file_size=file_recovery->file_size+i;
    return DC_STOP;
  }
  file_recovery->calculated_file_size=file_recovery->file_size+(buffer_size/2);
  return DC_CONTINUE;
}

static data_check_t data_check_txt(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  const unsigned int i=UTFsize(&buffer[buffer_size/2], buffer_size/2);
  if(i<buffer_size/2)
  {
    if(i>=10)
      file_recovery->calculated_file_size=file_recovery->file_size+i;
    return DC_STOP;
  }
  file_recovery->calculated_file_size=file_recovery->file_size+(buffer_size/2);
  return DC_CONTINUE;
}

static data_check_t data_check_ttd(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  unsigned int i;
  for(i=buffer_size/2; i<buffer_size; i++)
  {
    const unsigned char car=buffer[i];
    if((car>='A' && car<='F') || (car >='0' && car <='9') || car==' ' || car=='\n')
      continue;
    file_recovery->calculated_file_size=file_recovery->file_size + i - buffer_size/2;
    return DC_STOP;
  }
  file_recovery->calculated_file_size=file_recovery->file_size+(buffer_size/2);
  return DC_CONTINUE;
}

static int header_check_ttd(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(buffer[56]<'0' || buffer[56]>'9')
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->data_check=&data_check_ttd;
  file_recovery_new->file_check=&file_check_size;
  file_recovery_new->extension="ttd";
  return 1;
}

static void file_check_ers(file_recovery_t *file_recovery)
{
  file_search_footer(file_recovery, "DatasetHeader End", 17, 0);
  file_allow_nl(file_recovery, NL_BARENL|NL_CRLF|NL_BARECR);
}

static int header_check_ers(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /* ER Mapper Rasters (ERS) */
  reset_file_recovery(file_recovery_new);
  file_recovery_new->data_check=&data_check_txt;
  file_recovery_new->file_check=&file_check_ers;
  file_recovery_new->extension="ers";
  return 1;
}

static int header_check_ics(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const char *date_asc;
  char *buffer2;
  if(buffer[15]=='\0')
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->data_check=&data_check_txt;
  file_recovery_new->file_check=&file_check_size;
  /* vcalendar  */
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

static int header_check_perlm(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  unsigned int i;
  const unsigned int buffer_size_test=(buffer_size < 2048 ? buffer_size : 2048);
  for(i=0; i<128 && buffer[i]!=';' && buffer[i]!='\n'; i++);
  if(buffer[i]!=';')
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->data_check=&data_check_txt;
  file_recovery_new->file_check=&file_check_size;
  if( td_memmem(buffer, buffer_size_test, "class", 5)!=NULL ||
      td_memmem(buffer, buffer_size_test, "private static", 14)!=NULL ||
      td_memmem(buffer, buffer_size_test, "public interface", 16)!=NULL)
  {
    /* source code in java */
#ifdef DJGPP
    file_recovery_new->extension="jav";
#else
    file_recovery_new->extension="java";
#endif
  }
  else
  {
    /* perl module */
    file_recovery_new->extension="pm";
  }
  return 1;
}

static int header_check_dc(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(buffer[0]=='0' && buffer[1]=='0')
  { /*
       TSCe Survey Controller DC v10.0
     */
    reset_file_recovery(file_recovery_new);
    file_recovery_new->data_check=&data_check_txt;
    file_recovery_new->file_check=&file_check_size;
    file_recovery_new->extension="dc";
    return 1;
  }
  return 0;
}

static int header_check_html(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(file_recovery->file_stat!=NULL &&
      file_recovery->file_stat->file_hint==&file_hint_fasttxt &&
      strcmp(file_recovery->extension,"mbox")==0)
    return 0;
  if(buffer[14]==0)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->data_check=&data_check_html;
  file_recovery_new->file_check=&file_check_size;
  /* Hypertext Markup Language (HTML) */
#ifdef DJGPP
  file_recovery_new->extension="htm";
#else
  file_recovery_new->extension="html";
#endif
  return 1;
}

static void file_check_xml(file_recovery_t *file_recovery)
{
  file_search_footer(file_recovery, ">", 1, 0);
  file_allow_nl(file_recovery, NL_BARENL|NL_CRLF|NL_BARECR);
}

static void file_check_svg(file_recovery_t *file_recovery)
{
  file_search_footer(file_recovery, "</svg>", 6, 0);
  file_allow_nl(file_recovery, NL_BARENL|NL_CRLF|NL_BARECR);
}

static int header_check_xml(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const char *tmp;
  /* buffer may not be null-terminated */
  char *buf=(char *)MALLOC(buffer_size+1);
  memcpy(buf, buffer, buffer_size);
  buf[buffer_size]='\0';
  reset_file_recovery(file_recovery_new);
  file_recovery_new->data_check=&data_check_txt;
  file_recovery_new->extension=NULL;
  tmp=strchr(buf,'<');
  while(tmp!=NULL && file_recovery_new->extension==NULL)
  {
    if(strncasecmp(tmp, "<Grisbi>", 8)==0)
    {
      /* Grisbi - Personal Finance Manager XML data */
      file_recovery_new->extension="gsb";
    }
    else if(strncasecmp(tmp, "<collection type=\"GC", 20)==0)
    {
      /* GCstart, personal collections manager, http://www.gcstar.org/ */
      file_recovery_new->extension="gcs";
    }
    else if(strncasecmp(tmp, "<html", 5)==0)
    {
      file_recovery_new->data_check=&data_check_html;
#ifdef DJGPP
      file_recovery_new->extension="htm";
#else
      file_recovery_new->extension="html";
#endif
    }
    else if(strncasecmp(tmp, "<Version>QBFSD", 14)==0)
    {
      /* QuickBook */
      file_recovery_new->extension="fst";
    }
    else if(strncasecmp(tmp, "<svg", 4)==0)
    {
      /* Scalable Vector Graphics */
      file_recovery_new->extension="svg";
      file_recovery_new->file_check=&file_check_svg;
      free(buf);
      return 1;
    }
    else if(strncasecmp(tmp, "<!DOCTYPE plist ", 16)==0)
    {
      /* Mac OS X property list */
#ifdef DJGPP
      file_recovery_new->extension="pli";
#else
      file_recovery_new->extension="plist";
#endif
    }
    else if(strncasecmp(tmp, "<PremiereData Version=", 22)==0)
    {
      /* Adobe Premiere project  */
      file_recovery_new->data_check=NULL;
      file_recovery_new->extension="prproj";
    }
    else if(strncasecmp(tmp, "<SCRIBUS", 8)==0)
    {
      /* Scribus XML file */
      file_recovery_new->extension="sla";
    }
    else if(strncasecmp(tmp, "<FictionBook", 12)==0)
    {
      /* FictionBook, see http://www.fictionbook.org */
      file_recovery_new->extension="fb2";
    }
    tmp++;
    tmp=strchr(tmp,'<');
  }
  if(file_recovery_new->extension==NULL)
  {
    /* XML Extensible Markup Language */
    file_recovery_new->extension="xml";
  }
  file_recovery_new->file_check=&file_check_xml;
  free(buf);
  return 1;
}

static int header_check_rtf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  unsigned int i;
  for(i=0; i<16; i++)
    if(buffer[i]=='\0')
      return 0;
  /* Avoid a false positive with .snt */
  if(file_recovery->file_stat!=NULL &&
      file_recovery->file_stat->file_hint==&file_hint_doc)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->data_check=&data_check_txt;
  file_recovery_new->file_check=&file_check_size;
  /* Rich Text Format */
  file_recovery_new->extension="rtf";
  return 1;
}

static int header_check_xmp(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(buffer[35]=='\0')
    return 0;
  if(file_recovery->file_stat!=NULL &&
      (file_recovery->file_stat->file_hint==&file_hint_pdf ||
       file_recovery->file_stat->file_hint==&file_hint_tiff))
    return 0;
  /* Adobe's Extensible Metadata Platform */
  reset_file_recovery(file_recovery_new);
  file_recovery_new->data_check=&data_check_txt;
  file_recovery_new->file_check=&file_check_size;
  file_recovery_new->extension="xmp";
  return 1;
}

static int header_check_mbox(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  unsigned int i;
  if(file_recovery->file_stat!=NULL &&
      file_recovery->file_stat->file_hint==&file_hint_fasttxt &&
      strcmp(file_recovery->extension,"mbox")==0)
    return 0;
  for(i=0; i<64; i++)
    if(buffer[i]==0)
      return 0;
  if( memcmp(buffer, "From ", 5)==0 &&
      memcmp(buffer, "From MAILER-DAEMON ", 19)!=0)
  {
    /* From someone@somewhere */
    for(i=5; i<200 && buffer[i]!=' ' && buffer[i]!='@'; i++);
    if(buffer[i]!='@')
      return 0;
  }
  reset_file_recovery(file_recovery_new);
  file_recovery_new->data_check=&data_check_txt;
  file_recovery_new->file_check=&file_check_size;
  /* Incredimail has .imm extension but this extension isn't frequent */
  file_recovery_new->extension="mbox";
  return 1;
}

static int header_check_fasttxt(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const txt_header_t *header=&fasttxt_headers[0];
  while(header->len > 0)
  {
    if(memcmp(buffer, header->string, header->len)==0)
    {
      if(buffer[header->len]=='\0')
	return 0;
      reset_file_recovery(file_recovery_new);
      file_recovery_new->data_check=&data_check_txt;
      file_recovery_new->file_check=&file_check_size;
      file_recovery_new->extension=header->extension;
      file_recovery_new->min_filesize=header->len+1;
      return 1;
    }
    header++;
  }
  return 0;
}

static int is_ini(const char *buffer)
{
  const char *src=buffer;
  if(*src!='[')
    return 0;
  src++;
  while(1)
  {
    if(*src==']')
    {
      if(src > buffer + 3)
	return 1;
      return 0;
    }
    if(!isalnum(*src) && *src!=' ')
      return 0;
    src++;
  }
}

#ifdef UTF16
static int header_check_le16_txt(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  unsigned int i;
  for(i=0; i+1 < buffer_size; i+=2)
  {
    if(!( buffer[i+1]=='\0' && (isprint(buffer[i]) || buffer[i]=='\n' || buffer[i]=='\r' || buffer[i]==0xbb)))
    {
      if(i<40)
	return 0;
      reset_file_recovery(file_recovery_new);
      file_recovery_new->calculated_file_size=i;
      file_recovery_new->data_check=&data_check_size;
      file_recovery_new->file_check=&file_check_size;
      file_recovery_new->extension="utf16";
      return 1;
    }
  }
  reset_file_recovery(file_recovery_new);
  file_recovery_new->calculated_file_size=i;
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  file_recovery_new->extension="utf16";
  return 1;
}
#endif

static void file_check_emlx(file_recovery_t *file_recovery)
{
  if(file_recovery->file_size < file_recovery->calculated_file_size)
    file_recovery->file_size=0;
  else
  {
    if(file_recovery->file_size > file_recovery->calculated_file_size+2048)
      file_recovery->file_size=file_recovery->calculated_file_size+2048;
    file_search_footer(file_recovery, "</plist>\n", 9, 0);
  }
}

static int header_check_txt(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  static char *buffer_lower=NULL;
  static unsigned int buffer_lower_size=0;
  unsigned int l;
  const unsigned int buffer_size_test=(buffer_size < 2048 ? buffer_size : 2048);
  {
    unsigned int i;
    unsigned int tmp=0;
    for(i=0;i<10 && isdigit(buffer[i]);i++)
      tmp=tmp*10+buffer[i]-'0';
    if(buffer[i]==0x0a &&
      (memcmp(buffer+i+1, "Return-Path: ", 13)==0 ||
       memcmp(buffer+i+1, "Received: from", 14)==0) &&
        !(file_recovery->file_stat!=NULL &&
          file_recovery->file_stat->file_hint==&file_hint_fasttxt &&
          strcmp(file_recovery->extension,"mbox")==0))
    {
      reset_file_recovery(file_recovery_new);
      file_recovery_new->calculated_file_size=tmp+i+1;
      file_recovery_new->data_check=NULL;
      file_recovery_new->file_check=&file_check_emlx;
      /* Mac OSX mail */
      file_recovery_new->extension="emlx";
      return 1;
    }
  }
  if(strncasecmp((const char *)buffer, "@echo off", 9)==0)
  {
    if(buffer[9]=='\0')
      return 0;
    reset_file_recovery(file_recovery_new);
    file_recovery_new->data_check=&data_check_txt;
    file_recovery_new->file_check=&file_check_size;
    /* Dos/Windows bath */
    file_recovery_new->extension="bat";
    return 1;
  }
  if(strncasecmp((const char *)buffer, "<%@ language=\"vbscript", 22)==0)
  {
    if(buffer[22]=='\0')
      return 0;
    reset_file_recovery(file_recovery_new);
    file_recovery_new->data_check=&data_check_txt;
    file_recovery_new->file_check=&file_check_size;
    /* Microsoft Active Server Pages */
    file_recovery_new->extension="asp";
    return 1;
  }
  if(strncasecmp((const char *)buffer, "version 4.00\r\nbegin", 19)==0)
  {
    if(buffer[19]=='\0')
      return 0;
    reset_file_recovery(file_recovery_new);
    file_recovery_new->data_check=&data_check_txt;
    file_recovery_new->file_check=&file_check_size;
    /* Microsoft Visual Basic */
    file_recovery_new->extension="vb";
    return 1;
  }
  if(strncasecmp((const char *)buffer, "begin:vcard", 11)==0)
  {
    if(buffer[11]=='\0')
      return 0;
    reset_file_recovery(file_recovery_new);
    file_recovery_new->data_check=&data_check_txt;
    file_recovery_new->file_check=&file_check_size;
    /* vcard, electronic business cards */
    file_recovery_new->extension="vcf";
    return 1;
  }
  if(buffer[0]=='#' && buffer[1]=='!')
  {
    unsigned int ll=512-2;
    const unsigned char *haystack=(const unsigned char *)buffer+2;
    const unsigned char *res;
    res=(const unsigned char *)memchr(haystack,'\n',ll);
    if(res!=NULL)
      ll=res-haystack;
    if(td_memmem(haystack, ll, "perl", 4) != NULL)
    {
      reset_file_recovery(file_recovery_new);
      file_recovery_new->data_check=&data_check_txt;
      file_recovery_new->file_check=&file_check_size;
      /* Perl script */
      file_recovery_new->extension="pl";
      return 1;
    }
    if(td_memmem(haystack, ll, "python", 6) != NULL)
    {
      reset_file_recovery(file_recovery_new);
      file_recovery_new->data_check=&data_check_txt;
      file_recovery_new->file_check=&file_check_size;
      /* Python script */
      file_recovery_new->extension="py";
      return 1;
    }
    if(td_memmem(haystack, ll, "ruby", 4) != NULL)
    {
      reset_file_recovery(file_recovery_new);
      file_recovery_new->data_check=&data_check_txt;
      file_recovery_new->file_check=&file_check_size;
      /* Ruby script */
      file_recovery_new->extension="rb";
      return 1;
    }
  }
  if(safe_header_only!=0)
  {
    return 0;
  }
  if(file_recovery->file_stat!=NULL)
  {
    if(file_recovery->file_stat->file_hint == &file_hint_doc)
    {
      if(strstr(file_recovery->filename,".doc")==NULL)
	return 0;
    }
    else if(file_recovery->file_stat->file_hint == &file_hint_fasttxt ||
	file_recovery->file_stat->file_hint == &file_hint_txt)
    {
      if(strstr(file_recovery->filename,".html")==NULL)
	return 0;
    }
    else if(file_recovery->file_stat->file_hint == &file_hint_jpg)
    {
      /* Don't search text at the beginning of JPG */
      if(file_recovery->file_size < file_recovery->min_filesize)
	return 0;
      /* Text should not be found in JPEG */
      if(td_memmem(buffer, buffer_size_test, "8BIM", 4)!=NULL ||
	  td_memmem(buffer, buffer_size_test, "adobe", 5)!=NULL ||
	  td_memmem(buffer, buffer_size_test, "exif:", 5)!=NULL ||
	  td_memmem(buffer, buffer_size_test, "<rdf:", 5)!=NULL ||
	  td_memmem(buffer, buffer_size_test, "<?xpacket", 9)!=NULL ||
	  td_memmem(buffer, buffer_size_test, "<dict>", 6)!=NULL ||
	  td_memmem(buffer, buffer_size_test, "xmp:CreatorTool>", 16)!=NULL ||
	  td_memmem(buffer, buffer_size_test, "[camera info]", 13)!=NULL)
	return 0;
    }
    else
      return 0;
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
  if(l<10)
    return 0;
  {
    unsigned int line_nbr=0;
    unsigned int i;
    for(i=0; i<512 && i<l; i++)
    {
      if(buffer[i]=='\n')
	line_nbr++;
    }
    /* A text file must contains several lines */
    if(line_nbr==0)
      return 0;
  }
  if(strncasecmp((const char *)buffer, "rem ", 4)==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->data_check=&data_check_txt;
    file_recovery_new->file_check=&file_check_size;
    /* Dos/Windows bath */
    file_recovery_new->extension="bat";
    return 1;
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
    /* if(l>1) */
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
    /* Windows Autorun */
    if(strstr(buffer_lower, "[autorun]")!=NULL)
      ext="inf";
    /* Detect .ini */
    else if(buffer[0]=='[' && l>50 && is_ini(buffer_lower))
      ext="ini";
    /* php (Hypertext Preprocessor) script */
    else if(strstr(buffer_lower, "<?php")!=NULL)
      ext="php";
    /* Comma separated values */
    else if(is_csv>0)
      ext="csv";
    /* Detect LaTeX, C, PHP, JSP, ASP, HTML, C header */
    else if(strstr(buffer_lower, "\\begin{")!=NULL)
      ext="tex";
    else if(strstr(buffer_lower, "#include")!=NULL)
      ext="c";
    else if(l>20 && strstr(buffer_lower, "<%@")!=NULL)
      ext="jsp";
    else if(l>20 && strstr(buffer_lower, "<%=")!=NULL)
      ext="jsp";
    else if(l>20 && strstr(buffer_lower, "<% ")!=NULL)
      ext="asp";
    else if(strstr(buffer_lower, "<html")!=NULL)
      ext="html";
    else if(strstr(buffer_lower, "private static")!=NULL ||
	strstr(buffer_lower, "public interface")!=NULL)
    {
#ifdef DJGPP
      ext="jav";
#else
      ext="java";
#endif
    }
    else if(strstr(buffer_lower, "class")!=NULL &&
	(l>=100 || file_recovery->file_stat==NULL))
    {
#ifdef DJGPP
      ext="jav";
#else
      ext="java";
#endif
    }
    /* Fortran */
    else if(nbrf>10 && ind<0.9 && strstr(buffer_lower, "integer")!=NULL)
      ext="f";
    /* LilyPond http://lilypond.org*/
    else if(strstr(buffer_lower, "\\score {")!=NULL)
      ext="ly";
    /* C header file */
    else if(strstr(buffer_lower, "/*")!=NULL && l>50)
      ext="h";
    else if(l<100 || ind<0.03 || ind>0.90)
      ext=NULL;
    /* JavaScript Object Notation  */
    else if(memcmp(buffer_lower, "{\"", 2)==0)
      ext="json";
    else
      ext=file_hint_txt.extension;
    if(ext==NULL)
      return 0;
    if(strcmp(ext,"txt")==0 &&
	(strstr(buffer_lower,"<br>")!=NULL || strstr(buffer_lower,"<p>")!=NULL))
    {
      ext="html";
    }
    if(file_recovery->file_stat!=NULL)
    {
      if(file_recovery->file_stat->file_hint == &file_hint_doc)
      {
	unsigned int i;
	unsigned int txt_nl=0;
	/* file_recovery->filename is .doc */
	if(ind>0.20)
	  return 0;
	/* Unix: \n (0xA)
	 * Dos: \r\n (0xD 0xA)
	 * Doc: \r (0xD) */
	for(i=0; i<l-1; i++)
	{
	  if(buffer_lower[i]=='\r' && buffer_lower[i+1]!='\n')
	    return 0;
	}
	for(i=0; i<l && i<512; i++)
	  if(buffer_lower[i]=='\n')
	    txt_nl++;
	if(txt_nl<=1)
	  return 0;
      }
      else if(file_recovery->file_stat->file_hint == &file_hint_fasttxt ||
	  file_recovery->file_stat->file_hint == &file_hint_txt)
      {
	/* file_recovery->filename is a .html */
	buffer_lower[511]='\0';
	if(strstr(buffer_lower, "<html")==NULL)
	  return 0;
	/* Special case: two consecutive HTML files */
      }
    }
    reset_file_recovery(file_recovery_new);
    if(strcmp(ext, "html")==0)
      file_recovery_new->data_check=&data_check_html;
    else
      file_recovery_new->data_check=&data_check_txt;
    file_recovery_new->file_check=&file_check_size;
    file_recovery_new->extension=ext;
    return 1;
  }
}

static void file_check_smil(file_recovery_t *file_recovery)
{
  file_search_footer(file_recovery, "</smil>", 7, 0);
  file_allow_nl(file_recovery, NL_BARENL|NL_CRLF|NL_BARECR);
}

static int header_check_smil(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /* Synchronized Multimedia Integration Language
   * http://en.wikipedia.org/wiki/Synchronized_Multimedia_Integration_Language */
  reset_file_recovery(file_recovery_new);
  file_recovery_new->data_check=&data_check_txt;
  file_recovery_new->file_check=&file_check_smil;
  file_recovery_new->extension="smil";
  return 1;
}

static int header_check_stl(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const unsigned int buffer_size_test=(buffer_size < 512? buffer_size : 512);
  if(td_memmem(buffer, buffer_size_test, "facet normal", 12)==NULL)
    return 0;
  /* StereoLithography - STL Ascii format
   * http://www.ennex.com/~fabbers/StL.asp	*/
  reset_file_recovery(file_recovery_new);
  file_recovery_new->data_check=&data_check_txt;
  file_recovery_new->file_check=&file_check_size;
  file_recovery_new->extension="stl";
  return 1;
}

static void register_header_check_fasttxt(file_stat_t *file_stat)
{
  static const unsigned char header_xml_utf8[17]	= {0xef, 0xbb, 0xbf, '<', '?', 'x', 'm', 'l', ' ', 'v', 'e', 'r', 's', 'i', 'o', 'n', '='};
  const txt_header_t *header=&fasttxt_headers[0];
  while(header->len > 0)
  {
    register_header_check(0, header->string, header->len, &header_check_fasttxt, file_stat);
    header++;
  }
  register_header_check(4, "SC V10", 		6,  &header_check_dc, file_stat);
  register_header_check(0, "DatasetHeader Begin", 19, &header_check_ers, file_stat);
//  register_header_check(0, "\n<!DOCTYPE html",	15, &header_check_html, file_stat);
  register_header_check(0, "<!DOCTYPE html",	14, &header_check_html, file_stat);
  register_header_check(0, "<!DOCTYPE HTML",	14, &header_check_html, file_stat);
//  register_header_check(0, "<html",		 5, &header_check_html, file_stat);
  register_header_check(0, "BEGIN:VCALENDAR",	15, &header_check_ics, file_stat);
  register_header_check(0, "From ",		 5, &header_check_mbox, file_stat);
  register_header_check(0, "Message-ID: ",	12, &header_check_mbox, file_stat);
  register_header_check(0, "MIME-Version:",	13, &header_check_mbox, file_stat);
  register_header_check(0, "Received: from ",	15, &header_check_mbox, file_stat);
  register_header_check(0, "Reply-To: ",	10, &header_check_mbox, file_stat);
  register_header_check(0, "Return-path: ",	13, &header_check_mbox, file_stat);
  register_header_check(0, "Return-Path: ",	13, &header_check_mbox, file_stat);
  register_header_check(0, "package ",		 8, &header_check_perlm, file_stat);
  register_header_check(0, "package\t", 	 8, &header_check_perlm, file_stat);
  register_header_check(0, "{\\rtf",		 5, &header_check_rtf, file_stat);
  register_header_check(0, "<smil>",		 6, &header_check_smil, file_stat);
  register_header_check(0, "solid ",		 6, &header_check_stl, file_stat);
  register_header_check(0, "<?xml version=",	14, &header_check_xml, file_stat);
  register_header_check(0, header_xml_utf8, sizeof(header_xml_utf8), &header_check_xml, file_stat);
  /* TinyTag */
  register_header_check(0, "FF 09 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FFFF 00", 55, &header_check_ttd, file_stat);
  register_header_check(0, "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"", 35, &header_check_xmp, file_stat);
}
