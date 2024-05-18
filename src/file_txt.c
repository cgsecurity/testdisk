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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_txt)
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
#include <assert.h>
#include <stdio.h>
#include "types.h"
#include "common.h"
#include "filegen.h"
#include "log.h"
#include "memmem.h"
#include "utfsize.h"
#if defined(__FRAMAC__)
#include "__fc_builtin.h"
#endif

#if !defined(MAIN_txt) && !defined(SINGLE_FORMAT)
extern const file_hint_t file_hint_doc;
extern const file_hint_t file_hint_jpg;
extern const file_hint_t file_hint_pdf;
extern const file_hint_t file_hint_sld;
extern const file_hint_t file_hint_tiff;
extern const file_hint_t file_hint_zip;
#endif

typedef struct
{
  const char *string;
  const unsigned int len;
  const char *extension;
} txt_header_t;

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_fasttxt(file_stat_t *file_stat);
/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_snz(file_stat_t *file_stat);
/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_txt(file_stat_t *file_stat);

static const char *extension_asp="asp";
static const char *extension_bat="bat";
static const char *extension_c="c";
static const char *extension_csv="csv";
static const char *extension_cdxml="cdxml";
static const char *extension_dc="dc";
static const char *extension_emlx="emlx";
static const char *extension_ers="ers";
static const char *extension_f="f";
static const char *extension_fb2="fb2";
static const char *extension_fods="fods";
static const char *extension_fst="fst";
static const char *extension_gcs="gcs";
static const char *extension_ghx="ghx";
static const char *extension_go="go";
static const char *extension_gpx="gpx";
static const char *extension_groovy="groovy";
static const char *extension_gsb="gsb";
static const char *extension_h="h";
#ifdef DJGPP
static const char *extension_html="htm";
#else
static const char *extension_html="html";
#endif
static const char *extension_ics="ics";
static const char *extension_inf="inf";
static const char *extension_ini="ini";
#ifdef DJGPP
static const char *extension_java="jav";
#else
static const char *extension_java="java";
#endif
static const char *extension_json="json";
static const char *extension_jsp="jsp";
static const char *extension_ldif="ldif";
static const char *extension_ly="ly";
static const char *extension_mbox="mbox";
static const char *extension_mol2="mol2";
static const char *extension_php="php";
static const char *extension_pl="pl";
#ifdef DJGPP
static const char *extension_plist="pli";
#else
static const char *extension_plist="plist";
#endif
static const char *extension_pm="pm";
static const char *extension_prproj="prproj";
static const char *extension_py="py";
static const char *extension_rb="rb";
static const char *extension_rtf="rtf";
static const char *extension_sla="sla";
static const char *extension_smil="smil";
static const char *extension_stl="stl";
static const char *extension_svg="svg";
static const char *extension_ttd="ttd";
static const char *extension_tex="tex";
#ifdef UTF16
static const char *extension_utf16="utf16";
#endif
static const char *extension_vb="vb";
static const char *extension_vbm="vbm";
static const char *extension_vcf="vcf";
static const char *extension_xml="xml";
static const char *extension_xmp="xmp";

const file_hint_t file_hint_fasttxt= {
  .extension="tx?",
  .description="Text files with header: rtf,xml,xhtml,mbox/imm,pm,ram,reg,sh,slk,stp,jad,url",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_fasttxt
};

const file_hint_t file_hint_snz= {
  .extension="snz",
  .description="Olfaction SeeNez odorama",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_snz
};

const file_hint_t file_hint_txt= {
  .extension="txt",
  .description="Other text files: txt,html,asp,bat,C,jsp,perl,php,py/emlx... scripts",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_txt
};

static unsigned char ascii_char[256];

static const txt_header_t fasttxt_headers[] = {
  /* Unix shell */
  { "#!/bin/bash", 					11, "sh"},
  { "#!/bin/ksh",					10, "sh"},
#ifndef DISABLED_FOR_FRAMAC
  { "#!/bin/sh",					 9, "sh"},
  { "#! /bin/bash", 					12, "sh"},
  { "#! /bin/ksh",					11, "sh"},
  { "#! /bin/sh",					10, "sh"},
  { "#!/usr/bin/env groovy",				21, "groovy"},
  { "#!/usr/bin/env perl",				19, "pl"},
  { "#!/usr/bin/env php",				18, "php"},
  { "#!/usr/bin/env python",				21, "py"},
  { "#!/usr/bin/env ruby",				19, "rb"},
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
  { "-----BEGIN DSA PRIVATE KEY-----",			31, "dsa"},
  /* EMKA IOX file */
  { "1\t\t\t\t\tthis file\t", 				16,
#ifdef DJGPP
    "emk"
#else
    "emka"
#endif
  },
  /* Source code in go language */
  { "package main",					12, "go"},
  /* ENVI */
  { "ENVI\r\ndescription",				17, "hdr"},
  /* Java Application Descriptor
   * http://en.wikipedia.org/wiki/JAD_%28file_format%29 */
  { "MIDlet-1:",					 9, "jad"},
  { "{\"title\":\"\",\"id\":1,\"dateAdded\":",		31, "json"},
  { "-----BEGIN RSA PRIVATE KEY-----",			31, "key"},
  /* Lyx http://www.lyx.org */
  { "#LyX 1.", 						 7, "lyx"},
  { "#LyX 2.", 						 7, "lyx"},
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
  { "# ************************************************************\n# Sequel Pro SQL dump", 84, "sql"},
  { "---- BEGIN SSH2 PUBLIC KEY ----",			31, "ppk"},
  { "PuTTY-User-Key-File-2:",				22, "ppk"},
  { "-----BEGIN PGP PRIVATE KEY BLOCK-----",		37, "priv"},
  { "-----BEGIN PGP PUBLIC KEY BLOCK-----",		36, "pub"},
  /* PTGui,  panoramic stitching software */
  { "# ptGui project file",				20, "pts"},
  { "ssh-dss AAAAB3",					14, "pub"},
  { "ssh-rsa AAAAB3",					14, "pub"},
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
  /* Windows folder settings for file explorer */
  { "[.ShellClassInfo]",				17, "Desktop.ini" },
  /* Fotobook */
  { "<fotobook ",					10, "mcf"},
#endif
  {NULL, 0, NULL}
};


// #define DEBUG_FILETXT

/* return 1 if char can be found in text file */
/*@
  @ assigns \nothing;
  @*/
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
    case 0xe0:	/* 'à' */
    case 0xe1:	/* 'á' */
    case 0xe2:	/* 'â' */
    case 0xe3:  /* 'ã' */
    case 0xe4:	/* 'ä' */
    case 0xe6:  /* 'æ' */
    case 0xe7:	/* 'ç' */
    case 0xe8:	/* 'è' */
    case 0xe9:	/* 'é' */
    case 0xea:	/* 'ê' */
    case 0xeb:	/* 'ë' */
    case 0xed:  /* 'í' */
    case 0xee:	/* 'î' */
    case 0xef:	/* 'ï' */
    case 0xf4:	/* 'ô' */
    case 0xf6:	/* 'ö' */
    case 0xf8:  /* 'ø' */
    case 0xf9:	/* 'ù' */
    case 0xfa:  /* 'ú' */
    case 0xfb:	/* 'û' */
    case 0xfc:	/* 'ü' */
      return 1;
  }
  if(car=='\b' || car=='\t' || car=='\r' || car=='\n' ||
      (car >=  ' ' && car <=  '~') ||
      (car >= 0x82 && car <= 0x8d) ||
      (car >= 0x93 && car <= 0x98))
    return 1;
  return 0;
}

/*@
  @ requires \valid_read(buffer+(0..buffer_size-1));
  @ requires \initialized(buffer+(0..buffer_size-1));
  @ terminates \true;
  @ assigns \nothing;
  @*/
static int has_newline(const char *buffer, const unsigned int buffer_size)
{
  unsigned int i;
  /*@
    @ loop invariant 0 <= i <= 512;
    @ loop assigns i;
    @ loop variant 512-i;
    @*/
  for(i=0; i<512 && i < buffer_size && buffer[i]!='\0'; i++)
  {
    if(buffer[i]=='\n')
      return 1;
  }
  /* A text file must contains several lines */
  return 0;
}

/*@
  @ requires buffer_size > 0;
  @ requires \valid_read(buffer+(0..buffer_size-1));
  @ terminates \true;
  @ assigns \nothing;
  @*/
static unsigned int is_csv(const char *buffer, const unsigned int buffer_size)
{
  unsigned int csv_per_line_current=0;
  unsigned int csv_per_line=0;
  unsigned int line_nbr=0;
  unsigned int i;
  /*@
    @ loop invariant 0 <= i <= buffer_size;
    @ loop invariant csv_per_line_current <= i;
    @ loop invariant line_nbr <= i;
    @ loop assigns i, csv_per_line_current, csv_per_line, line_nbr;
    @ loop variant buffer_size-i;
    @*/
  for(i=0; i<buffer_size; i++)
  {
    if(buffer[i]==';')
    {
      csv_per_line_current++;
    }
    else if(buffer[i]=='\n')
    {
      if(line_nbr==0)
      {
	if(csv_per_line_current==0)
	  return 0;
	csv_per_line=csv_per_line_current;
      }
      if(csv_per_line_current!=csv_per_line)
	return 0;
      line_nbr++;
      csv_per_line_current=0;
    }
  }
  if(line_nbr<10)
    return 0;
  return 1;
}

/*@
  @ requires valid_read_string(buffer);
  @ assigns \nothing;
  @*/
static unsigned int is_fortran(const char *buffer)
{
  const char *str=buffer;
  unsigned int i=0;
  /* Detect Fortran */
  /*@ assert valid_read_string(str); */
  /*@
    @ loop invariant 0 <= i <= 10;
    @ loop invariant valid_read_string(str);
    @ loop assigns str,i;
    @ loop variant 10 - i;
    @*/
  for(i=0; i<10; i++)
  {
    str=strstr(str, "\n      ");
    if(str==NULL)
      return 0;
    /*@ assert valid_read_string(str); */
#ifdef DISABLED_FOR_FRAMAC
    if(*str=='\0')
      return 0;
#endif
    str++;
    /*@ assert valid_read_string(str); */
  }
  if(i < 10)
    return 0;
  if(strstr(buffer, "integer")==NULL)
    return 0;
  return 1;
}

/*@
  @ requires valid_read_string((char *)buffer);
  @ assigns \nothing;
  @*/
static int is_ini(const char *buffer)
{
  const char *src=buffer;
  if(*src!='[')
    return 0;
  src++;
  /*@ assert strlen(buffer) == 1 + strlen(src); */
  /*@ ghost unsigned int i = 1; */
  /*@
    @ loop invariant strlen(buffer) > strlen(src);
    @ loop invariant strlen(src) >= 0;
    @ loop invariant valid_read_string(src);
    @ loop invariant src == buffer + i;
    @ loop invariant i <= strlen(buffer);
    @ loop assigns src;
    @ loop assigns i;
    @ loop variant strlen(buffer) - i;
    @*/
  while(*src!='\0')
  {
    if(*src==']')
    {
      if(src > buffer + 3)
        return 1;
      return 0;
    }
    if(!isalnum(*(const unsigned char *)src) && *src!=' ')
      return 0;
    src++;
    /*@ ghost i++; */
  }
  return 0;
}

/*@
  @ requires buffer_size >= 0;
  @ requires \valid_read(buffer+(0..buffer_size-1));
  @ requires \initialized(buffer+(0..buffer_size-1));
  @ terminates \true;
  @ assigns  \nothing;
  @*/
static double is_random(const unsigned char *buffer, const unsigned int buffer_size)
{
  unsigned int stats[256];
  unsigned int i;
  double ind;
  if(buffer_size < 2)
    return 1;
#ifndef DISABLED_FOR_FRAMAC
  memset(&stats, 0, sizeof(stats));
#else
  /*@
    @ loop invariant \forall integer j; (0 <= j < i) ==> stats[j] == 0;
    @ loop invariant \initialized(&stats[0 .. i-1]);
    @ loop assigns i, stats[0 ..i];
    @ loop variant 256-i;
    @ */
  for(i=0; i < 256; i++)
    stats[i] = 0;
#endif
  /*@ assert initialization: \initialized(&stats[0 .. 255]); */
  /*@ assert \forall int j; (0 <= j <= 255) ==> (stats[j] == 0); */
  /*@
    @ loop invariant 0 <= i <= buffer_size;
    @ loop invariant \forall integer j; (0 <= j <= 255) ==> (stats[j] <= i);
    @ loop assigns i, stats[0..255];
    @ loop variant buffer_size-i;
    @*/
  for(i=0; i<buffer_size; i++)
  {
    /*@ assert \forall int j; (0 <= j <= 255) ==> (stats[j] <= i); */
    stats[buffer[i]]++;
    /*@ assert \forall int j; (0 <= j <= 255) ==> (stats[j] <= i+1); */
  }
  /*@ assert \forall integer j; (0 <= j <= 255) ==> stats[j] <= buffer_size; */
  ind=0;
  /*@
    @ loop invariant 0 <= i <= 256;
    @ loop assigns i,ind;
    @ loop variant 256-i;
    @*/
  for(i=0; i<256; i++)
  {
    /*@ assert stats[i] <= buffer_size; */
    const unsigned int c=stats[i];
    /*@ assert 0 <= c <= buffer_size; */
    if(c>0)
      ind+=c*(c-1);
  }
  return ind/buffer_size/(buffer_size-1);
}

/* destination should have an extra byte available for null terminator
   return written size */
/*@
  @ requires buf_len > 0;
  @ requires \valid(buffer_lower + (0..buf_len-1));
  @ requires \valid_read(buffer + (0..buf_len-1));
  @ requires \initialized(buffer + (0..buf_len-1));
  @ requires \separated(buffer + (0..buf_len-1), buffer_lower + (0..buf_len-1));
  @ ensures \result <= buf_len;
  @*/
/* TODO assigns buffer_lower[0 .. \result]; */
static int UTF2Lat(unsigned char *buffer_lower, const unsigned char *buffer, const int buf_len)
{
  const unsigned char *p;	/* pointers to actual position in source buffer */
  unsigned char *q;	/* pointers to actual position in destination buffer */
  unsigned int offset_dst;
  /* destination will be null terminated */
  /*@
    @ loop invariant offset_dst < buf_len;
    @ loop invariant q == buffer_lower + offset_dst;
    @ loop assigns offset_dst, p, q;
    @ loop assigns buffer_lower[0 .. offset_dst];
    @ loop variant buf_len - 1 - offset_dst;
    @*/
  for (offset_dst = 0, p = buffer, q = buffer_lower;
      p+2-buffer<buf_len && offset_dst < buf_len-1 && *p!='\0';)
  {
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
	  {
	    unsigned char tmp=((*(p+1)) | 0x80) & 0xBF; /* A0-BF and a few 80-9F */
	    if(tmp == 0xA0)
	      (*q) = ' ';
	    else
	      (*q) = tmp;
	  }
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
    else if( 'A' <= *p && *p <='Z')
    {
      /*@ assert 'A' <= *p <= 'Z'; */
      /*@ assert 0 <= *p - 'A' <= 26; */
      *q = *p-'A'+'a';
      p++;
    }
    else
    { /* Ascii UCS */
#ifdef DEBUG_TXT
      log_info("UTF8 Ascii UCS 0x%02x\n", *p);
#endif
      *q = *p;
      p++;
    }
    if (*q=='\0' || filtre(*q)==0)
    {
#ifdef DEBUG_TXT
      log_warning("UTF2Lat reject 0x%x\n",*q);
#endif
      *q = '\0';
      return offset_dst;
    }
    q++;
    offset_dst++;
  }
  /*@ assert q == buffer_lower + offset_dst; */
  *q = '\0';
  return offset_dst;
}

/*@
  @ requires file_recovery->data_check == &data_check_html;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ assigns file_recovery->calculated_file_size;
  @*/
static data_check_t data_check_html(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  const char sign_html_end[]	= "</html>";
  if(buffer_size/2 > (sizeof(sign_html_end)-1))
  {
    unsigned int j;
    /*@
      @ loop assigns j, file_recovery->calculated_file_size;
      @ loop variant buffer_size - (j+sizeof(sign_html_end)-1);
      @*/
    for(j=buffer_size/2-(sizeof(sign_html_end)-1);
	j+sizeof(sign_html_end)-1 < buffer_size;
	j++)
    {
      if(buffer[j]=='<' && strncasecmp((const char *)&buffer[j], sign_html_end, sizeof(sign_html_end)-1)==0)
      {
	j+=sizeof(sign_html_end)-1;
	/*@ assert j >= buffer_size/2; */
	/*@
	  @ loop assigns j;
	  @ loop variant buffer_size - j;
	  @*/
	while(j < buffer_size && (buffer[j]=='\n' || buffer[j]=='\r'))
	  j++;
	file_recovery->calculated_file_size+=j-buffer_size/2;
	return DC_STOP;
      }
    }
  }
  {
    const unsigned int i=UTFsize(&buffer[buffer_size/2], buffer_size/2);
    if(i<buffer_size/2)
    {
      if(i>=10)
	file_recovery->calculated_file_size=file_recovery->file_size+i;
      return DC_STOP;
    }
  }
  file_recovery->calculated_file_size=file_recovery->file_size+(buffer_size/2);
  return DC_CONTINUE;
}

/*@
  @ requires file_recovery->data_check == &data_check_ttd;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ terminates \true;
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ assigns file_recovery->calculated_file_size;
  @*/
static data_check_t data_check_ttd(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  unsigned int i;
  /*@
    @ loop invariant buffer_size/2 <= i <= buffer_size;
    @ loop assigns i, file_recovery->calculated_file_size;
    @ loop variant buffer_size - i;
    @*/
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

/*@
  @ requires file_recovery->data_check == &data_check_txt;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ terminates \true;
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ assigns file_recovery->calculated_file_size;
  @*/
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

/*@
  @ requires file_recovery->data_check == &data_check_xml_utf8;
  @ requires buffer_size >= 10;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ terminates \true;
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ ensures \result == DC_CONTINUE ==> (file_recovery->data_check==&data_check_txt);
  @ assigns file_recovery->calculated_file_size,file_recovery->data_check;
  @*/
static data_check_t data_check_xml_utf8(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  unsigned int i;
  if(buffer_size<=8)
    return DC_CONTINUE;
  i=UTFsize(&buffer[buffer_size/2+4], buffer_size/2-4)+4;
  if(i<buffer_size/2)
  {
    file_recovery->calculated_file_size=file_recovery->file_size+i;
    return DC_STOP;
  }
  file_recovery->calculated_file_size=file_recovery->file_size+(buffer_size/2);
  file_recovery->data_check=&data_check_txt;
  return DC_CONTINUE;
}

/*@
  @ requires file_recovery->file_rename==&file_rename_fods;
  @ requires valid_file_rename_param(file_recovery);
  @ ensures  valid_file_rename_result(file_recovery);
  @*/
static void file_rename_fods(file_recovery_t *file_recovery)
{
  const char *meta_title="<office:meta><dc:title>";
  FILE *file;
  char buffer[4096];
  char *tmp=NULL;
  size_t lu;
  /*@ assert valid_read_string((char*)file_recovery->filename); */
  if((file=fopen(file_recovery->filename, "rb"))==NULL)
  {
    /*@ assert valid_read_string((char*)file_recovery->filename); */
    return;
  }
  if((lu=fread(&buffer, 1, sizeof(buffer)-1, file)) <= 0)
  {
    fclose(file);
    /*@ assert valid_read_string((char*)file_recovery->filename); */
    return ;
  }
#if defined(__FRAMAC__)
  Frama_C_make_unknown(buffer, sizeof(buffer)-1);
#endif
  fclose(file);
  buffer[lu]='\0';
#ifndef DISABLED_FOR_FRAMAC
  /*@
    @ loop invariant tmp==\null || valid_read_string(tmp);
    @ loop assigns tmp;
    @*/
  for(tmp=strchr(buffer,'<');
      tmp!=NULL && strncasecmp(tmp, meta_title, 23)!=0;
      tmp=strchr(tmp,'<'))
  {
    /* TODO assert tmp[0]=='<'; */
    /*@ assert valid_read_string(tmp); */
    tmp++;
    /*@ assert valid_read_string(tmp); */
  }
  if(tmp!=NULL)
  {
    const char *title=tmp+23;
    /*@ assert valid_read_string(title); */
    tmp=strchr(title,'<');
    if(tmp!=NULL)
      *tmp='\0';
    file_rename(file_recovery, (const unsigned char*)title, strlen(title), 0, NULL, 1);
  }
#endif
  /*@ assert valid_read_string((char*)file_recovery->filename); */
}

/*@
  @ requires file_recovery->file_rename==&file_rename_html;
  @ requires valid_file_rename_param(file_recovery);
  @ ensures  valid_file_rename_result(file_recovery);
  @*/
static void file_rename_html(file_recovery_t *file_recovery)
{
  FILE *file;
  char buffer[4096];
  char *tmp;
  size_t lu;
  /*@ assert valid_read_string((char*)file_recovery->filename); */
  if((file=fopen(file_recovery->filename, "rb"))==NULL)
  {
    /*@ assert valid_read_string((char*)file_recovery->filename); */
    return;
  }
  if((lu=fread(&buffer, 1, sizeof(buffer)-1, file)) <= 0)
  {
    fclose(file);
    /*@ assert valid_read_string((char*)file_recovery->filename); */
    return ;
  }
#if defined(__FRAMAC__)
  Frama_C_make_unknown(buffer, sizeof(buffer)-1);
#endif
  fclose(file);
  buffer[lu]='\0';
#ifndef DISABLED_FOR_FRAMAC
  tmp=strchr(buffer,'<');
  while(tmp!=NULL)
  {
    if(strncasecmp(tmp, "</head", 5)==0)
    {
      /*@ assert valid_read_string((char*)file_recovery->filename); */
      return ;
    }
    if(strncasecmp(tmp, "<title>", 7)==0)
    {
      const char *title=tmp+7;
      tmp=strchr(title,'<');
      if(tmp!=NULL)
	*tmp='\0';
      file_rename(file_recovery, (const unsigned char*)title, strlen(title), 0, NULL, 1);
      /*@ assert valid_read_string((char*)file_recovery->filename); */
      return ;
    }
    tmp++;
    tmp=strchr(tmp,'<');
  }
#endif
  /*@ assert valid_read_string((char*)file_recovery->filename); */
}

/*@
  @ requires file_recovery->file_check == &file_check_emlx;
  @ requires valid_file_check_param(file_recovery);
  @ ensures  valid_file_check_result(file_recovery);
  @ assigns *file_recovery->handle, errno, file_recovery->file_size;
  @ assigns Frama_C_entropy_source;
  @*/
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

/*@
  @ requires file_recovery->file_check == &file_check_ers;
  @ requires valid_file_check_param(file_recovery);
  @ ensures  valid_file_check_result(file_recovery);
  @ assigns *file_recovery->handle, errno, file_recovery->file_size;
  @ assigns Frama_C_entropy_source;
  @*/
static void file_check_ers(file_recovery_t *file_recovery)
{
  file_search_footer(file_recovery, "DatasetHeader End", 17, 0);
  file_allow_nl(file_recovery, NL_BARENL|NL_CRLF|NL_BARECR);
}

/*@
  @ requires file_recovery->file_check == &file_check_gpx;
  @ requires valid_file_check_param(file_recovery);
  @ ensures  valid_file_check_result(file_recovery);
  @ assigns *file_recovery->handle, errno, file_recovery->file_size;
  @ assigns Frama_C_entropy_source;
  @*/
static void file_check_gpx(file_recovery_t *file_recovery)
{
  file_search_footer(file_recovery, "</gpx>", 6, 0);
  file_allow_nl(file_recovery, NL_BARENL|NL_CRLF|NL_BARECR);
}

/*@
  @ requires file_recovery->file_check == &file_check_svg;
  @ requires valid_file_check_param(file_recovery);
  @ ensures  valid_file_check_result(file_recovery);
  @ assigns *file_recovery->handle, errno, file_recovery->file_size;
  @ assigns Frama_C_entropy_source;
  @*/
static void file_check_svg(file_recovery_t *file_recovery)
{
  file_search_footer(file_recovery, "</svg>", 6, 0);
  file_allow_nl(file_recovery, NL_BARENL|NL_CRLF|NL_BARECR);
}

/*@
  @ requires file_recovery->file_check == &file_check_smil;
  @ requires valid_file_check_param(file_recovery);
  @ ensures  valid_file_check_result(file_recovery);
  @ assigns *file_recovery->handle, errno, file_recovery->file_size;
  @ assigns Frama_C_entropy_source;
  @*/
static void file_check_smil(file_recovery_t *file_recovery)
{
  file_search_footer(file_recovery, "</smil>", 7, 0);
  file_allow_nl(file_recovery, NL_BARENL|NL_CRLF|NL_BARECR);
}

/*@
  @ requires file_recovery->file_check == &file_check_vbm;
  @ requires valid_file_check_param(file_recovery);
  @ ensures  valid_file_check_result(file_recovery);
  @ assigns *file_recovery->handle, errno, file_recovery->file_size;
  @ assigns Frama_C_entropy_source;
  @*/
static void file_check_vbm(file_recovery_t *file_recovery)
{
  file_search_footer(file_recovery, "</BackupMeta>", 13, 0);
  file_allow_nl(file_recovery, NL_BARENL|NL_CRLF|NL_BARECR);
}

/*@
  @ requires file_recovery->file_check == &file_check_xml;
  @ requires valid_file_check_param(file_recovery);
  @ ensures  valid_file_check_result(file_recovery);
  @ assigns *file_recovery->handle, errno, file_recovery->file_size;
  @ assigns Frama_C_entropy_source;
  @*/
static void file_check_xml(file_recovery_t *file_recovery)
{
  file_search_footer(file_recovery, ">", 1, 0);
  file_allow_nl(file_recovery, NL_BARENL|NL_CRLF|NL_BARECR);
}

/*@
  @ requires separation: \separated(&file_hint_fasttxt, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ ensures  (\result == 1) ==> (file_recovery_new->calculated_file_size == 0);
  @ ensures  (\result == 1) ==> (file_recovery_new->extension == extension_dc);
  @ ensures  (\result == 1) ==> (file_recovery_new->file_size == 0);
  @ ensures  (\result == 1) ==> (file_recovery_new->min_filesize == 0);
  @ ensures  (\result == 1) ==> (file_recovery_new->data_check == &data_check_txt);
  @ ensures  (\result == 1) ==> (file_recovery_new->file_check == &file_check_size);
  @ ensures  (\result == 1) ==> (file_recovery_new->file_rename == \null);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_dc(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(buffer_size < 2)
    return 0;
  if(buffer[0]!='0' || buffer[1]!='0')
    return 0;
  /*
     TSCe Survey Controller DC v10.0
     */
  reset_file_recovery(file_recovery_new);
  file_recovery_new->data_check=&data_check_txt;
  file_recovery_new->file_check=&file_check_size;
  file_recovery_new->extension=extension_dc;
  /*@ assert valid_read_string(file_recovery_new->extension); */
  /*@ assert \separated(file_recovery_new, file_recovery_new->extension); */
  /*@ assert valid_file_recovery(file_recovery_new); */
  return 1;
}

/*@
  @ requires separation: \separated(&file_hint_fasttxt, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ ensures \result == 1;
  @ ensures  file_recovery_new->calculated_file_size == 0;
  @ ensures  file_recovery_new->extension == extension_ers;
  @ ensures  file_recovery_new->file_size == 0;
  @ ensures  file_recovery_new->min_filesize == 0;
  @ ensures  file_recovery_new->data_check == &data_check_txt;
  @ ensures  file_recovery_new->file_check == &file_check_ers;
  @ ensures  file_recovery_new->file_rename == \null;
  @ assigns  *file_recovery_new;
  @*/
static int header_check_ers(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /* ER Mapper Rasters (ERS) */
  reset_file_recovery(file_recovery_new);
  file_recovery_new->data_check=&data_check_txt;
  file_recovery_new->file_check=&file_check_ers;
  file_recovery_new->extension=extension_ers;
  /*@ assert valid_read_string(file_recovery_new->extension); */
  /*@ assert \separated(file_recovery_new, file_recovery_new->extension); */
  /*@ assert valid_file_recovery(file_recovery_new); */
  return 1;
}

/*@
  @ requires separation: \separated(&file_hint_fasttxt, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ ensures (\result == 1) ==> (file_recovery_new->calculated_file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->min_filesize > 0);
  @ ensures (\result == 1) ==> (file_recovery_new->file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->data_check == &data_check_txt);
  @ ensures (\result == 1) ==> (file_recovery_new->file_check == &file_check_size);
  @ ensures (\result == 1) ==> (file_recovery_new->extension != \null);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_fasttxt(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const txt_header_t *header=&fasttxt_headers[0];
  /*@ ghost int i = 0; */
  /*@
    @ loop unroll 200;
    @ loop invariant header == &fasttxt_headers[i];
    @ loop invariant 0 <= i <= sizeof(fasttxt_headers)/sizeof(txt_header_t);
    @ loop assigns header;
    @ loop assigns i;
    @ loop variant sizeof(fasttxt_headers)/sizeof(txt_header_t) - i;
    @ */
  while(header->len > 0)
  {
    if(memcmp(buffer, header->string, header->len)==0)
    {
      if(buffer[header->len]=='\0')
	return 0;
      reset_file_recovery(file_recovery_new);
      file_recovery_new->data_check=&data_check_txt;
      file_recovery_new->file_check=&file_check_size;
      /*@ assert valid_read_string(header->extension); */
      file_recovery_new->extension=header->extension;
      /*@ assert file_recovery_new->extension != \null; */
      file_recovery_new->min_filesize=header->len+1;
      /*@ assert file_recovery_new->file_stat == \null; */
      /*@ assert file_recovery_new->handle == \null; */
      /*@ assert file_recovery_new->min_filesize > 0; */
      /*@ assert file_recovery_new->calculated_file_size == 0; */
      /*@ assert file_recovery_new->file_size == 0; */
      /*@ assert file_recovery_new->data_check == &data_check_txt; */
      /*@ assert file_recovery_new->file_check == &file_check_size; */
      /*@ assert valid_read_string(file_recovery_new->extension); */
      /*@ assert \separated(file_recovery_new, file_recovery_new->extension); */
      /*@ assert valid_file_recovery(file_recovery_new); */
      return 1;
    }
    header++;
    /*@ ghost i++; */
  }
  return 0;
}

/*@
  @ requires separation: \separated(&file_hint_fasttxt, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ ensures (\result == 1) ==> (file_recovery_new->extension == extension_html);
  @ ensures (\result == 1) ==> (file_recovery_new->calculated_file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->min_filesize == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->data_check == &data_check_html);
  @ ensures (\result == 1) ==> (file_recovery_new->file_check == &file_check_size);
  @ ensures (\result == 1) ==> (file_recovery_new->file_rename == &file_rename_html);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_html(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(buffer_size < 15)
    return 0;
  if(file_recovery->file_stat!=NULL &&
      file_recovery->file_stat->file_hint==&file_hint_fasttxt &&
      file_recovery->extension==extension_mbox)
    return 0;
  if(buffer[14]==0)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->data_check=&data_check_html;
  file_recovery_new->file_check=&file_check_size;
  /* Hypertext Markup Language (HTML) */
  file_recovery_new->extension=extension_html;
  file_recovery_new->file_rename=&file_rename_html;
  /*@ assert valid_read_string(file_recovery_new->extension); */
  /*@ assert \separated(file_recovery_new, file_recovery_new->extension); */
  /*@ assert valid_file_recovery(file_recovery_new); */
  return 1;
}

/*@
  @ requires separation: \separated(&file_hint_fasttxt, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ ensures (\result == 1) ==> (file_recovery_new->extension == extension_ics);
  @ ensures (\result == 1) ==> (file_recovery_new->calculated_file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->min_filesize == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->data_check == &data_check_txt);
  @ ensures (\result == 1) ==> (file_recovery_new->file_check == &file_check_size);
  @*/
static int header_check_ics(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const char *date_asc;
  char *buffer2;
  if(buffer_size < 22)
    return 0;
  if(buffer[15]=='\0')
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->data_check=&data_check_txt;
  file_recovery_new->file_check=&file_check_size;
  /* vcalendar  */
  file_recovery_new->extension=extension_ics;
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
  if(date_asc!=NULL && date_asc+1+14 < buffer2+buffer_size)
  {
    file_recovery_new->time=get_time_from_YYYYMMDD_HHMMSS(date_asc+1);
  }
  free(buffer2);
  /*@ assert valid_read_string(file_recovery_new->extension); */
  /*@ assert \separated(file_recovery_new, file_recovery_new->extension); */
  /*@ assert valid_file_recovery(file_recovery_new); */
  return 1;
}

#ifdef UTF16
/*@
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @*/
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
      file_recovery_new->extension=extension_utf16;
      /*@ assert valid_read_string(file_recovery_new->extension); */
      /*@ assert \separated(file_recovery_new, file_recovery_new->extension); */
      return 1;
    }
  }
  reset_file_recovery(file_recovery_new);
  file_recovery_new->calculated_file_size=i;
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_size;
  file_recovery_new->extension=extension_utf16;
  /*@ assert valid_read_string(file_recovery_new->extension); */
  /*@ assert \separated(file_recovery_new, file_recovery_new->extension); */
  return 1;
}
#endif

/*@
  @ requires separation: \separated(&file_hint_fasttxt, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ ensures (\result == 1) ==> (file_recovery_new->extension == extension_mbox);
  @ ensures (\result == 1) ==> (file_recovery_new->calculated_file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->min_filesize == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->data_check == &data_check_txt);
  @ ensures (\result == 1) ==> (file_recovery_new->file_check == &file_check_size);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_mbox(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  unsigned int i;
  if(buffer_size < 200)
    return 0;
  if(file_recovery->file_stat!=NULL &&
      file_recovery->file_stat->file_hint==&file_hint_fasttxt &&
      file_recovery->extension==extension_mbox)
    return 0;
  /*@
    @ loop assigns i;
    @ loop variant 64 - i;
    @*/
  for(i=0; i<64; i++)
    if(buffer[i]==0)
      return 0;
  if( memcmp(buffer, "From ", 5)==0 &&
      memcmp(buffer, "From MAILER-DAEMON ", 19)!=0)
  {
    /* From someone@somewhere */
    /*@
      @ loop assigns i;
      @ loop variant 200 - i;
      @*/
    for(i=5; i<200 && buffer[i]!=' ' && buffer[i]!='@'; i++);
    if(buffer[i]!='@')
      return 0;
  }
  reset_file_recovery(file_recovery_new);
  file_recovery_new->data_check=&data_check_txt;
  file_recovery_new->file_check=&file_check_size;
  /* Incredimail has .imm extension but this extension isn't frequent */
  file_recovery_new->extension=extension_mbox;
  /*@ assert valid_read_string(file_recovery_new->extension); */
  /*@ assert \separated(file_recovery_new, file_recovery_new->extension); */
  /*@ assert valid_file_recovery(file_recovery_new); */
  return 1;
}

/*@
  @ requires separation: \separated(&file_hint_fasttxt, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ ensures (\result == 1) ==> (file_recovery_new->extension == extension_mol2);
  @ ensures (\result == 1) ==> (file_recovery_new->calculated_file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->min_filesize == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->data_check == &data_check_txt);
  @ ensures (\result == 1) ==> (file_recovery_new->file_check == &file_check_size);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_mol2(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  reset_file_recovery(file_recovery_new);
  file_recovery_new->data_check=&data_check_txt;
  file_recovery_new->file_check=&file_check_size;
  file_recovery_new->extension=extension_mol2;
  /*@ assert valid_file_recovery(file_recovery_new); */
  return 1;
}

/*@
  @ requires separation: \separated(&file_hint_fasttxt, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ ensures (\result == 1) ==> (file_recovery_new->extension == extension_java || file_recovery_new->extension == extension_pm);
  @ ensures (\result == 1) ==> (file_recovery_new->calculated_file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->min_filesize == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->data_check == &data_check_txt);
  @ ensures (\result == 1) ==> (file_recovery_new->file_check == &file_check_size);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_perlm(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  unsigned int i;
  const unsigned int buffer_size_test=(buffer_size < 2048 ? buffer_size : 2048);
  if(buffer_size < 128)
    return 0;
  /*@
    @ loop assigns i;
    @ loop variant 128 - i;
    */
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
    file_recovery_new->extension=extension_java;
  }
  else
  {
    /* perl module */
    file_recovery_new->extension=extension_pm;
  }
  /*@ assert valid_read_string(file_recovery_new->extension); */
  /*@ assert \separated(file_recovery_new, file_recovery_new->extension); */
  /*@ assert valid_file_recovery(file_recovery_new); */
  return 1;
}

/*@
  @ requires separation: \separated(&file_hint_fasttxt, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ ensures (\result == 1) ==> (file_recovery_new->extension == extension_rtf);
  @ ensures (\result == 1) ==> (file_recovery_new->calculated_file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->min_filesize == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->data_check == &data_check_txt);
  @ ensures (\result == 1) ==> (file_recovery_new->file_check == &file_check_size);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_rtf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  unsigned int i;
  if(buffer_size < 16)
    return 0;
  /*@
    @ loop assigns i;
    @ loop variant 16 - i;
    @*/
  for(i=0; i<16; i++)
    if(buffer[i]=='\0')
      return 0;
  /* Avoid a false positive with .snt */
  if(file_recovery->file_stat!=NULL
#if !defined(MAIN_txt) && !defined(SINGLE_FORMAT)
      && file_recovery->file_stat->file_hint==&file_hint_doc
#endif
    )
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->data_check=&data_check_txt;
  file_recovery_new->file_check=&file_check_size;
  /* Rich Text Format */
  file_recovery_new->extension=extension_rtf;
  /*@ assert valid_read_string(file_recovery_new->extension); */
  /*@ assert \separated(file_recovery_new, file_recovery_new->extension); */
  /*@ assert valid_file_recovery(file_recovery_new); */
  return 1;
}

/*@
  @ requires separation: \separated(&file_hint_fasttxt, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ ensures (\result == 1) ==> (file_recovery_new->extension == extension_smil);
  @ ensures (\result == 1) ==> (file_recovery_new->calculated_file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->min_filesize == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->data_check == &data_check_txt);
  @ ensures (\result == 1) ==> (file_recovery_new->file_check == &file_check_smil);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_smil(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /* Synchronized Multimedia Integration Language
   * http://en.wikipedia.org/wiki/Synchronized_Multimedia_Integration_Language */
  reset_file_recovery(file_recovery_new);
  file_recovery_new->data_check=&data_check_txt;
  file_recovery_new->file_check=&file_check_smil;
  file_recovery_new->extension=extension_smil;
  /*@ assert valid_read_string(file_recovery_new->extension); */
  /*@ assert \separated(file_recovery_new, file_recovery_new->extension); */
  /*@ assert valid_file_recovery(file_recovery_new); */
  return 1;
}

/*@
  @ requires separation: \separated(&file_hint_snz, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ ensures (\result == 1) ==> (file_recovery_new->extension == file_hint_snz.extension);
  @ ensures (\result == 1) ==> (file_recovery_new->calculated_file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->data_check == &data_check_txt);
  @ ensures (\result == 1) ==> (file_recovery_new->file_check == &file_check_size);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_snz(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const char *sbuffer=(const char *)buffer;
  const unsigned int buffer_size_test=(buffer_size < 512? buffer_size : 512);
  const char *pos=(const char *)td_memmem(buffer, buffer_size_test, ".snz", 4);
  if(pos==NULL)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->data_check=&data_check_txt;
  file_recovery_new->file_check=&file_check_size;
  file_recovery_new->extension=file_hint_snz.extension;
  file_recovery_new->min_filesize=pos-sbuffer;
  /*@ assert valid_read_string(file_recovery_new->extension); */
  /*@ assert \separated(file_recovery_new, file_recovery_new->extension); */
  /*@ assert valid_file_recovery(file_recovery_new); */
  return 1;
}

/*@
  @ requires separation: \separated(&file_hint_fasttxt, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ ensures (\result == 1) ==> (file_recovery_new->extension == extension_stl);
  @ ensures (\result == 1) ==> (file_recovery_new->calculated_file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->min_filesize == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->data_check == &data_check_txt);
  @ ensures (\result == 1) ==> (file_recovery_new->file_check == &file_check_size);
  @ assigns  *file_recovery_new;
  @*/
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
  file_recovery_new->extension=extension_stl;
  /*@ assert valid_read_string(file_recovery_new->extension); */
  /*@ assert \separated(file_recovery_new, file_recovery_new->extension); */
  /*@ assert valid_file_recovery(file_recovery_new); */
  return 1;
}

/*@
  @ requires separation: \separated(&file_hint_fasttxt, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ ensures \result == 0 || \result == 1;
  @ ensures (\result == 1) ==> (file_recovery_new->extension == extension_svg);
  @ ensures (\result == 1) ==> (file_recovery_new->calculated_file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->min_filesize == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->data_check == \null);
  @ ensures (\result == 1) ==> (file_recovery_new->file_check == &file_check_svg);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_svg(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /* Scalable Vector Graphics */
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=extension_svg;
  file_recovery_new->file_check=&file_check_svg;
  /*@ assert valid_read_string(file_recovery_new->extension); */
  /*@ assert \separated(file_recovery_new, file_recovery_new->extension); */
  /*@ assert valid_file_recovery(file_recovery_new); */
  return 1;
}

/*@
  @ requires separation: \separated(&file_hint_fasttxt, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ ensures (\result == 1) ==> (file_recovery_new->extension == extension_mbox);
  @ ensures (\result == 1) ==> (file_recovery_new->calculated_file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->min_filesize == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->data_check == &data_check_txt);
  @ ensures (\result == 1) ==> (file_recovery_new->file_check == &file_check_size);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_thunderbird(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  unsigned int i;
  if(buffer_size < 64)
    return 0;
  if(file_recovery->file_stat!=NULL &&
      file_recovery->file_stat->file_hint==&file_hint_fasttxt &&
      file_recovery->extension == extension_mbox)
    return 0;
  /*@
    @ loop assigns i;
    @ loop variant 64 - i;
    @*/
  for(i=0; i<64; i++)
    if(buffer[i]==0)
      return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->data_check=&data_check_txt;
  file_recovery_new->file_check=&file_check_size;
  file_recovery_new->extension=extension_mbox;
  /*@ assert valid_read_string(file_recovery_new->extension); */
  /*@ assert \separated(file_recovery_new, file_recovery_new->extension); */
  /*@ assert valid_file_recovery(file_recovery_new); */
  return 1;
}

/*@
  @ requires separation: \separated(&file_hint_fasttxt, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ ensures (\result == 1) ==> (file_recovery_new->extension == extension_ttd);
  @ ensures (\result == 1) ==> (file_recovery_new->calculated_file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->min_filesize == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->data_check == &data_check_ttd);
  @ ensures (\result == 1) ==> (file_recovery_new->file_check == &file_check_size_max);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_ttd(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(buffer[56]<'0' || buffer[56]>'9')
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->data_check=&data_check_ttd;
  file_recovery_new->file_check=&file_check_size_max;
  file_recovery_new->extension=extension_ttd;
  /*@ assert valid_read_string(file_recovery_new->extension); */
  /*@ assert \separated(file_recovery_new, file_recovery_new->extension); */
  /*@ assert valid_file_recovery(file_recovery_new); */
  return 1;
}

/*@
  @ requires \valid_read(haystack + (0 .. ll-1));
  @ assigns \nothing;
  @ ensures \result == \null || valid_read_string(\result);
  @*/
static const char*she_bang_to_ext(const unsigned char *haystack, const unsigned int ll)
{
  if(td_memmem(haystack, ll, "groovy", 6) != NULL)
  {
    /* Groovy script */
    return extension_groovy;
  }
  if(td_memmem(haystack, ll, "perl", 4) != NULL)
  {
    /* Perl script */
    return extension_pl;
  }
  if(td_memmem(haystack, ll, "php", 3) != NULL)
  {
    /* PHP script */
    return extension_php;
  }
  if(td_memmem(haystack, ll, "python", 6) != NULL)
  {
    /* Python script */
    return extension_py;
  }
  if(td_memmem(haystack, ll, "ruby", 4) != NULL)
  {
    /* Ruby script */
    return extension_rb;
  }
  return NULL;
}

/*@
  @ requires separation: \separated(&file_hint_fasttxt, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ ensures (\result == 1) ==> (file_recovery_new->extension != \null);
  @ ensures (\result == 1) ==> (file_recovery_new->file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->min_filesize == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->data_check == \null || file_recovery_new->data_check == &data_check_html || file_recovery_new->data_check == &data_check_txt);
  @ ensures (\result == 1) ==> (file_recovery_new->file_check == &file_check_emlx || file_recovery_new->file_check == &file_check_size);
  @ ensures (\result == 1) ==> (file_recovery_new->file_rename == \null || file_recovery_new->file_rename == &file_rename_html);
  @*/
static int header_check_txt(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  static char *buffer_lower=NULL;
  static unsigned int buffer_lower_size=0;
  unsigned int l;
  const unsigned int buffer_size_test=(buffer_size < 2048 ? buffer_size : 2048);
  if(buffer_size < 512)
    return 0;
  {
    unsigned int i;
    uint64_t tmp=0;
    /*@
      @ loop unroll 10;
      @ loop invariant 0 <= i <= 10;
      @ loop assigns i, tmp;
      @ loop variant 10-i;
      @*/
    for(i=0;i<10 && isdigit(buffer[i]);i++)
    {
      /*@ assert '0' <= buffer[i] <= '9'; */
      unsigned int v=buffer[i]-'0';
      /*@ assert 0 <= v <= 9; */
      tmp=tmp*10+v;
    }
    if(buffer[i]==0x0a &&
      (memcmp(buffer+i+1, "Return-Path: ", 13)==0 ||
       memcmp(buffer+i+1, "Received: from", 14)==0) &&
        !(file_recovery->file_stat!=NULL &&
          file_recovery->file_stat->file_hint==&file_hint_fasttxt &&
          file_recovery->extension==extension_mbox))
    {
      reset_file_recovery(file_recovery_new);
      file_recovery_new->calculated_file_size=tmp+i+1;
      file_recovery_new->data_check=NULL;
      file_recovery_new->file_check=&file_check_emlx;
      /* Mac OSX mail */
      file_recovery_new->extension=extension_emlx;
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
    /* Dos/Windows batch */
    file_recovery_new->extension=extension_bat;
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
    file_recovery_new->extension=extension_asp;
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
    file_recovery_new->extension=extension_vb;
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
    file_recovery_new->extension=extension_vcf;
    return 1;
  }
  if(buffer[0]=='#' && buffer[1]=='!')
  {
    unsigned int ll=512-2;
    const unsigned char *haystack=(const unsigned char *)buffer+2;
    const char*ext;
    const unsigned char *res;
    res=(const unsigned char *)memchr(haystack,'\n',ll);
    if(res!=NULL)
      ll=res-haystack;
    ext=she_bang_to_ext(haystack, ll);
    if(ext)
    {
      reset_file_recovery(file_recovery_new);
      file_recovery_new->data_check=&data_check_txt;
      file_recovery_new->file_check=&file_check_size;
      file_recovery_new->extension=ext;
      return 1;
    }
  }
  if(safe_header_only!=0)
  {
    return 0;
  }
  if(file_recovery->file_stat!=NULL)
  {
    if(file_recovery->file_stat->file_hint == &file_hint_fasttxt ||
	file_recovery->file_stat->file_hint == &file_hint_txt)
    {
      if(strstr(file_recovery->filename,".html")==NULL)
	return 0;
    }
    /* DFRWS 2006 Forensics Challenge: recover recup_dir.1/f0034288.doc
     */
#if 0
    if(file_recovery->file_stat->file_hint == &file_hint_doc)
    {
      if(strstr(file_recovery->filename,".doc")==NULL)
	return 0;
    }
#endif
    /* Useful for DFRWS 2006 Forensics Challenge */
#if 0
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
#endif
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
  if(has_newline(buffer_lower, l)==0)
    return 0;
  if(strncasecmp((const char *)buffer, "rem ", 4)==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->data_check=&data_check_txt;
    file_recovery_new->file_check=&file_check_size;
    /* Dos/Windows batch */
    file_recovery_new->extension=extension_bat;
    return 1;
  }
  if(strncasecmp((const char *)buffer, "dn: ", 4)==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->data_check=&data_check_txt;
    file_recovery_new->file_check=&file_check_size;
    file_recovery_new->extension=extension_ldif;
    return 1;
  }
  {
    const char *ext=NULL;
    /* ind_random=~0: random
     * ind_random=~1: constant	*/
    double ind_random;
    const char *str;
    ind_random=is_random((const unsigned char *)buffer_lower, l);
    /* Windows Autorun */
    if(strstr(buffer_lower, "[autorun]")!=NULL)
    {
      ext=extension_inf;
      log_info("ext=%s\n", ext);
    }
    /* Detect .ini */
    else if(buffer[0]=='[' && l>50 && is_ini((const char *)buffer_lower))
      ext=extension_ini;
    /* php (Hypertext Preprocessor) script */
    else if(strstr(buffer_lower, "<?php")!=NULL)
      ext=extension_php;
    /* Comma separated values */
    else if(is_csv(buffer_lower, l)!=0)
      ext=extension_csv;
    /* Detect LaTeX, C, PHP, JSP, ASP, HTML, C header */
    else if(strstr(buffer_lower, "\\begin{")!=NULL)
      ext=extension_tex;
    else if(strstr(buffer_lower, "#include")!=NULL)
      ext=extension_c;
    else if(l>20 && strstr(buffer_lower, "<%@")!=NULL)
      ext=extension_jsp;
    else if(l>20 && strstr(buffer_lower, "<%=")!=NULL)
      ext=extension_jsp;
    else if(l>20 && strstr(buffer_lower, "<% ")!=NULL)
      ext=extension_asp;
    else if(strstr(buffer_lower, "<html")!=NULL)
      ext=extension_html;
    else if(strstr(buffer_lower, "private static")!=NULL ||
	strstr(buffer_lower, "public interface")!=NULL)
    {
      ext=extension_java;
    }
    else if(strstr(buffer_lower, "\nimport (")!=NULL)
    {
      ext=extension_go;
    }
    else if((str=strstr(buffer_lower, "\nimport "))!=NULL)
    {
      /*@ assert valid_read_string(str); */
#ifndef DISABLED_FOR_FRAMAC
      str+=8;
#endif
      /*@ assert valid_read_string(str); */
      /*@
        @ loop invariant valid_read_string(str);
	@ loop assigns str;
	@ loop variant strlen(str);
	@*/
      while(*str!='\0' && *str!='\n' && *str!=';')
	str++;
      if(*str==';')
	ext=extension_java;
      else
	ext=extension_py;
    }
    else if(strstr(buffer_lower, "class ")!=NULL &&
	(l>=100 || file_recovery->file_stat==NULL))
    {
      ext=extension_java;
    }
    /* Fortran */
    else if(ind_random<0.9 && is_fortran(buffer_lower)!=0)
      ext=extension_f;
    /* LilyPond http://lilypond.org*/
    else if(strstr(buffer_lower, "\\score {")!=NULL)
      ext=extension_ly;
    /* C header file */
    else if(strstr(buffer_lower, "/*")!=NULL && l>50)
      ext=extension_h;
    else if(l<100 || ind_random<0.03 || ind_random>0.90)
      ext=NULL;
    /* JavaScript Object Notation  */
    else if(memcmp(buffer_lower, "{\"", 2)==0)
      ext=extension_json;
    else if(strstr(buffer_lower,"<br>")!=NULL || strstr(buffer_lower,"<p>")!=NULL)
      ext=extension_html;
    else
      ext=file_hint_txt.extension;
    if(ext==NULL)
      return 0;
    if(file_recovery->file_stat!=NULL)
    {
      if(file_recovery->file_stat->file_hint == &file_hint_fasttxt ||
	  file_recovery->file_stat->file_hint == &file_hint_txt)
      {
	/* file_recovery->filename is a .html */
	buffer_lower[511]='\0';
	if(strstr(buffer_lower, "<html")==NULL)
	  return 0;
	/* Special case: two consecutive HTML files */
      }
      else
#if !defined(MAIN_txt) && !defined(SINGLE_FORMAT)
	if(file_recovery->file_stat->file_hint == &file_hint_doc)
#endif
      {
	unsigned int i;
	unsigned int txt_nl=0;
	/* file_recovery->filename is .doc */
	if(ind_random>0.20)
	  return 0;
	/* Unix: \n (0xA)
	 * Dos: \r\n (0xD 0xA)
	 * Doc: \r (0xD) */
	/*@
	  @ loop assigns i;
	  @ loop variant l-i;
	  @*/
	for(i=0; i<l-1; i++)
	{
	  if(buffer_lower[i]=='\r' && buffer_lower[i+1]!='\n')
	    return 0;
	}
	/*@
	  @ loop assigns i;
	  @ loop assigns txt_nl;
	  @ loop variant 512-i;
	  @*/
	for(i=0; i<l && i<512; i++)
	  if(buffer_lower[i]=='\n')
	    txt_nl++;
	if(txt_nl<=1)
	  return 0;
      }
    }
    reset_file_recovery(file_recovery_new);
    if(ext==extension_html)
    {
      file_recovery_new->file_rename=&file_rename_html;
      file_recovery_new->data_check=&data_check_html;
    }
    else
      file_recovery_new->data_check=&data_check_txt;
    file_recovery_new->file_check=&file_check_size;
    file_recovery_new->extension=ext;
    return 1;
  }
}

/*@
  @ requires separation: \separated(&file_hint_fasttxt, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ ensures (\result == 1) ==> (file_recovery_new->extension == extension_vbm);
  @ ensures (\result == 1) ==> (file_recovery_new->calculated_file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->min_filesize == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->data_check == &data_check_txt);
  @ ensures (\result == 1) ==> (file_recovery_new->file_check == &file_check_vbm);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_vbm(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  reset_file_recovery(file_recovery_new);
  file_recovery_new->data_check=&data_check_txt;
  file_recovery_new->extension=extension_vbm;
  file_recovery_new->file_check=&file_check_vbm;
  /*@ assert valid_read_string(file_recovery_new->extension); */
  /*@ assert \separated(file_recovery_new, file_recovery_new->extension); */
  /*@ assert valid_file_recovery(file_recovery_new); */
  return 1;
}

/*@
  @ requires separation: \separated(buf+(..), file_recovery_new);
  @ requires \valid_read(buf + (0 .. buffer_size));
  @ requires buf[buffer_size] == '\x00';
  @ requires valid_read_string(buf);
  @ requires file_recovery_new->data_check == &data_check_txt;
  @ requires file_recovery_new->file_check == &file_check_xml;
  @ requires file_recovery_new->file_rename == \null;
  @ requires valid_header_check_result((int)1, file_recovery_new);
  @ assigns file_recovery_new->extension;
  @ assigns file_recovery_new->data_check;
  @ assigns file_recovery_new->file_check;
  @ assigns file_recovery_new->file_rename;
  @ ensures  file_recovery_new->data_check == \null ||
				file_recovery_new->data_check == data_check_html ||
				file_recovery_new->data_check == data_check_txt;
  @ ensures  file_recovery_new->file_check == \null ||
				file_recovery_new->file_check == &file_check_gpx ||
				file_recovery_new->file_check == &file_check_svg ||
				file_recovery_new->file_check == &file_check_xml;
  @ ensures  file_recovery_new->file_rename == \null ||
				file_recovery_new->file_rename == &file_rename_fods ||
				file_recovery_new->file_rename == &file_rename_html;
  @ ensures  valid_header_check_result((int)1, file_recovery_new);
  @*/
static void header_check_xml_aux(const char *buf, const unsigned int buffer_size, file_recovery_t *file_recovery_new)
{
  const char *tmp;
  tmp=strchr(buf,'<');
  if(tmp==NULL)
    return;
  /*@
    @ loop invariant valid_file_recovery(file_recovery_new);
    @ loop invariant valid_read_string(tmp);
    @ loop assigns tmp;
    @ loop variant strlen(tmp);
    @*/
  while(*tmp!='\x00')
  {
    if(strncasecmp(tmp, "<Grisbi>", 8)==0)
    {
      /* Grisbi - Personal Finance Manager XML data */
      file_recovery_new->extension=extension_gsb;
      return;
    }
    else if(strncasecmp(tmp, "<collection type=\"GC", 20)==0)
    {
      /* GCstart, personal collections manager, http://www.gcstar.org/ */
      file_recovery_new->extension=extension_gcs;
      return;
    }
    else if(strncasecmp(tmp, "<html", 5)==0)
    {
      file_recovery_new->data_check=&data_check_html;
      file_recovery_new->extension=extension_html;
      file_recovery_new->file_rename=&file_rename_html;
      return;
    }
    else if(strncasecmp(tmp, "<Version>QBFSD", 14)==0)
    {
      /* QuickBook */
      file_recovery_new->extension=extension_fst;
      return;
    }
    else if(strncasecmp(tmp, "<svg", 4)==0)
    {
      /* Scalable Vector Graphics */
      file_recovery_new->extension=extension_svg;
      file_recovery_new->file_check=&file_check_svg;
      return;
    }
    else if(strncasecmp(tmp, "<!DOCTYPE CDXML", 15)==0)
    {
      file_recovery_new->extension=extension_cdxml;
      return;
    }
    else if(strncasecmp(tmp, "<!DOCTYPE plist ", 16)==0)
    {
      /* Mac OS X property list */
      file_recovery_new->extension=extension_plist;
      return;
    }
    else if(strncasecmp(tmp, "<gpx ", 5)==0)
    {
      /* GPS eXchange Format */
      file_recovery_new->extension=extension_gpx;
      file_recovery_new->file_check=&file_check_gpx;
      return;
    }
    else if(strncasecmp(tmp, "<PremiereData Version=", 22)==0)
    {
      /* Adobe Premiere project  */
      file_recovery_new->data_check=NULL;
      file_recovery_new->extension=extension_prproj;
      return;
    }
    else if(strncasecmp(tmp, "<SCRIBUS", 8)==0)
    {
      /* Scribus XML file */
      file_recovery_new->extension=extension_sla;
      return;
    }
    else if(strncasecmp(tmp, "<FictionBook", 12)==0)
    {
      /* FictionBook, see http://www.fictionbook.org */
      file_recovery_new->extension=extension_fb2;
      return;
    }
    else if(strncasecmp(tmp, "<office:document", 16)==0)
    {
      /* OpenDocument Flat XML Spreadsheet */
      file_recovery_new->extension=extension_fods;
      file_recovery_new->data_check=NULL;
      file_recovery_new->file_rename=&file_rename_fods;
      return;
    }
    tmp++;
#ifndef DISABLED_FOR_FRAMAC
    tmp=strchr(tmp,'<');
    if(tmp==NULL)
      return;
#endif
  }
}

/*@
  @ requires separation: \separated(&file_hint_fasttxt, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ ensures  \result == 1;
  @ ensures  file_recovery_new->calculated_file_size == 0;
  @ ensures  file_recovery_new->file_size == 0;
  @ ensures  file_recovery_new->min_filesize == 0;
  @ ensures  file_recovery_new->data_check == \null ||
				file_recovery_new->data_check == data_check_html ||
				file_recovery_new->data_check == data_check_txt;
  @ ensures  file_recovery_new->file_check == \null ||
				file_recovery_new->file_check == &file_check_gpx ||
				file_recovery_new->file_check == &file_check_svg ||
				file_recovery_new->file_check == &file_check_xml;
  @ ensures  file_recovery_new->file_rename == \null ||
				file_recovery_new->file_rename == &file_rename_fods ||
				file_recovery_new->file_rename == &file_rename_html;
  @*/
static int header_check_xml(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /* buffer may not be null-terminated */
  char *buf=(char *)MALLOC(buffer_size+1);
  memcpy(buf, buffer, buffer_size);
  buf[buffer_size]='\0';
  /*@ assert strlen(buf) <= buffer_size; */
  reset_file_recovery(file_recovery_new);
  file_recovery_new->data_check=&data_check_txt;
  file_recovery_new->file_check=&file_check_xml;
  /* XML Extensible Markup Language */
  file_recovery_new->extension=extension_xml;
  header_check_xml_aux(buf, buffer_size, file_recovery_new);
  free(buf);
  return 1;
}

/*@
  @ requires valid_read_string(buf);
  @ assigns \nothing;
  @ ensures \result == extension_ghx || \result == extension_xml;
  @*/
static const char *get_extension_from_xml_utf8(const char *buf)
{
  const char *tmp;
  tmp=strchr(buf,'<');
  if(tmp==NULL)
    return extension_xml;
  /*@ assert *tmp == '<'; */
  /*@
    @ loop invariant valid_read_string(tmp);
    @ loop assigns tmp;
    @ loop variant strlen(tmp);
    @*/
  while(*tmp)
  {
    if(*tmp == '<' && strncasecmp(tmp, "<Archive name=\"Root\">", 8)==0)
    {
      /* Grasshopper archive */
      return extension_ghx;
    }
    tmp++;
  }
  return extension_xml;
}

/*@
  @ requires separation: \separated(&file_hint_fasttxt, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ ensures  \result == 1;
  @ ensures  file_recovery_new->extension == extension_ghx || file_recovery_new->extension == extension_xml;
  @ ensures  file_recovery_new->calculated_file_size == 0;
  @ ensures  file_recovery_new->file_size == 0;
  @ ensures  file_recovery_new->min_filesize == 0;
  @ ensures  (buffer_size >= 10) ==> (file_recovery_new->data_check == &data_check_xml_utf8);
  @ ensures  (buffer_size < 10) ==> file_recovery_new->data_check == \null;
  @ ensures  file_recovery_new->file_check == &file_check_xml;
  @*/
static int header_check_xml_utf8(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /* buffer may not be null-terminated */
  char *buf=(char *)MALLOC(buffer_size+1);
  memcpy(buf, buffer, buffer_size);
  buf[buffer_size]='\0';
  reset_file_recovery(file_recovery_new);
  if(buffer_size >= 10)
    file_recovery_new->data_check=&data_check_xml_utf8;
  file_recovery_new->extension=get_extension_from_xml_utf8(buf);
  file_recovery_new->file_check=&file_check_xml;
  free(buf);
  /*@ assert valid_read_string(file_recovery_new->extension); */
  /*@ assert \separated(file_recovery_new, file_recovery_new->extension); */
  /*@ assert valid_file_recovery(file_recovery_new); */
  return 1;
}

/*@
  @ requires separation: \separated(&file_hint_fasttxt, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ ensures (\result == 1) ==> (file_recovery_new->extension == extension_xml);
  @ ensures (\result == 1) ==> (file_recovery_new->calculated_file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->min_filesize == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->data_check == \null);
  @ ensures (\result == 1) ==> (file_recovery_new->file_check == \null);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_xml_utf16(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  /* Avoid false positive with .sldprt */
  if(file_recovery->file_stat!=NULL
#if !defined(MAIN_txt) && !defined(SINGLE_FORMAT)
      && file_recovery->file_stat->file_hint==&file_hint_doc
#endif
    )
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=extension_xml;
  /*@ assert valid_read_string(file_recovery_new->extension); */
  /*@ assert \separated(file_recovery_new, file_recovery_new->extension); */
  /*@ assert valid_file_recovery(file_recovery_new); */
  return 1;
}

/*@
  @ requires separation: \separated(&file_hint_fasttxt, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ ensures (\result == 1) ==> (file_recovery_new->extension == extension_xmp);
  @ ensures (\result == 1) ==> (file_recovery_new->calculated_file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->min_filesize == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->data_check == &data_check_txt);
  @ ensures (\result == 1) ==> (file_recovery_new->file_check == &file_check_size);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_xmp(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(buffer[35]=='\0')
    return 0;
  if(file_recovery->file_stat!=NULL
#if !defined(MAIN_txt) && !defined(SINGLE_FORMAT)
      && (file_recovery->file_stat->file_hint==&file_hint_jpg ||
	file_recovery->file_stat->file_hint==&file_hint_pdf ||
	file_recovery->file_stat->file_hint==&file_hint_tiff)
#endif
    )
    return 0;
  /* Adobe's Extensible Metadata Platform */
  reset_file_recovery(file_recovery_new);
  file_recovery_new->data_check=&data_check_txt;
  file_recovery_new->file_check=&file_check_size;
  file_recovery_new->extension=extension_xmp;
  /*@ assert valid_read_string(file_recovery_new->extension); */
  /*@ assert \separated(file_recovery_new, file_recovery_new->extension); */
  /*@ assert valid_file_recovery(file_recovery_new); */
  return 1;
}

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_fasttxt(file_stat_t *file_stat)
{
  static const unsigned char header_xml_utf8[17]	= {0xef, 0xbb, 0xbf, '<', '?', 'x', 'm', 'l', ' ', 'v', 'e', 'r', 's', 'i', 'o', 'n', '='};
  static const unsigned char header_xml_utf16[30]	= {0xff, 0xfe, '<', 0, '?', 0, 'x', 0, 'm', 0, 'l', 0, ' ', 0, 'v', 0, 'e', 0, 'r', 0, 's', 0, 'i', 0, 'o', 0, 'n', 0, '=', 0};
  const txt_header_t *header=&fasttxt_headers[0];
  /*@ ghost int i = 0; */
  /*@
    @ loop unroll 200;
    @ loop invariant header == &fasttxt_headers[i];
    @ loop invariant 0 <= i <= sizeof(fasttxt_headers)/sizeof(txt_header_t);
    @ loop variant sizeof(fasttxt_headers)/sizeof(txt_header_t) - i;
  @ */
  while(header->len > 0)
  {
    assert(strlen(header->string) == header->len);
    register_header_check(0, header->string, header->len, &header_check_fasttxt, file_stat);
    header++;
    /*@ ghost i++; */
  }
  register_header_check(4, "SC V10",		6,  &header_check_dc, file_stat);
  register_header_check(0, "DatasetHeader Begin", 19, &header_check_ers, file_stat);
  /* DFRWS 2006 Forensics Challenge */
  register_header_check(0, "\n<!DOCTYPE html",	15, &header_check_html, file_stat);
//
  register_header_check(0, "<!DOCTYPE html",	14, &header_check_html, file_stat);
  register_header_check(0, "<!DOCTYPE HTML",	14, &header_check_html, file_stat);
//  register_header_check(0, "<html",		 5, &header_check_html, file_stat);
  register_header_check(0, "BEGIN:VCALENDAR",	15, &header_check_ics, file_stat);
  register_header_check(0, "From - ",		 7, &header_check_thunderbird, file_stat);
  register_header_check(0, "From ",		 5, &header_check_mbox, file_stat);
  register_header_check(0, "Message-ID: ",	12, &header_check_mbox, file_stat);
  register_header_check(0, "MIME-Version:",	13, &header_check_mbox, file_stat);
  register_header_check(0, "Received: from ",	15, &header_check_mbox, file_stat);
  register_header_check(0, "Reply-To: ",	10, &header_check_mbox, file_stat);
  register_header_check(0, "Return-path: ",	13, &header_check_mbox, file_stat);
  register_header_check(0, "Return-Path: ",	13, &header_check_mbox, file_stat);
  register_header_check(0, "package ",		 8, &header_check_perlm, file_stat);
  register_header_check(0, "package\t",		 8, &header_check_perlm, file_stat);
  register_header_check(0, "{\\rtf",		 5, &header_check_rtf, file_stat);
  register_header_check(0, "<smil>",		 6, &header_check_smil, file_stat);
  register_header_check(0, "solid ",		 6, &header_check_stl, file_stat);
  register_header_check(0, "<?xml version=",	14, &header_check_xml, file_stat);
  register_header_check(0, header_xml_utf8, sizeof(header_xml_utf8), &header_check_xml_utf8, file_stat);
  register_header_check(0, header_xml_utf16, sizeof(header_xml_utf16), &header_check_xml_utf16, file_stat);
  /* Veeam Backup */
  register_header_check(0, "<BackupMeta Version=",	20, &header_check_vbm, file_stat);
  /* TinyTag */
  register_header_check(0, "FF 09 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FFFF 00", 55, &header_check_ttd, file_stat);
  register_header_check(0, "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"", 35, &header_check_xmp, file_stat);
  register_header_check(0, "<svg xmlns=\"http://www.w3.org/2000/svg\"", 39, &header_check_svg, file_stat);
  register_header_check(0, "@<TRIPOS>MOLECULE", 17, &header_check_mol2, file_stat);
}

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_snz(file_stat_t *file_stat)
{
  register_header_check(0, "DEFAULT\n",   8, &header_check_snz, file_stat);
  register_header_check(0, "DEFAULT\r\n", 9, &header_check_snz, file_stat);
}

/*@
  @ requires valid_register_header_check(file_stat);
  @*/
static void register_header_check_txt(file_stat_t *file_stat)
{
  unsigned int i;
  /*@
    @ loop assigns i, ascii_char[0 .. 255];
    @ loop variant 256 - i;
    @*/
  for(i=0; i<256; i++)
    ascii_char[i]=i;
  /*@
    @ loop variant 256 - i;
    @*/
  for(i=0; i<256; i++)
  {
    if(filtre(i) || i==0xE2 || i==0xC2 || i==0xC3 || i==0xC5 || i==0xC6 || i==0xCB)
      register_header_check(0, &ascii_char[i], 1, &header_check_txt, file_stat);
  }
#ifdef UTF16
  register_header_check(1, &ascii_char[0], 1, &header_check_le16_txt, file_stat);
#endif
}
#endif

#if defined(MAIN_txt)
#define BLOCKSIZE 65536u
static int main_dc()
{
  const char fn[] = "recup_dir.1/f0000000.dc";
  unsigned char buffer[BLOCKSIZE];
  file_recovery_t file_recovery_new;
  file_recovery_t file_recovery;
  file_stat_t file_stats;

  /*@ assert \valid(buffer + (0 .. (BLOCKSIZE - 1))); */
#if defined(__FRAMAC__)
  Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif

  reset_file_recovery(&file_recovery);
  /*@ assert file_recovery.extension == \null; */
  /*@ assert file_recovery.file_stat == \null; */
  file_recovery.blocksize=BLOCKSIZE;

  /*@ assert valid_read_string((const char *)file_recovery.filename); */
  /*@ assert (file_recovery.file_stat == \null || valid_file_stat(file_recovery.file_stat)); */
  /*@ assert (file_recovery.handle == \null || \valid(file_recovery.handle)); */
  /*@ assert (file_recovery.extension == \null || valid_read_string(file_recovery.extension)); */
  /*@ assert (file_recovery.data_check == \null || \valid_function(file_recovery.data_check)); */
  /*@ assert (file_recovery.file_check == \null || \valid_function(file_recovery.file_check)); */
  /*@ assert (file_recovery.file_rename == \null || \valid_function(file_recovery.file_rename)); */
  /*@ assert \separated(&file_recovery, file_recovery.extension); */
  /*@ assert \initialized(&file_recovery.calculated_file_size); */
  /*@ assert \initialized(&file_recovery.file_check); */
  /*@ assert \initialized(&file_recovery.file_size); */
  /*@ assert \initialized(&file_recovery.min_filesize); */
  /*@ assert \initialized(&file_recovery.time); */

  reset_file_recovery(&file_recovery_new);
  file_recovery_new.blocksize=BLOCKSIZE;

  file_stats.file_hint=&file_hint_fasttxt;
  file_stats.not_recovered=0;
  file_stats.recovered=0;
#if 0
  register_header_check_fasttxt(&file_stats);
#endif
  /*@ assert file_recovery.extension == \null; */
  if(header_check_dc(buffer, BLOCKSIZE, 0u, &file_recovery, &file_recovery_new)!=1)
    return 0;
  /*@ assert valid_read_string((char *)&fn); */
  memcpy(file_recovery_new.filename, fn, sizeof(fn));
  file_recovery_new.file_stat=&file_stats;
  /*@ assert file_recovery_new.extension == extension_dc; */
  /*@ assert valid_read_string(extension_dc); */
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  /*@ assert file_recovery_new.calculated_file_size == 0; */
  /*@ assert file_recovery_new.file_size == 0;	*/
  /*@ assert file_recovery_new.data_check == &data_check_txt; */
  /*@ assert file_recovery_new.file_check == &file_check_size; */
  /*@ assert file_recovery_new.file_rename == \null; */
  /*@ assert file_recovery_new.file_stat->file_hint==&file_hint_fasttxt; */
  {
    unsigned char big_buffer[2*BLOCKSIZE];
    data_check_t res_data_check=DC_CONTINUE;
    memset(big_buffer, 0, BLOCKSIZE);
    memcpy(big_buffer + BLOCKSIZE, buffer, BLOCKSIZE);
    /*@ assert file_recovery_new.data_check == &data_check_txt; */
    /*@ assert file_recovery_new.file_size == 0; */;
    /*@ assert file_recovery_new.file_size <= file_recovery_new.calculated_file_size; */;
    res_data_check=data_check_txt(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    file_recovery_new.file_size+=BLOCKSIZE;
    if(res_data_check == DC_CONTINUE)
    {
      /*@ assert file_recovery_new.data_check == &data_check_txt; */
      memcpy(big_buffer, big_buffer + BLOCKSIZE, BLOCKSIZE);
#if defined(__FRAMAC__)
      Frama_C_make_unknown((char *)big_buffer + BLOCKSIZE, BLOCKSIZE);
#endif
      data_check_txt(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    }
  }
  {
    file_recovery_t file_recovery_new2;
    file_recovery_new2.blocksize=BLOCKSIZE;
    file_recovery_new2.file_stat=NULL;
    file_recovery_new2.file_check=NULL;
    file_recovery_new2.location.start=BLOCKSIZE;
    file_recovery_new.handle=NULL;	/* In theory should be not null */
#if defined(__FRAMAC__)
    Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif
    /*@ assert file_recovery_new.extension == extension_dc; */
    /*@ assert valid_read_string(extension_dc); */
    /*@ assert valid_read_string((char *)file_recovery_new.filename); */

    /*@ assert valid_read_string((const char *)file_recovery_new.filename); */
    /*@ assert (file_recovery_new.file_stat == \null || valid_file_stat(file_recovery_new.file_stat)); */
    /*@ assert (file_recovery_new.handle == \null || \valid(file_recovery_new.handle)); */
    /*@ assert (file_recovery_new.extension == \null || valid_read_string(file_recovery_new.extension)); */
    /*@ assert (file_recovery_new.data_check == \null || \valid_function(file_recovery_new.data_check)); */
    /*@ assert (file_recovery_new.file_check == \null || \valid_function(file_recovery_new.file_check)); */
    /*@ assert (file_recovery_new.file_rename == \null || \valid_function(file_recovery_new.file_rename)); */
    /*@ assert \separated(&file_recovery_new, file_recovery_new.extension); */
    /*@ assert \initialized(&file_recovery_new.calculated_file_size); */
    /*@ assert \initialized(&file_recovery_new.file_check); */
    /*@ assert \initialized(&file_recovery_new.file_size); */
    /*@ assert \initialized(&file_recovery_new.min_filesize); */
    /*@ assert \initialized(&file_recovery_new.time); */


    header_check_dc(buffer, BLOCKSIZE, 0, &file_recovery_new, &file_recovery_new2);
  }
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  file_recovery_new.handle=fopen(fn, "rb");
  /*@ assert file_recovery_new.file_check == &file_check_size; */
  if(file_recovery_new.handle!=NULL)
  {
    file_check_size(&file_recovery_new);
    fclose(file_recovery_new.handle);
  }
  return 0;
}

static int main_ers()
{
  const char fn[] = "recup_dir.1/f0000000.ers";
  unsigned char buffer[BLOCKSIZE];
  file_recovery_t file_recovery_new;
  file_recovery_t file_recovery;
  file_stat_t file_stats;

  /*@ assert \valid(buffer + (0 .. (BLOCKSIZE - 1))); */
#if defined(__FRAMAC__)
  Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif

  reset_file_recovery(&file_recovery);
  /*@ assert file_recovery.extension == \null; */
  /*@ assert file_recovery.file_stat == \null; */
  file_recovery.blocksize=BLOCKSIZE;
  reset_file_recovery(&file_recovery_new);
  file_recovery_new.blocksize=BLOCKSIZE;

  file_stats.file_hint=&file_hint_fasttxt;
  file_stats.not_recovered=0;
  file_stats.recovered=0;
#if 0
  register_header_check_fasttxt(&file_stats);
#endif
  /*@ assert file_recovery.extension == \null; */
  if(header_check_ers(buffer, BLOCKSIZE, 0u, &file_recovery, &file_recovery_new)!=1)
    return 0;
  /*@ assert valid_read_string((char *)&fn); */
  memcpy(file_recovery_new.filename, fn, sizeof(fn));
  file_recovery_new.file_stat=&file_stats;
  /*@ assert file_recovery_new.extension == extension_ers; */
  /*@ assert valid_read_string(extension_ers); */
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  /*@ assert file_recovery_new.calculated_file_size == 0; */
  /*@ assert file_recovery_new.file_size == 0;	*/
  /*@ assert file_recovery_new.data_check == &data_check_txt; */
  /*@ assert file_recovery_new.file_check == &file_check_ers; */
  /*@ assert file_recovery_new.file_rename == \null; */
  /*@ assert file_recovery_new.file_stat->file_hint==&file_hint_fasttxt; */
  {
    unsigned char big_buffer[2*BLOCKSIZE];
    data_check_t res_data_check=DC_CONTINUE;
    memset(big_buffer, 0, BLOCKSIZE);
    memcpy(big_buffer + BLOCKSIZE, buffer, BLOCKSIZE);
    /*@ assert file_recovery_new.data_check == &data_check_txt; */
    /*@ assert file_recovery_new.file_size == 0; */;
    /*@ assert file_recovery_new.file_size <= file_recovery_new.calculated_file_size; */;
    res_data_check=data_check_txt(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    file_recovery_new.file_size+=BLOCKSIZE;
    if(res_data_check == DC_CONTINUE)
    {
      /*@ assert file_recovery_new.data_check == &data_check_txt; */
      memcpy(big_buffer, big_buffer + BLOCKSIZE, BLOCKSIZE);
#if defined(__FRAMAC__)
      Frama_C_make_unknown((char *)big_buffer + BLOCKSIZE, BLOCKSIZE);
#endif
      data_check_txt(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    }
  }
  {
    file_recovery_t file_recovery_new2;
    file_recovery_new2.blocksize=BLOCKSIZE;
    file_recovery_new2.file_stat=NULL;
    file_recovery_new2.file_check=NULL;
    file_recovery_new2.location.start=BLOCKSIZE;
    file_recovery_new.handle=NULL;	/* In theory should be not null */
#if defined(__FRAMAC__)
    Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif
    /*@ assert file_recovery_new.extension == extension_ers; */
    /*@ assert valid_read_string(extension_ers); */
    /*@ assert valid_read_string((char *)file_recovery_new.filename); */
    header_check_ers(buffer, BLOCKSIZE, 0, &file_recovery_new, &file_recovery_new2);
  }
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  file_recovery_new.handle=fopen(fn, "rb");
  /*@ assert file_recovery_new.file_check == &file_check_ers; */
  if(file_recovery_new.handle!=NULL)
  {
    file_check_ers(&file_recovery_new);
    fclose(file_recovery_new.handle);
  }
  return 0;
}

static int main_fasttxt()
{
  const char fn[] = "recup_dir.1/f0000000.txt";
  unsigned char buffer[BLOCKSIZE];
  file_recovery_t file_recovery_new;
  file_recovery_t file_recovery;
  file_stat_t file_stats;

  /*@ assert \valid(buffer + (0 .. (BLOCKSIZE - 1))); */
#if defined(__FRAMAC__)
  Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif

  reset_file_recovery(&file_recovery);
  /*@ assert file_recovery.extension == \null; */
  /*@ assert file_recovery.file_stat == \null; */
  file_recovery.blocksize=BLOCKSIZE;
  reset_file_recovery(&file_recovery_new);
  file_recovery_new.blocksize=BLOCKSIZE;

  file_stats.file_hint=&file_hint_fasttxt;
  file_stats.not_recovered=0;
  file_stats.recovered=0;
#if 0
  register_header_check_fasttxt(&file_stats);
#endif
  /*@ assert file_recovery.extension == \null; */
  if(header_check_fasttxt(buffer, BLOCKSIZE, 0u, &file_recovery, &file_recovery_new)!=1)
    return 0;
  /*@ assert valid_read_string((char *)&fn); */
  /*@ assert file_recovery_new.extension != \null; */
  memcpy(file_recovery_new.filename, fn, sizeof(fn));
  file_recovery_new.file_stat=&file_stats;
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  /*@ assert valid_read_string((char *)file_recovery_new.extension); */
  /*@ assert file_recovery_new.calculated_file_size == 0; */
  /*@ assert file_recovery_new.file_size == 0;	*/
  /*@ assert file_recovery_new.data_check == &data_check_txt; */
  /*@ assert file_recovery_new.file_check == &file_check_size; */
  /*@ assert file_recovery_new.file_rename == \null; */
  /*@ assert file_recovery_new.file_stat->file_hint==&file_hint_fasttxt; */
  {
    unsigned char big_buffer[2*BLOCKSIZE];
    data_check_t res_data_check=DC_CONTINUE;
    memset(big_buffer, 0, BLOCKSIZE);
    memcpy(big_buffer + BLOCKSIZE, buffer, BLOCKSIZE);
    /*@ assert file_recovery_new.data_check == &data_check_txt; */
    /*@ assert file_recovery_new.file_size == 0; */;
    /*@ assert file_recovery_new.file_size <= file_recovery_new.calculated_file_size; */;
    res_data_check=data_check_txt(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    file_recovery_new.file_size+=BLOCKSIZE;
    if(res_data_check == DC_CONTINUE)
    {
      /*@ assert file_recovery_new.data_check == &data_check_txt; */
      memcpy(big_buffer, big_buffer + BLOCKSIZE, BLOCKSIZE);
#if defined(__FRAMAC__)
      Frama_C_make_unknown((char *)big_buffer + BLOCKSIZE, BLOCKSIZE);
#endif
      data_check_txt(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    }
  }
  {
    file_recovery_t file_recovery_new2;
    file_recovery_new2.blocksize=BLOCKSIZE;
    file_recovery_new2.file_stat=NULL;
    file_recovery_new2.file_check=NULL;
    file_recovery_new2.location.start=BLOCKSIZE;
    file_recovery_new.handle=NULL;	/* In theory should be not null */
#if defined(__FRAMAC__)
    Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif
    /*@ assert valid_read_string((char *)file_recovery_new.extension); */
    /*@ assert valid_read_string((char *)file_recovery_new.filename); */
    header_check_fasttxt(buffer, BLOCKSIZE, 0, &file_recovery_new, &file_recovery_new2);
  }
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  file_recovery_new.handle=fopen(fn, "rb");
  /*@ assert file_recovery_new.file_check == &file_check_size; */
  if(file_recovery_new.handle!=NULL)
  {
    file_check_size(&file_recovery_new);
    fclose(file_recovery_new.handle);
  }
  return 0;
}

static int main_html()
{
  const char fn[] = "recup_dir.1/f0000000.html";
  unsigned char buffer[BLOCKSIZE];
  file_recovery_t file_recovery_new;
  file_recovery_t file_recovery;
  file_stat_t file_stats;

  /*@ assert \valid(buffer + (0 .. (BLOCKSIZE - 1))); */
#if defined(__FRAMAC__)
  Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif

  reset_file_recovery(&file_recovery);
  /*@ assert file_recovery.extension == \null; */
  /*@ assert file_recovery.file_stat == \null; */
  file_recovery.blocksize=BLOCKSIZE;
  reset_file_recovery(&file_recovery_new);
  file_recovery_new.blocksize=BLOCKSIZE;

  file_stats.file_hint=&file_hint_fasttxt;
  file_stats.not_recovered=0;
  file_stats.recovered=0;
#if 0
  register_header_check_fasttxt(&file_stats);
#endif
  /*@ assert file_recovery.extension == \null; */
  if(header_check_html(buffer, BLOCKSIZE, 0u, &file_recovery, &file_recovery_new)!=1)
    return 0;
  /*@ assert valid_read_string((char *)&fn); */
  memcpy(file_recovery_new.filename, fn, sizeof(fn));
  file_recovery_new.file_stat=&file_stats;
  /*@ assert file_recovery_new.extension == extension_html; */
  /*@ assert valid_read_string(extension_html); */
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  /*@ assert file_recovery_new.calculated_file_size == 0; */
  /*@ assert file_recovery_new.file_size == 0;	*/
  /*@ assert file_recovery_new.data_check == &data_check_html; */
  /*@ assert file_recovery_new.file_check == &file_check_size; */
  /*@ assert file_recovery_new.file_rename == &file_rename_html; */
  /*@ assert file_recovery_new.file_stat->file_hint==&file_hint_fasttxt; */
  {
    unsigned char big_buffer[2*BLOCKSIZE];
    data_check_t res_data_check=DC_CONTINUE;
    memset(big_buffer, 0, BLOCKSIZE);
    memcpy(big_buffer + BLOCKSIZE, buffer, BLOCKSIZE);
    /*@ assert file_recovery_new.data_check == &data_check_html; */
    /*@ assert file_recovery_new.file_size == 0; */;
    /*@ assert file_recovery_new.file_size <= file_recovery_new.calculated_file_size; */;
    res_data_check=data_check_html(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    file_recovery_new.file_size+=BLOCKSIZE;
    if(res_data_check == DC_CONTINUE)
    {
      /*@ assert file_recovery_new.data_check == &data_check_html; */
      memcpy(big_buffer, big_buffer + BLOCKSIZE, BLOCKSIZE);
#if defined(__FRAMAC__)
      Frama_C_make_unknown((char *)big_buffer + BLOCKSIZE, BLOCKSIZE);
#endif
      data_check_html(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    }
  }
  {
    file_recovery_t file_recovery_new2;
    file_recovery_new2.blocksize=BLOCKSIZE;
    file_recovery_new2.file_stat=NULL;
    file_recovery_new2.file_check=NULL;
    file_recovery_new2.location.start=BLOCKSIZE;
    file_recovery_new.handle=NULL;	/* In theory should be not null */
#if defined(__FRAMAC__)
    Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif
    /*@ assert file_recovery_new.extension == extension_html; */
    /*@ assert valid_read_string(extension_html); */
    /*@ assert valid_read_string((char *)file_recovery_new.filename); */
    header_check_html(buffer, BLOCKSIZE, 0, &file_recovery_new, &file_recovery_new2);
  }
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  file_recovery_new.handle=fopen(fn, "rb");
  /*@ assert file_recovery_new.file_check == &file_check_size; */
  if(file_recovery_new.handle!=NULL)
  {
    file_check_size(&file_recovery_new);
    fclose(file_recovery_new.handle);
  }
  file_rename_html(&file_recovery_new);
  return 0;
}

static int main_ics()
{
  const char fn[] = "recup_dir.1/f0000000.ics";
  unsigned char buffer[BLOCKSIZE];
  file_recovery_t file_recovery_new;
  file_recovery_t file_recovery;
  file_stat_t file_stats;

  /*@ assert \valid(buffer + (0 .. (BLOCKSIZE - 1))); */
#if defined(__FRAMAC__)
  Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif

  reset_file_recovery(&file_recovery);
  /*@ assert file_recovery.extension == \null; */
  /*@ assert file_recovery.file_stat == \null; */
  file_recovery.blocksize=BLOCKSIZE;
  reset_file_recovery(&file_recovery_new);
  file_recovery_new.blocksize=BLOCKSIZE;

  file_stats.file_hint=&file_hint_fasttxt;
  file_stats.not_recovered=0;
  file_stats.recovered=0;
#if 0
  register_header_check_fasttxt(&file_stats);
#endif
  /*@ assert file_recovery.extension == \null; */
  if(header_check_ics(buffer, BLOCKSIZE, 0u, &file_recovery, &file_recovery_new)!=1)
    return 0;
  /*@ assert valid_read_string((char *)&fn); */
  memcpy(file_recovery_new.filename, fn, sizeof(fn));
  file_recovery_new.file_stat=&file_stats;
  /*@ assert file_recovery_new.extension == extension_ics; */
  /*@ assert valid_read_string(extension_ics); */
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  /*@ assert file_recovery_new.calculated_file_size == 0; */
  /*@ assert file_recovery_new.file_size == 0;	*/
  /*@ assert file_recovery_new.data_check == &data_check_txt; */
  /*@ assert file_recovery_new.file_check == &file_check_size; */
  /*@ assert file_recovery_new.file_stat->file_hint==&file_hint_fasttxt; */
  {
    unsigned char big_buffer[2*BLOCKSIZE];
    data_check_t res_data_check=DC_CONTINUE;
    memset(big_buffer, 0, BLOCKSIZE);
    memcpy(big_buffer + BLOCKSIZE, buffer, BLOCKSIZE);
    /*@ assert file_recovery_new.data_check == &data_check_txt; */
    /*@ assert file_recovery_new.file_size == 0; */;
    /*@ assert file_recovery_new.file_size <= file_recovery_new.calculated_file_size; */;
    res_data_check=data_check_txt(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    file_recovery_new.file_size+=BLOCKSIZE;
    if(res_data_check == DC_CONTINUE)
    {
      /*@ assert file_recovery_new.data_check == &data_check_txt; */
      memcpy(big_buffer, big_buffer + BLOCKSIZE, BLOCKSIZE);
#if defined(__FRAMAC__)
      Frama_C_make_unknown((char *)big_buffer + BLOCKSIZE, BLOCKSIZE);
#endif
      data_check_txt(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    }
  }
  {
    file_recovery_t file_recovery_new2;
    file_recovery_new2.blocksize=BLOCKSIZE;
    file_recovery_new2.file_stat=NULL;
    file_recovery_new2.file_check=NULL;
    file_recovery_new2.location.start=BLOCKSIZE;
    file_recovery_new.handle=NULL;	/* In theory should be not null */
#if defined(__FRAMAC__)
    Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif
    /*@ assert file_recovery_new.extension == extension_ics; */
    /*@ assert valid_read_string(extension_ics); */
    /*@ assert valid_read_string((char *)file_recovery_new.filename); */
    header_check_ics(buffer, BLOCKSIZE, 0, &file_recovery_new, &file_recovery_new2);
  }
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  file_recovery_new.handle=fopen(fn, "rb");
  /*@ assert file_recovery_new.file_check == &file_check_size; */
  if(file_recovery_new.handle!=NULL)
  {
    file_check_size(&file_recovery_new);
    fclose(file_recovery_new.handle);
  }
  return 0;
}

static int main_mbox()
{
  const char fn[] = "recup_dir.1/f0000000.mbox";
  unsigned char buffer[BLOCKSIZE];
  file_recovery_t file_recovery_new;
  file_recovery_t file_recovery;
  file_stat_t file_stats;

  /*@ assert \valid(buffer + (0 .. (BLOCKSIZE - 1))); */
#if defined(__FRAMAC__)
  Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif

  reset_file_recovery(&file_recovery);
  /*@ assert file_recovery.extension == \null; */
  /*@ assert file_recovery.file_stat == \null; */
  file_recovery.blocksize=BLOCKSIZE;
  reset_file_recovery(&file_recovery_new);
  file_recovery_new.blocksize=BLOCKSIZE;

  file_stats.file_hint=&file_hint_fasttxt;
  file_stats.not_recovered=0;
  file_stats.recovered=0;
#if 0
  register_header_check_fasttxt(&file_stats);
#endif
  /*@ assert file_recovery.extension == \null; */
  if(header_check_mbox(buffer, BLOCKSIZE, 0u, &file_recovery, &file_recovery_new)!=1)
    return 0;
  /*@ assert valid_read_string((char *)&fn); */
  memcpy(file_recovery_new.filename, fn, sizeof(fn));
  file_recovery_new.file_stat=&file_stats;
  /*@ assert file_recovery_new.extension == extension_mbox; */
  /*@ assert valid_read_string(extension_mbox); */
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  /*@ assert file_recovery_new.calculated_file_size == 0; */
  /*@ assert file_recovery_new.file_size == 0;	*/
  /*@ assert file_recovery_new.data_check == &data_check_txt; */
  /*@ assert file_recovery_new.file_check == &file_check_size; */
  /*@ assert file_recovery_new.file_stat->file_hint==&file_hint_fasttxt; */
  {
    unsigned char big_buffer[2*BLOCKSIZE];
    data_check_t res_data_check=DC_CONTINUE;
    memset(big_buffer, 0, BLOCKSIZE);
    memcpy(big_buffer + BLOCKSIZE, buffer, BLOCKSIZE);
    /*@ assert file_recovery_new.data_check == &data_check_txt; */
    /*@ assert file_recovery_new.file_size == 0; */;
    /*@ assert file_recovery_new.file_size <= file_recovery_new.calculated_file_size; */;
    res_data_check=data_check_txt(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    file_recovery_new.file_size+=BLOCKSIZE;
    if(res_data_check == DC_CONTINUE)
    {
      /*@ assert file_recovery_new.data_check == &data_check_txt; */
      memcpy(big_buffer, big_buffer + BLOCKSIZE, BLOCKSIZE);
#if defined(__FRAMAC__)
      Frama_C_make_unknown((char *)big_buffer + BLOCKSIZE, BLOCKSIZE);
#endif
      data_check_txt(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    }
  }
  {
    file_recovery_t file_recovery_new2;
    file_recovery_new2.blocksize=BLOCKSIZE;
    file_recovery_new2.file_stat=NULL;
    file_recovery_new2.file_check=NULL;
    file_recovery_new2.location.start=BLOCKSIZE;
    file_recovery_new.handle=NULL;	/* In theory should be not null */
#if defined(__FRAMAC__)
    Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif
    /*@ assert file_recovery_new.extension == extension_mbox; */
    /*@ assert valid_read_string(extension_mbox); */
    /*@ assert valid_read_string((char *)file_recovery_new.filename); */
    header_check_mbox(buffer, BLOCKSIZE, 0, &file_recovery_new, &file_recovery_new2);
  }
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  file_recovery_new.handle=fopen(fn, "rb");
  /*@ assert file_recovery_new.file_check == &file_check_size; */
  if(file_recovery_new.handle!=NULL)
  {
    file_check_size(&file_recovery_new);
    fclose(file_recovery_new.handle);
  }
  return 0;
}

static int main_perlm()
{
  const char fn[] = "recup_dir.1/f0000000.pm";
  unsigned char buffer[BLOCKSIZE];
  file_recovery_t file_recovery_new;
  file_recovery_t file_recovery;
  file_stat_t file_stats;

  /*@ assert \valid(buffer + (0 .. (BLOCKSIZE - 1))); */
#if defined(__FRAMAC__)
  Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif

  reset_file_recovery(&file_recovery);
  /*@ assert file_recovery.file_stat == \null; */
  file_recovery.blocksize=BLOCKSIZE;
  reset_file_recovery(&file_recovery_new);
  file_recovery_new.blocksize=BLOCKSIZE;

  file_stats.file_hint=&file_hint_fasttxt;
  file_stats.not_recovered=0;
  file_stats.recovered=0;
#if 0
  register_header_check_fasttxt(&file_stats);
#endif
  if(header_check_perlm(buffer, BLOCKSIZE, 0u, &file_recovery, &file_recovery_new)!=1)
    return 0;
  /*@ assert valid_read_string((char *)&fn); */
  memcpy(file_recovery_new.filename, fn, sizeof(fn));
  file_recovery_new.file_stat=&file_stats;
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  /*@ assert file_recovery_new.extension == extension_pm || file_recovery_new.extension == extension_java; */
  /*@ assert valid_read_string((char *)file_recovery_new.extension); */
  /*@ assert file_recovery_new.calculated_file_size == 0; */
  /*@ assert file_recovery_new.file_size == 0;	*/
  /*@ assert file_recovery_new.data_check == &data_check_txt; */
  /*@ assert file_recovery_new.file_check == &file_check_size; */
  /*@ assert file_recovery_new.file_stat->file_hint==&file_hint_fasttxt; */
  {
    unsigned char big_buffer[2*BLOCKSIZE];
    data_check_t res_data_check=DC_CONTINUE;
    memset(big_buffer, 0, BLOCKSIZE);
    memcpy(big_buffer + BLOCKSIZE, buffer, BLOCKSIZE);
    /*@ assert file_recovery_new.data_check == &data_check_txt; */
    /*@ assert file_recovery_new.file_size == 0; */;
    /*@ assert file_recovery_new.file_size <= file_recovery_new.calculated_file_size; */;
    res_data_check=data_check_txt(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    file_recovery_new.file_size+=BLOCKSIZE;
    if(res_data_check == DC_CONTINUE)
    {
      /*@ assert file_recovery_new.data_check == &data_check_txt; */
      memcpy(big_buffer, big_buffer + BLOCKSIZE, BLOCKSIZE);
#if defined(__FRAMAC__)
      Frama_C_make_unknown((char *)big_buffer + BLOCKSIZE, BLOCKSIZE);
#endif
      data_check_txt(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    }
  }
  {
    file_recovery_t file_recovery_new2;
    file_recovery_new2.blocksize=BLOCKSIZE;
    file_recovery_new2.file_stat=NULL;
    file_recovery_new2.file_check=NULL;
    file_recovery_new2.location.start=BLOCKSIZE;
    file_recovery_new.handle=NULL;	/* In theory should be not null */
#if defined(__FRAMAC__)
    Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif
    /*@ assert valid_read_string((char *)file_recovery_new.filename); */
    header_check_perlm(buffer, BLOCKSIZE, 0, &file_recovery_new, &file_recovery_new2);
  }
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  file_recovery_new.handle=fopen(fn, "rb");
  /*@ assert file_recovery_new.file_check == &file_check_size; */
  if(file_recovery_new.handle!=NULL)
  {
    file_check_size(&file_recovery_new);
    fclose(file_recovery_new.handle);
  }
  return 0;
}

static int main_rtf()
{
  const char fn[] = "recup_dir.1/f0000000.rtf";
  unsigned char buffer[BLOCKSIZE];
  file_recovery_t file_recovery_new;
  file_recovery_t file_recovery;
  file_stat_t file_stats;

  /*@ assert \valid(buffer + (0 .. (BLOCKSIZE - 1))); */
#if defined(__FRAMAC__)
  Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif

  reset_file_recovery(&file_recovery);
  /*@ assert file_recovery.file_stat == \null; */
  file_recovery.blocksize=BLOCKSIZE;
  reset_file_recovery(&file_recovery_new);
  file_recovery_new.blocksize=BLOCKSIZE;

  file_stats.file_hint=&file_hint_fasttxt;
  file_stats.not_recovered=0;
  file_stats.recovered=0;
#if 0
  register_header_check_fasttxt(&file_stats);
#endif
  if(header_check_rtf(buffer, BLOCKSIZE, 0u, &file_recovery, &file_recovery_new)!=1)
    return 0;
  /*@ assert valid_read_string((char *)&fn); */
  memcpy(file_recovery_new.filename, fn, sizeof(fn));
  file_recovery_new.file_stat=&file_stats;
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  /*@ assert file_recovery_new.extension == extension_rtf; */
  /*@ assert file_recovery_new.calculated_file_size == 0; */
  /*@ assert file_recovery_new.file_size == 0;	*/
  /*@ assert file_recovery_new.data_check == &data_check_txt; */
  /*@ assert file_recovery_new.file_check == &file_check_size; */
  /*@ assert file_recovery_new.file_stat->file_hint==&file_hint_fasttxt; */
  {
    unsigned char big_buffer[2*BLOCKSIZE];
    data_check_t res_data_check=DC_CONTINUE;
    memset(big_buffer, 0, BLOCKSIZE);
    memcpy(big_buffer + BLOCKSIZE, buffer, BLOCKSIZE);
    /*@ assert file_recovery_new.data_check == &data_check_txt; */
    /*@ assert file_recovery_new.file_size == 0; */;
    /*@ assert file_recovery_new.file_size <= file_recovery_new.calculated_file_size; */;
    res_data_check=data_check_txt(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    file_recovery_new.file_size+=BLOCKSIZE;
    if(res_data_check == DC_CONTINUE)
    {
      /*@ assert file_recovery_new.data_check == &data_check_txt; */
      memcpy(big_buffer, big_buffer + BLOCKSIZE, BLOCKSIZE);
#if defined(__FRAMAC__)
      Frama_C_make_unknown((char *)big_buffer + BLOCKSIZE, BLOCKSIZE);
#endif
      data_check_txt(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    }
  }
  {
    file_recovery_t file_recovery_new2;
    file_recovery_new2.blocksize=BLOCKSIZE;
    file_recovery_new2.file_stat=NULL;
    file_recovery_new2.file_check=NULL;
    file_recovery_new2.location.start=BLOCKSIZE;
    file_recovery_new.handle=NULL;	/* In theory should be not null */
#if defined(__FRAMAC__)
    Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif
    /*@ assert valid_read_string((char *)file_recovery_new.filename); */
    header_check_rtf(buffer, BLOCKSIZE, 0, &file_recovery_new, &file_recovery_new2);
  }
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  file_recovery_new.handle=fopen(fn, "rb");
  /*@ assert file_recovery_new.file_check == &file_check_size; */
  if(file_recovery_new.handle!=NULL)
  {
    file_check_size(&file_recovery_new);
    fclose(file_recovery_new.handle);
  }
  return 0;
}

static int main_smail()
{
  const char fn[] = "recup_dir.1/f0000000.smil";
  unsigned char buffer[BLOCKSIZE];
  file_recovery_t file_recovery_new;
  file_recovery_t file_recovery;
  file_stat_t file_stats;

  /*@ assert \valid(buffer + (0 .. (BLOCKSIZE - 1))); */
#if defined(__FRAMAC__)
  Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif

  reset_file_recovery(&file_recovery);
  /*@ assert file_recovery.file_stat == \null; */
  file_recovery.blocksize=BLOCKSIZE;
  reset_file_recovery(&file_recovery_new);
  file_recovery_new.blocksize=BLOCKSIZE;

  file_stats.file_hint=&file_hint_fasttxt;
  file_stats.not_recovered=0;
  file_stats.recovered=0;
#if 0
  register_header_check_fasttxt(&file_stats);
#endif
  if(header_check_smil(buffer, BLOCKSIZE, 0u, &file_recovery, &file_recovery_new)!=1)
    return 0;
  /*@ assert valid_read_string((char *)&fn); */
  memcpy(file_recovery_new.filename, fn, sizeof(fn));
  file_recovery_new.file_stat=&file_stats;
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  /*@ assert file_recovery_new.extension == extension_smil; */
  /*@ assert file_recovery_new.calculated_file_size == 0; */
  /*@ assert file_recovery_new.file_size == 0;	*/
  /*@ assert file_recovery_new.data_check == &data_check_txt; */
  /*@ assert file_recovery_new.file_check == &file_check_smil; */
  /*@ assert file_recovery_new.file_stat->file_hint==&file_hint_fasttxt; */
  {
    unsigned char big_buffer[2*BLOCKSIZE];
    data_check_t res_data_check=DC_CONTINUE;
    memset(big_buffer, 0, BLOCKSIZE);
    memcpy(big_buffer + BLOCKSIZE, buffer, BLOCKSIZE);
    /*@ assert file_recovery_new.data_check == &data_check_txt; */
    /*@ assert file_recovery_new.file_size == 0; */;
    /*@ assert file_recovery_new.file_size <= file_recovery_new.calculated_file_size; */;
    res_data_check=data_check_txt(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    file_recovery_new.file_size+=BLOCKSIZE;
    if(res_data_check == DC_CONTINUE)
    {
      /*@ assert file_recovery_new.data_check == &data_check_txt; */
      memcpy(big_buffer, big_buffer + BLOCKSIZE, BLOCKSIZE);
#if defined(__FRAMAC__)
      Frama_C_make_unknown((char *)big_buffer + BLOCKSIZE, BLOCKSIZE);
#endif
      data_check_txt(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    }
  }
  {
    file_recovery_t file_recovery_new2;
    file_recovery_new2.blocksize=BLOCKSIZE;
    file_recovery_new2.file_stat=NULL;
    file_recovery_new2.file_check=NULL;
    file_recovery_new2.location.start=BLOCKSIZE;
    file_recovery_new.handle=NULL;	/* In theory should be not null */
#if defined(__FRAMAC__)
    Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif
    /*@ assert valid_read_string((char *)file_recovery_new.filename); */
    header_check_smil(buffer, BLOCKSIZE, 0, &file_recovery_new, &file_recovery_new2);
  }
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  file_recovery_new.handle=fopen(fn, "rb");
  /*@ assert file_recovery_new.file_check == &file_check_smil; */
  if(file_recovery_new.handle!=NULL)
  {
    file_check_smil(&file_recovery_new);
    fclose(file_recovery_new.handle);
  }
  return 0;
}

static int main_snz()
{
  const char fn[] = "recup_dir.1/f0000000.snz";
  unsigned char buffer[BLOCKSIZE];
  file_recovery_t file_recovery_new;
  file_recovery_t file_recovery;
  file_stat_t file_stats;

  /*@ assert \valid(buffer + (0 .. (BLOCKSIZE - 1))); */
#if defined(__FRAMAC__)
  Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif

  reset_file_recovery(&file_recovery);
  /*@ assert file_recovery.file_stat == \null; */
  file_recovery.blocksize=BLOCKSIZE;
  reset_file_recovery(&file_recovery_new);
  file_recovery_new.blocksize=BLOCKSIZE;

  file_stats.file_hint=&file_hint_snz;
  file_stats.not_recovered=0;
  file_stats.recovered=0;
#if 0
  register_header_check_snz(&file_stats);
#endif
  if(header_check_snz(buffer, BLOCKSIZE, 0u, &file_recovery, &file_recovery_new)!=1)
    return 0;
  /*@ assert valid_read_string((char *)&fn); */
  memcpy(file_recovery_new.filename, fn, sizeof(fn));
  file_recovery_new.file_stat=&file_stats;
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  /*@ assert file_recovery_new.extension == file_hint_snz.extension; */
  /*@ assert file_recovery_new.calculated_file_size == 0; */
  /*@ assert file_recovery_new.file_size == 0;	*/
  /*@ assert file_recovery_new.file_check == &file_check_size; */
  /*@ assert file_recovery_new.data_check == &data_check_txt; */
  /*@ assert file_recovery_new.file_stat->file_hint==&file_hint_snz; */
  {
    unsigned char big_buffer[2*BLOCKSIZE];
    data_check_t res_data_check=DC_CONTINUE;
    memset(big_buffer, 0, BLOCKSIZE);
    memcpy(big_buffer + BLOCKSIZE, buffer, BLOCKSIZE);
    /*@ assert file_recovery_new.data_check == &data_check_txt; */
    /*@ assert file_recovery_new.file_size == 0; */;
    /*@ assert file_recovery_new.file_size <= file_recovery_new.calculated_file_size; */;
    res_data_check=data_check_txt(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    file_recovery_new.file_size+=BLOCKSIZE;
    if(res_data_check == DC_CONTINUE)
    {
      /*@ assert file_recovery_new.data_check == &data_check_txt; */
      memcpy(big_buffer, big_buffer + BLOCKSIZE, BLOCKSIZE);
#if defined(__FRAMAC__)
      Frama_C_make_unknown((char *)big_buffer + BLOCKSIZE, BLOCKSIZE);
#endif
      data_check_txt(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    }
  }
  {
    file_recovery_t file_recovery_new2;
    file_recovery_new2.blocksize=BLOCKSIZE;
    file_recovery_new2.file_stat=NULL;
    file_recovery_new2.file_check=NULL;
    file_recovery_new2.location.start=BLOCKSIZE;
    file_recovery_new.handle=NULL;	/* In theory should be not null */
#if defined(__FRAMAC__)
    Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif
    /*@ assert valid_read_string((char *)file_recovery_new.filename); */
    header_check_snz(buffer, BLOCKSIZE, 0, &file_recovery_new, &file_recovery_new2);
  }
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  file_recovery_new.handle=fopen(fn, "rb");
  /*@ assert file_recovery_new.file_check == &file_check_size; */
  if(file_recovery_new.handle!=NULL)
  {
    file_check_size(&file_recovery_new);
    fclose(file_recovery_new.handle);
  }
  return 0;
}

static int main_stl()
{
  const char fn[] = "recup_dir.1/f0000000.stl";
  unsigned char buffer[BLOCKSIZE];
  file_recovery_t file_recovery_new;
  file_recovery_t file_recovery;
  file_stat_t file_stats;

  /*@ assert \valid(buffer + (0 .. (BLOCKSIZE - 1))); */
#if defined(__FRAMAC__)
  Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif

  reset_file_recovery(&file_recovery);
  /*@ assert file_recovery.file_stat == \null; */
  file_recovery.blocksize=BLOCKSIZE;
  reset_file_recovery(&file_recovery_new);
  file_recovery_new.blocksize=BLOCKSIZE;

  file_stats.file_hint=&file_hint_fasttxt;
  file_stats.not_recovered=0;
  file_stats.recovered=0;
#if 0
  register_header_check_fasttxt(&file_stats);
#endif
  if(header_check_stl(buffer, BLOCKSIZE, 0u, &file_recovery, &file_recovery_new)!=1)
    return 0;
  /*@ assert valid_read_string((char *)&fn); */
  memcpy(file_recovery_new.filename, fn, sizeof(fn));
  file_recovery_new.file_stat=&file_stats;
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  /*@ assert file_recovery_new.extension == extension_stl; */
  /*@ assert file_recovery_new.calculated_file_size == 0; */
  /*@ assert file_recovery_new.file_size == 0;	*/
  /*@ assert file_recovery_new.data_check == &data_check_txt; */
  /*@ assert file_recovery_new.file_check == &file_check_size; */
  /*@ assert file_recovery_new.file_stat->file_hint==&file_hint_fasttxt; */
  {
    unsigned char big_buffer[2*BLOCKSIZE];
    data_check_t res_data_check=DC_CONTINUE;
    memset(big_buffer, 0, BLOCKSIZE);
    memcpy(big_buffer + BLOCKSIZE, buffer, BLOCKSIZE);
    /*@ assert file_recovery_new.data_check == &data_check_txt; */
    /*@ assert file_recovery_new.file_size == 0; */;
    /*@ assert file_recovery_new.file_size <= file_recovery_new.calculated_file_size; */;
    res_data_check=data_check_txt(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    file_recovery_new.file_size+=BLOCKSIZE;
    if(res_data_check == DC_CONTINUE)
    {
      /*@ assert file_recovery_new.data_check == &data_check_txt; */
      memcpy(big_buffer, big_buffer + BLOCKSIZE, BLOCKSIZE);
#if defined(__FRAMAC__)
      Frama_C_make_unknown((char *)big_buffer + BLOCKSIZE, BLOCKSIZE);
#endif
      data_check_txt(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    }
  }
  {
    file_recovery_t file_recovery_new2;
    file_recovery_new2.blocksize=BLOCKSIZE;
    file_recovery_new2.file_stat=NULL;
    file_recovery_new2.file_check=NULL;
    file_recovery_new2.location.start=BLOCKSIZE;
    file_recovery_new.handle=NULL;	/* In theory should be not null */
#if defined(__FRAMAC__)
    Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif
    /*@ assert valid_read_string((char *)file_recovery_new.filename); */
    header_check_stl(buffer, BLOCKSIZE, 0, &file_recovery_new, &file_recovery_new2);
  }
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  file_recovery_new.handle=fopen(fn, "rb");
  /*@ assert file_recovery_new.file_check == &file_check_size; */
  if(file_recovery_new.handle!=NULL)
  {
    file_check_size(&file_recovery_new);
    fclose(file_recovery_new.handle);
  }
  return 0;
}

static int main_svg()
{
  const char fn[] = "recup_dir.1/f0000000.svg";
  unsigned char buffer[BLOCKSIZE];
  file_recovery_t file_recovery_new;
  file_recovery_t file_recovery;
  file_stat_t file_stats;

  /*@ assert \valid(buffer + (0 .. (BLOCKSIZE - 1))); */
#if defined(__FRAMAC__)
  Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif

  reset_file_recovery(&file_recovery);
  /*@ assert file_recovery.file_stat == \null; */
  file_recovery.blocksize=BLOCKSIZE;
  reset_file_recovery(&file_recovery_new);
  file_recovery_new.blocksize=BLOCKSIZE;

  file_stats.file_hint=&file_hint_fasttxt;
  file_stats.not_recovered=0;
  file_stats.recovered=0;
#if 0
  register_header_check_fasttxt(&file_stats);
#endif
  if(header_check_svg(buffer, BLOCKSIZE, 0u, &file_recovery, &file_recovery_new)!=1)
    return 0;
  /*@ assert valid_read_string((char *)&fn); */
  memcpy(file_recovery_new.filename, fn, sizeof(fn));
  file_recovery_new.file_stat=&file_stats;
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  /*@ assert file_recovery_new.extension == extension_svg; */
  /*@ assert file_recovery_new.calculated_file_size == 0; */
  /*@ assert file_recovery_new.file_size == 0;	*/
  /*@ assert file_recovery_new.file_check == &file_check_svg; */
  /*@ assert file_recovery_new.data_check == \null; */
  /*@ assert file_recovery_new.file_stat->file_hint==&file_hint_fasttxt; */
  {
    file_recovery_t file_recovery_new2;
    file_recovery_new2.blocksize=BLOCKSIZE;
    file_recovery_new2.file_stat=NULL;
    file_recovery_new2.file_check=NULL;
    file_recovery_new2.location.start=BLOCKSIZE;
    file_recovery_new.handle=NULL;	/* In theory should be not null */
#if defined(__FRAMAC__)
    Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif
    /*@ assert valid_read_string((char *)file_recovery_new.filename); */
    header_check_svg(buffer, BLOCKSIZE, 0, &file_recovery_new, &file_recovery_new2);
  }
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  file_recovery_new.handle=fopen(fn, "rb");
  /*@ assert file_recovery_new.file_check == &file_check_svg; */
  if(file_recovery_new.handle!=NULL)
  {
    file_check_svg(&file_recovery_new);
    fclose(file_recovery_new.handle);
  }
  return 0;
}

static int main_thunderbird()
{
  const char fn[] = "recup_dir.1/f0000000.mbox";
  unsigned char buffer[BLOCKSIZE];
  file_recovery_t file_recovery_new;
  file_recovery_t file_recovery;
  file_stat_t file_stats;

  /*@ assert \valid(buffer + (0 .. (BLOCKSIZE - 1))); */
#if defined(__FRAMAC__)
  Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif

  reset_file_recovery(&file_recovery);
  reset_file_recovery(&file_recovery_new);
  /*@ assert file_recovery.file_stat == \null; */
  file_recovery.blocksize=BLOCKSIZE;
  file_recovery_new.blocksize=BLOCKSIZE;
  file_stats.file_hint=&file_hint_fasttxt;
  file_stats.not_recovered=0;
  file_stats.recovered=0;
#if 0
  register_header_check_fasttxt(&file_stats);
#endif
  if(header_check_thunderbird(buffer, BLOCKSIZE, 0u, &file_recovery, &file_recovery_new)!=1)
    return 0;
  /*@ assert valid_read_string((char *)&fn); */
  memcpy(file_recovery_new.filename, fn, sizeof(fn));
  file_recovery_new.file_stat=&file_stats;
  /*@ assert valid_read_string(extension_mbox); */
  /*@ assert file_recovery_new.extension == extension_mbox; */
  /*@ assert valid_read_string(file_recovery_new.extension); */
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  /*@ assert file_recovery_new.calculated_file_size == 0; */
  /*@ assert file_recovery_new.file_size == 0;	*/
  /*@ assert file_recovery_new.data_check == &data_check_txt; */
  /*@ assert file_recovery_new.file_check == &file_check_size; */
  /*@ assert file_recovery_new.file_stat->file_hint==&file_hint_fasttxt; */
  {
    unsigned char big_buffer[2*BLOCKSIZE];
    data_check_t res_data_check=DC_CONTINUE;
    memset(big_buffer, 0, BLOCKSIZE);
    memcpy(big_buffer + BLOCKSIZE, buffer, BLOCKSIZE);
    /*@ assert file_recovery_new.data_check == &data_check_txt; */
    /*@ assert file_recovery_new.file_size == 0; */;
    /*@ assert file_recovery_new.file_size <= file_recovery_new.calculated_file_size; */;
    res_data_check=data_check_txt(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    file_recovery_new.file_size+=BLOCKSIZE;
    if(res_data_check == DC_CONTINUE)
    {
      /*@ assert file_recovery_new.data_check == &data_check_txt; */
      memcpy(big_buffer, big_buffer + BLOCKSIZE, BLOCKSIZE);
#if defined(__FRAMAC__)
      Frama_C_make_unknown((char *)big_buffer + BLOCKSIZE, BLOCKSIZE);
#endif
      data_check_txt(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    }
  }
  {
    file_recovery_t file_recovery_new2;
    file_recovery_new2.blocksize=BLOCKSIZE;
    file_recovery_new2.file_stat=NULL;
    file_recovery_new2.file_check=NULL;
    file_recovery_new2.location.start=BLOCKSIZE;
    file_recovery_new.handle=NULL;	/* In theory should be not null */
#if defined(__FRAMAC__)
    Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif
    /*@ assert valid_read_string(extension_mbox); */
    /*@ assert file_recovery_new.extension == extension_mbox; */
    /*@ assert valid_read_string(file_recovery_new.extension); */
    /*@ assert valid_read_string((char *)file_recovery_new.filename); */
    header_check_thunderbird(buffer, BLOCKSIZE, 0, &file_recovery_new, &file_recovery_new2);
  }
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  file_recovery_new.handle=fopen(fn, "rb");
  /*@ assert file_recovery_new.file_check == &file_check_size; */
  if(file_recovery_new.handle!=NULL)
  {
    file_check_size(&file_recovery_new);
    fclose(file_recovery_new.handle);
  }
  return 0;
}

static int main_ttd()
{
  const char fn[] = "recup_dir.1/f0000000.ttd";
  unsigned char buffer[BLOCKSIZE];
  file_recovery_t file_recovery_new;
  file_recovery_t file_recovery;
  file_stat_t file_stats;

  /*@ assert \valid(buffer + (0 .. (BLOCKSIZE - 1))); */
#if defined(__FRAMAC__)
  Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif

  reset_file_recovery(&file_recovery);
  /*@ assert file_recovery.file_stat == \null; */
  file_recovery.blocksize=BLOCKSIZE;
  reset_file_recovery(&file_recovery_new);
  file_recovery_new.blocksize=BLOCKSIZE;

  file_stats.file_hint=&file_hint_fasttxt;
  file_stats.not_recovered=0;
  file_stats.recovered=0;
//  register_header_check_fasttxt(&file_stats);
  if(header_check_ttd(buffer, BLOCKSIZE, 0u, &file_recovery, &file_recovery_new)!=1)
    return 0;
  /*@ assert valid_read_string((char *)&fn); */
  memcpy(file_recovery_new.filename, fn, sizeof(fn));
  file_recovery_new.file_stat=&file_stats;
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  /*@ assert file_recovery_new.extension == extension_ttd; */
  /*@ assert file_recovery_new.calculated_file_size == 0; */
  /*@ assert file_recovery_new.file_size == 0;	*/
  /*@ assert file_recovery_new.file_check == &file_check_size_max; */
  /*@ assert file_recovery_new.data_check == &data_check_ttd; */
  /*@ assert file_recovery_new.file_stat->file_hint==&file_hint_fasttxt; */
  {
    unsigned char big_buffer[2*BLOCKSIZE];
    data_check_t res_data_check=DC_CONTINUE;
    memset(big_buffer, 0, BLOCKSIZE);
    memcpy(big_buffer + BLOCKSIZE, buffer, BLOCKSIZE);
    /*@ assert file_recovery_new.data_check == &data_check_ttd; */
    /*@ assert file_recovery_new.file_size == 0; */;
    /*@ assert file_recovery_new.file_size <= file_recovery_new.calculated_file_size; */;
    res_data_check=data_check_ttd(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    file_recovery_new.file_size+=BLOCKSIZE;
    if(res_data_check == DC_CONTINUE)
    {
      memcpy(big_buffer, big_buffer + BLOCKSIZE, BLOCKSIZE);
#if defined(__FRAMAC__)
      Frama_C_make_unknown((char *)big_buffer + BLOCKSIZE, BLOCKSIZE);
#endif
      data_check_ttd(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    }
  }
  {
    file_recovery_t file_recovery_new2;
    file_recovery_new2.blocksize=BLOCKSIZE;
    file_recovery_new2.file_stat=NULL;
    file_recovery_new2.file_check=NULL;
    file_recovery_new2.location.start=BLOCKSIZE;
    file_recovery_new.handle=NULL;	/* In theory should be not null */
#if defined(__FRAMAC__)
    Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif
    /*@ assert valid_read_string((char *)file_recovery_new.filename); */
    header_check_ttd(buffer, BLOCKSIZE, 0, &file_recovery_new, &file_recovery_new2);
  }
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  file_recovery_new.handle=fopen(fn, "rb");
  /*@ assert file_recovery_new.file_check == &file_check_size_max; */
  if(file_recovery_new.handle!=NULL)
  {
    file_check_size_max(&file_recovery_new);
    fclose(file_recovery_new.handle);
  }
  return 0;
}

static int main_txt()
{
  const char fn[] = "recup_dir.1/f0000000.txt";
  unsigned char buffer[BLOCKSIZE];
  file_recovery_t file_recovery_new;
  file_recovery_t file_recovery;
  file_stat_t file_stats;

  /*@ assert \valid(buffer + (0 .. (BLOCKSIZE - 1))); */
#if defined(__FRAMAC__)
  Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif

  reset_file_recovery(&file_recovery);
  /*@ assert file_recovery.extension == \null; */
  /*@ assert file_recovery.file_stat == \null; */
  file_recovery.blocksize=BLOCKSIZE;
  reset_file_recovery(&file_recovery_new);
  file_recovery_new.blocksize=BLOCKSIZE;

  file_stats.file_hint=&file_hint_txt;
  file_stats.not_recovered=0;
  file_stats.recovered=0;
#if 0
  register_header_check_txt(&file_stats);
#endif
  /*@ assert file_recovery.extension == \null; */
  if(header_check_txt(buffer, BLOCKSIZE, 0u, &file_recovery, &file_recovery_new)!=1)
    return 0;
  /*@ assert valid_read_string((char *)&fn); */
  /*@ assert file_recovery_new.extension != \null; */
  memcpy(file_recovery_new.filename, fn, sizeof(fn));
  file_recovery_new.file_stat=&file_stats;
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  /*@ assert valid_read_string((char *)file_recovery_new.extension); */
  /*@ assert file_recovery_new.file_size == 0;	*/
  /*@ assert file_recovery_new.data_check == \null || file_recovery_new.data_check == &data_check_html || file_recovery_new.data_check == &data_check_txt; */
  /*@ assert file_recovery_new.file_check == &file_check_emlx || file_recovery_new.file_check == &file_check_size; */
  /*@ assert file_recovery_new.file_rename == \null || file_recovery_new.file_rename == &file_rename_html; */
  /*@ assert file_recovery_new.file_stat->file_hint==&file_hint_txt; */
  if(file_recovery_new.data_check != NULL)
  {
    unsigned char big_buffer[2*BLOCKSIZE];
    data_check_t res_data_check=DC_CONTINUE;
    memset(big_buffer, 0, BLOCKSIZE);
    memcpy(big_buffer + BLOCKSIZE, buffer, BLOCKSIZE);
    /*@ assert file_recovery_new.data_check == &data_check_html || file_recovery_new.data_check == &data_check_txt; */
    /*@ assert file_recovery_new.file_size == 0; */;
    /*@ assert file_recovery_new.file_size <= file_recovery_new.calculated_file_size; */;
    res_data_check=file_recovery_new.data_check(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    file_recovery_new.file_size+=BLOCKSIZE;
    if(res_data_check == DC_CONTINUE)
    {
      memcpy(big_buffer, big_buffer + BLOCKSIZE, BLOCKSIZE);
#if defined(__FRAMAC__)
      Frama_C_make_unknown((char *)big_buffer + BLOCKSIZE, BLOCKSIZE);
#endif
      file_recovery_new.data_check(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    }
  }
  {
    file_recovery_t file_recovery_new2;
    file_recovery_new2.blocksize=BLOCKSIZE;
    file_recovery_new2.file_stat=NULL;
    file_recovery_new2.file_check=NULL;
    file_recovery_new2.location.start=BLOCKSIZE;
    file_recovery_new.handle=NULL;	/* In theory should be not null */
#if defined(__FRAMAC__)
    Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif
    /*@ assert valid_read_string((char *)file_recovery_new.extension); */
    /*@ assert valid_read_string((char *)file_recovery_new.filename); */
    header_check_txt(buffer, BLOCKSIZE, 0, &file_recovery_new, &file_recovery_new2);
  }
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  file_recovery_new.handle=fopen(fn, "rb");
  /*@ assert file_recovery_new.file_check == &file_check_emlx || file_recovery_new.file_check == &file_check_size; */
  if(file_recovery_new.handle!=NULL)
  {
    file_recovery_new.file_check(&file_recovery_new);
    fclose(file_recovery_new.handle);
  }
  if(file_recovery_new.file_rename != NULL)
  {
    /*@ assert file_recovery_new.file_rename == &file_rename_html; */
    file_rename_html(&file_recovery_new);
  }
  return 0;
}

static int main_vbm()
{
  const char fn[] = "recup_dir.1/f0000000.vbm";
  unsigned char buffer[BLOCKSIZE];
  file_recovery_t file_recovery_new;
  file_recovery_t file_recovery;
  file_stat_t file_stats;

  /*@ assert \valid(buffer + (0 .. (BLOCKSIZE - 1))); */
#if defined(__FRAMAC__)
  Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif

  reset_file_recovery(&file_recovery);
  /*@ assert file_recovery.file_stat == \null; */
  file_recovery.blocksize=BLOCKSIZE;
  reset_file_recovery(&file_recovery_new);
  file_recovery_new.blocksize=BLOCKSIZE;

  file_stats.file_hint=&file_hint_fasttxt;
  file_stats.not_recovered=0;
  file_stats.recovered=0;
#if 0
  register_header_check_fasttxt(&file_stats);
#endif
  if(header_check_vbm(buffer, BLOCKSIZE, 0u, &file_recovery, &file_recovery_new)!=1)
    return 0;
  /*@ assert valid_read_string((char *)&fn); */
  memcpy(file_recovery_new.filename, fn, sizeof(fn));
  file_recovery_new.file_stat=&file_stats;
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  /*@ assert file_recovery_new.extension == extension_vbm; */
  /*@ assert file_recovery_new.calculated_file_size == 0; */
  /*@ assert file_recovery_new.file_size == 0;	*/
  /*@ assert file_recovery_new.file_check == &file_check_vbm; */
  /*@ assert file_recovery_new.data_check == &data_check_txt; */
  /*@ assert file_recovery_new.file_stat->file_hint==&file_hint_fasttxt; */
  {
    unsigned char big_buffer[2*BLOCKSIZE];
    data_check_t res_data_check=DC_CONTINUE;
    memset(big_buffer, 0, BLOCKSIZE);
    memcpy(big_buffer + BLOCKSIZE, buffer, BLOCKSIZE);
    /*@ assert file_recovery_new.data_check == &data_check_txt; */
    /*@ assert file_recovery_new.file_size == 0; */;
    /*@ assert file_recovery_new.file_size <= file_recovery_new.calculated_file_size; */;
    res_data_check=data_check_txt(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    file_recovery_new.file_size+=BLOCKSIZE;
    if(res_data_check == DC_CONTINUE)
    {
      /*@ assert file_recovery_new.data_check == &data_check_txt; */
      memcpy(big_buffer, big_buffer + BLOCKSIZE, BLOCKSIZE);
#if defined(__FRAMAC__)
      Frama_C_make_unknown((char *)big_buffer + BLOCKSIZE, BLOCKSIZE);
#endif
      data_check_txt(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    }
  }
  {
    file_recovery_t file_recovery_new2;
    file_recovery_new2.blocksize=BLOCKSIZE;
    file_recovery_new2.file_stat=NULL;
    file_recovery_new2.file_check=NULL;
    file_recovery_new2.location.start=BLOCKSIZE;
    file_recovery_new.handle=NULL;	/* In theory should be not null */
#if defined(__FRAMAC__)
    Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif
    /*@ assert valid_read_string((char *)file_recovery_new.filename); */
    header_check_vbm(buffer, BLOCKSIZE, 0, &file_recovery_new, &file_recovery_new2);
  }
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  file_recovery_new.handle=fopen(fn, "rb");
  /*@ assert file_recovery_new.file_check == &file_check_vbm; */
  if(file_recovery_new.handle!=NULL)
  {
    file_check_vbm(&file_recovery_new);
    fclose(file_recovery_new.handle);
  }
  return 0;
}

static int main_xml()
{
  const char fn[] = "recup_dir.1/f0000000.xml";
  unsigned char buffer[BLOCKSIZE];
  file_recovery_t file_recovery_new;
  file_recovery_t file_recovery;
  file_stat_t file_stats;

  /*@ assert \valid(buffer + (0 .. (BLOCKSIZE - 1))); */
#if defined(__FRAMAC__)
  Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif

  reset_file_recovery(&file_recovery);
  /*@ assert file_recovery.file_stat == \null; */
  file_recovery.blocksize=BLOCKSIZE;
  reset_file_recovery(&file_recovery_new);
  file_recovery_new.blocksize=BLOCKSIZE;

  file_stats.file_hint=&file_hint_fasttxt;
  file_stats.not_recovered=0;
  file_stats.recovered=0;
#if 0
  register_header_check_fasttxt(&file_stats);
#endif
  if(header_check_xml(buffer, BLOCKSIZE, 0u, &file_recovery, &file_recovery_new)!=1)
    return 0;
  /*@ assert valid_read_string((char *)&fn); */
  memcpy(file_recovery_new.filename, fn, sizeof(fn));
  file_recovery_new.file_stat=&file_stats;
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  /*@ assert file_recovery_new.calculated_file_size == 0; */
  /*@ assert file_recovery_new.file_size == 0;	*/
  /*@ assert file_recovery_new.file_check == &file_check_gpx ||
		file_recovery_new.file_check == &file_check_svg ||
		file_recovery_new.file_check == &file_check_xml; */
  /*@ assert file_recovery_new.data_check == \null ||
		file_recovery_new.data_check == &data_check_html ||
		file_recovery_new.data_check == &data_check_txt; */
  /*@ assert file_recovery_new.file_rename == \null ||
		file_recovery_new.file_rename == &file_rename_fods ||
		file_recovery_new.file_rename == &file_rename_html;
	     */
  /*@ assert file_recovery_new.file_stat->file_hint==&file_hint_fasttxt; */
  if(file_recovery_new.data_check != NULL)
  {
    unsigned char big_buffer[2*BLOCKSIZE];
    data_check_t res_data_check=DC_CONTINUE;
    memset(big_buffer, 0, BLOCKSIZE);
    memcpy(big_buffer + BLOCKSIZE, buffer, BLOCKSIZE);
    /*@ assert file_recovery_new.file_size == 0; */;
    /*@ assert file_recovery_new.file_size <= file_recovery_new.calculated_file_size; */;
    res_data_check=file_recovery_new.data_check(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    file_recovery_new.file_size+=BLOCKSIZE;
    if(res_data_check == DC_CONTINUE)
    {
      memcpy(big_buffer, big_buffer + BLOCKSIZE, BLOCKSIZE);
#if defined(__FRAMAC__)
      Frama_C_make_unknown((char *)big_buffer + BLOCKSIZE, BLOCKSIZE);
#endif
      file_recovery_new.data_check(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    }
  }
  {
    file_recovery_t file_recovery_new2;
    file_recovery_new2.blocksize=BLOCKSIZE;
    file_recovery_new2.file_stat=NULL;
    file_recovery_new2.file_check=NULL;
    file_recovery_new2.location.start=BLOCKSIZE;
    file_recovery_new.handle=NULL;	/* In theory should be not null */
#if defined(__FRAMAC__)
    Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif
    /*@ assert valid_read_string((char *)file_recovery_new.filename); */
    header_check_xml(buffer, BLOCKSIZE, 0, &file_recovery_new, &file_recovery_new2);
  }
  if(file_recovery_new.file_check != NULL)
  {
    /*@ assert valid_read_string((char *)file_recovery_new.filename); */
    file_recovery_new.handle=fopen(fn, "rb");
    if(file_recovery_new.handle!=NULL)
    {
      file_recovery_new.file_check(&file_recovery_new);
      fclose(file_recovery_new.handle);
    }
  }
  if(file_recovery_new.file_rename!=NULL)
  {
    file_recovery_new.file_rename(&file_recovery_new);
  }
  return 0;
}

static int main_xml_utf8()
{
  const char fn[] = "recup_dir.1/f0000000.xml";
  unsigned char buffer[BLOCKSIZE];
  file_recovery_t file_recovery_new;
  file_recovery_t file_recovery;
  file_stat_t file_stats;

  /*@ assert \valid(buffer + (0 .. (BLOCKSIZE - 1))); */
#if defined(__FRAMAC__)
  Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif

  reset_file_recovery(&file_recovery);
  /*@ assert file_recovery.file_stat == \null; */
  file_recovery.blocksize=BLOCKSIZE;
  reset_file_recovery(&file_recovery_new);
  file_recovery_new.blocksize=BLOCKSIZE;

  file_stats.file_hint=&file_hint_fasttxt;
  file_stats.not_recovered=0;
  file_stats.recovered=0;
#if 0
  register_header_check_fasttxt(&file_stats);
#endif
  if(header_check_xml_utf8(buffer, BLOCKSIZE, 0u, &file_recovery, &file_recovery_new)!=1)
    return 0;
  /*@ assert valid_read_string((char *)&fn); */
  memcpy(file_recovery_new.filename, fn, sizeof(fn));
  file_recovery_new.file_stat=&file_stats;
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  /*@ assert file_recovery_new.extension == extension_ghx || file_recovery_new.extension == extension_xml; */
  /*@ assert file_recovery_new.calculated_file_size == 0; */
  /*@ assert file_recovery_new.file_size == 0;	*/
  /*@ assert file_recovery_new.file_check == &file_check_xml; */
  /*@ assert file_recovery_new.data_check == &data_check_xml_utf8; */
  /*@ assert file_recovery_new.file_stat->file_hint==&file_hint_fasttxt; */
  {
    unsigned char big_buffer[2*BLOCKSIZE];
    data_check_t res_data_check=DC_CONTINUE;
    memset(big_buffer, 0, BLOCKSIZE);
    memcpy(big_buffer + BLOCKSIZE, buffer, BLOCKSIZE);
    /*@ assert file_recovery_new.data_check == &data_check_xml_utf8; */
    /*@ assert file_recovery_new.file_size == 0; */;
    /*@ assert file_recovery_new.file_size <= file_recovery_new.calculated_file_size; */;
    res_data_check=data_check_xml_utf8(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    file_recovery_new.file_size+=BLOCKSIZE;
    if(res_data_check == DC_CONTINUE)
    {
      /*@ assert file_recovery_new.data_check == &data_check_txt; */
      memcpy(big_buffer, big_buffer + BLOCKSIZE, BLOCKSIZE);
#if defined(__FRAMAC__)
      Frama_C_make_unknown((char *)big_buffer + BLOCKSIZE, BLOCKSIZE);
#endif
      data_check_txt(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    }
  }
  {
    file_recovery_t file_recovery_new2;
    file_recovery_new2.blocksize=BLOCKSIZE;
    file_recovery_new2.file_stat=NULL;
    file_recovery_new2.file_check=NULL;
    file_recovery_new2.location.start=BLOCKSIZE;
    file_recovery_new.handle=NULL;	/* In theory should be not null */
#if defined(__FRAMAC__)
    Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif
    /*@ assert valid_read_string((char *)file_recovery_new.filename); */
    header_check_xml_utf8(buffer, BLOCKSIZE, 0, &file_recovery_new, &file_recovery_new2);
  }
  /*@ assert file_recovery_new.file_check == &file_check_xml; */
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  file_recovery_new.handle=fopen(fn, "rb");
  if(file_recovery_new.handle!=NULL)
  {
    file_check_xml(&file_recovery_new);
    fclose(file_recovery_new.handle);
  }
  return 0;
}

static int main_xml_utf16()
{
  const char fn[] = "recup_dir.1/f0000000.xml";
  unsigned char buffer[BLOCKSIZE];
  file_recovery_t file_recovery_new;
  file_recovery_t file_recovery;
  file_stat_t file_stats;

  /*@ assert \valid(buffer + (0 .. (BLOCKSIZE - 1))); */
#if defined(__FRAMAC__)
  Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif

  reset_file_recovery(&file_recovery);
  /*@ assert file_recovery.file_stat == \null; */
  file_recovery.blocksize=BLOCKSIZE;
  reset_file_recovery(&file_recovery_new);
  file_recovery_new.blocksize=BLOCKSIZE;

  file_stats.file_hint=&file_hint_fasttxt;
  file_stats.not_recovered=0;
  file_stats.recovered=0;
#if 0
  register_header_check_fasttxt(&file_stats);
#endif
  if(header_check_xml_utf16(buffer, BLOCKSIZE, 0u, &file_recovery, &file_recovery_new)!=1)
    return 0;
  /*@ assert valid_read_string((char *)&fn); */
  memcpy(file_recovery_new.filename, fn, sizeof(fn));
  file_recovery_new.file_stat=&file_stats;
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  /*@ assert file_recovery_new.extension == extension_xml; */
  /*@ assert file_recovery_new.calculated_file_size == 0; */
  /*@ assert file_recovery_new.file_size == 0;	*/
  /*@ assert file_recovery_new.file_check == \null; */
  /*@ assert file_recovery_new.data_check == \null; */
  /*@ assert file_recovery_new.file_stat->file_hint==&file_hint_fasttxt; */
  {
    file_recovery_t file_recovery_new2;
    file_recovery_new2.blocksize=BLOCKSIZE;
    file_recovery_new2.file_stat=NULL;
    file_recovery_new2.file_check=NULL;
    file_recovery_new2.location.start=BLOCKSIZE;
    file_recovery_new.handle=NULL;	/* In theory should be not null */
#if defined(__FRAMAC__)
    Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif
    /*@ assert valid_read_string((char *)file_recovery_new.filename); */
    header_check_xml_utf16(buffer, BLOCKSIZE, 0, &file_recovery_new, &file_recovery_new2);
  }
  /*@ assert file_recovery_new.file_check == \null; */
  return 0;
}

static int main_xmp()
{
  const char fn[] = "recup_dir.1/f0000000.xmp";
  unsigned char buffer[BLOCKSIZE];
  file_recovery_t file_recovery_new;
  file_recovery_t file_recovery;
  file_stat_t file_stats;

  /*@ assert \valid(buffer + (0 .. (BLOCKSIZE - 1))); */
#if defined(__FRAMAC__)
  Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif

  reset_file_recovery(&file_recovery);
  /*@ assert file_recovery.file_stat == \null; */
  file_recovery.blocksize=BLOCKSIZE;
  reset_file_recovery(&file_recovery_new);
  file_recovery_new.blocksize=BLOCKSIZE;

  file_stats.file_hint=&file_hint_fasttxt;
  file_stats.not_recovered=0;
  file_stats.recovered=0;
#if 0
  register_header_check_fasttxt(&file_stats);
#endif
  if(header_check_xmp(buffer, BLOCKSIZE, 0u, &file_recovery, &file_recovery_new)!=1)
    return 0;
  /*@ assert valid_read_string((char *)&fn); */
  memcpy(file_recovery_new.filename, fn, sizeof(fn));
  file_recovery_new.file_stat=&file_stats;
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  /*@ assert file_recovery_new.extension == extension_xmp; */
  /*@ assert file_recovery_new.calculated_file_size == 0; */
  /*@ assert file_recovery_new.file_size == 0;	*/
  /*@ assert file_recovery_new.file_check == &file_check_size; */
  /*@ assert file_recovery_new.data_check == &data_check_txt; */
  /*@ assert file_recovery_new.file_stat->file_hint==&file_hint_fasttxt; */
  {
    unsigned char big_buffer[2*BLOCKSIZE];
    data_check_t res_data_check=DC_CONTINUE;
    memset(big_buffer, 0, BLOCKSIZE);
    memcpy(big_buffer + BLOCKSIZE, buffer, BLOCKSIZE);
    /*@ assert file_recovery_new.data_check == &data_check_txt; */
    /*@ assert file_recovery_new.file_size == 0; */;
    /*@ assert file_recovery_new.file_size <= file_recovery_new.calculated_file_size; */;
    res_data_check=data_check_txt(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    file_recovery_new.file_size+=BLOCKSIZE;
    if(res_data_check == DC_CONTINUE)
    {
      /*@ assert file_recovery_new.data_check == &data_check_txt; */
      memcpy(big_buffer, big_buffer + BLOCKSIZE, BLOCKSIZE);
#if defined(__FRAMAC__)
      Frama_C_make_unknown((char *)big_buffer + BLOCKSIZE, BLOCKSIZE);
#endif
      data_check_txt(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    }
  }
  {
    file_recovery_t file_recovery_new2;
    file_recovery_new2.blocksize=BLOCKSIZE;
    file_recovery_new2.file_stat=NULL;
    file_recovery_new2.file_check=NULL;
    file_recovery_new2.location.start=BLOCKSIZE;
    file_recovery_new.handle=NULL;	/* In theory should be not null */
#if defined(__FRAMAC__)
    Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif
    /*@ assert valid_read_string((char *)file_recovery_new.filename); */
    header_check_xmp(buffer, BLOCKSIZE, 0, &file_recovery_new, &file_recovery_new2);
  }
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  file_recovery_new.handle=fopen(fn, "rb");
  /*@ assert file_recovery_new.file_check == &file_check_size; */
  if(file_recovery_new.handle!=NULL)
  {
    file_check_size(&file_recovery_new);
    fclose(file_recovery_new.handle);
  }
  return 0;
}

int main()
{
  main_dc();
  main_ers();
  main_fasttxt();
  main_html();
  main_ics();
  main_mbox();
  main_perlm();
  main_rtf();
  main_smail();
  main_snz();
  main_stl();
  main_svg();
  main_thunderbird();
  main_ttd();
  main_txt();
  main_vbm();
  main_xml();
  main_xml_utf8();
  main_xml_utf16();
  main_xmp();
  return 0;
}
#endif
