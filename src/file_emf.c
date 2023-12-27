/*

    File: file_emf.c

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
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_emf)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "filegen.h"
#include "log.h"
#include "common.h"
#if defined(__FRAMAC__)
#include "__fc_builtin.h"
#endif

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_emf(file_stat_t *file_stat);

const file_hint_t file_hint_emf= {
  .extension="emf",
  .description="Windows Enhanced MetaFile",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_emf
};

typedef struct {
  uint32_t iType;
  uint32_t nSize;
} U_EMR;

typedef struct {
  int32_t left;
  int32_t top;
  int32_t right;
  int32_t bottom;
} U_RECTL;

typedef struct {
  int32_t cx;
  int32_t cy;
} U_SIZEL;

struct EMF_HDR
{
  U_EMR emr;
  U_RECTL rclBounds;
  U_RECTL rclFrame;
  uint32_t dSignature;
  uint32_t nVersion;
  uint32_t nBytes;
  uint32_t nRecords;
  uint16_t nHandles;
  uint16_t sReserved;
  uint32_t nDescription;
  uint32_t offDescription;
  uint32_t nPalEntries;
  U_SIZEL szlDevice;
  U_SIZEL szlMillimeters;
} __attribute__ ((gcc_struct, __packed__));

#define EMR_HEADER	1
#define EMR_POLYBEZIER	2
#define EMR_POLYGON	3
#define EMR_POLYLINE	4
#define EMR_POLYBEZIERTO	5
#define EMR_POLYLINETO	6
#define EMR_POLYPOLYLINE	7
#define EMR_POLYPOLYGON	8
#define EMR_SETWINDOWEXTEX	9
#define EMR_SETWINDOWORGEX	10
#define EMR_SETVIEWPORTEXTEX	11
#define EMR_SETVIEWPORTORGEX	12
#define EMR_SETBRUSHORGEX	13
#define EMR_EOF	14
#define EMR_SETPIXELV	15
#define EMR_SETMAPPERFLAGS	16
#define EMR_SETMAPMODE	17
#define EMR_SETBKMODE	18
#define EMR_SETPOLYFILLMODE	19
#define EMR_SETROP2	20
#define EMR_SETSTRETCHBLTMODE	21
#define EMR_SETTEXTALIGN	22
#define EMR_SETCOLORADJUSTMENT	23
#define EMR_SETTEXTCOLOR	24
#define EMR_SETBKCOLOR	25
#define EMR_OFFSETCLIPRGN	26
#define EMR_MOVETOEX	27
#define EMR_SETMETARGN	28
#define EMR_EXCLUDECLIPRECT	29
#define EMR_INTERSECTCLIPRECT	30
#define EMR_SCALEVIEWPORTEXTEX	31
#define EMR_SCALEWINDOWEXTEX	32
#define EMR_SAVEDC	33
#define EMR_RESTOREDC	34
#define EMR_SETWORLDTRANSFORM	35
#define EMR_MODIFYWORLDTRANSFORM	36
#define EMR_SELECTOBJECT	37
#define EMR_CREATEPEN	38
#define EMR_CREATEBRUSHINDIRECT	39
#define EMR_DELETEOBJECT	40
#define EMR_ANGLEARC	41
#define EMR_ELLIPSE	42
#define EMR_RECTANGLE	43
#define EMR_ROUNDRECT	44
#define EMR_ARC	45
#define EMR_CHORD	46
#define EMR_PIE	47
#define EMR_SELECTPALETTE	48
#define EMR_CREATEPALETTE	49
#define EMR_SETPALETTEENTRIES	50
#define EMR_RESIZEPALETTE	51
#define EMR_REALIZEPALETTE	52
#define EMR_EXTFLOODFILL	53
#define EMR_LINETO	54
#define EMR_ARCTO	55
#define EMR_POLYDRAW	56
#define EMR_SETARCDIRECTION	57
#define EMR_SETMITERLIMIT	58
#define EMR_BEGINPATH	59
#define EMR_ENDPATH	60
#define EMR_CLOSEFIGURE	61
#define EMR_FILLPATH	62
#define EMR_STROKEANDFILLPATH	63
#define EMR_STROKEPATH	64
#define EMR_FLATTENPATH	65
#define EMR_WIDENPATH	66
#define EMR_SELECTCLIPPATH	67
#define EMR_ABORTPATH	68
#define EMR_GDICOMMENT	70
#define EMR_FILLRGN	71
#define EMR_FRAMERGN	72
#define EMR_INVERTRGN	73
#define EMR_PAINTRGN	74
#define EMR_EXTSELECTCLIPRGN	75
#define EMR_BITBLT	76
#define EMR_STRETCHBLT	77
#define EMR_MASKBLT	78
#define EMR_PLGBLT	79
#define EMR_SETDIBITSTODEVICE	80
#define EMR_STRETCHDIBITS	81
#define EMR_EXTCREATEFONTINDIRECTW	82
#define EMR_EXTTEXTOUTA	83
#define EMR_EXTTEXTOUTW	84
#define EMR_POLYBEZIER16	85
#define EMR_POLYGON16	86
#define EMR_POLYLINE16	87
#define EMR_POLYBEZIERTO16	88
#define EMR_POLYLINETO16	89
#define EMR_POLYPOLYLINE16	90
#define EMR_POLYPOLYGON16	91
#define EMR_POLYDRAW16	92
#define EMR_CREATEMONOBRUSH	93
#define EMR_CREATEDIBPATTERNBRUSHPT	94
#define EMR_EXTCREATEPEN	95
#define EMR_POLYTEXTOUTA	96
#define EMR_POLYTEXTOUTW	97
#define EMR_SETICMMODE	98
#define EMR_CREATECOLORSPACE	99
#define EMR_SETCOLORSPACE	100
#define EMR_DELETECOLORSPACE	101
#define EMR_GLSRECORD	102
#define EMR_GLSBOUNDEDRECORD	103
#define EMR_PIXELFORMAT 104
#define EMR_DRAWESCAPE 	105
#define EMR_EXTESCAPE	106
#define EMR_STARTDOC	107
#define EMR_SMALLTEXTOUT	108
#define EMR_FORCEUFIMAPPING	109
#define EMR_NAMEDESCAPE	110
#define EMR_COLORCORRECTPALETTE	111
#define EMR_SETICMPROFILEA	112
#define EMR_SETICMPROFILEW	113
#define EMR_ALPHABLEND	114
#define EMR_SETLAYOUT	115
#define EMR_TRANSPARENTBLT	116
#define EMR_RESERVED_117	117
#define EMR_GRADIENTFILL	118
#define EMR_SETLINKEDUFI	119
#define EMR_SETTEXTJUSTIFICATION	120
#define EMR_COLORMATCHTOTARGETW	121
#define EMR_CREATECOLORSPACEW	122

/*@
  @ requires file_recovery->data_check==&data_check_emf;
  @ requires buffer_size >= 2;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ terminates \true;
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ assigns file_recovery->calculated_file_size;
  @*/
static data_check_t data_check_emf(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@
    @ loop assigns file_recovery->calculated_file_size;
    @ loop variant file_recovery->file_size + buffer_size/2 - (file_recovery->calculated_file_size + 8);
    @*/
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 8 < file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size + buffer_size/2 - file_recovery->file_size;
    /*@ assert 0 <= i < buffer_size - 8 ; */
    const U_EMR *hdr=(const U_EMR *)&buffer[i];
    const unsigned int itype=le32(hdr->iType);
    const unsigned int atom_size=le32(hdr->nSize);
#ifdef DEBUG_EMF
    log_trace("0x%llx ", (long long unsigned)file_recovery->calculated_file_size);
    switch(itype)
    {
      case EMR_HEADER:			log_trace("EMR_HEADER"); break;
      case EMR_POLYBEZIER:		log_trace("EMR_POLYBEZIER"); break;
      case EMR_POLYGON:			log_trace("EMR_POLYGON"); break;
      case EMR_POLYLINE:		log_trace("EMR_POLYLINE"); break;
      case EMR_POLYBEZIERTO:		log_trace("EMR_POLYBEZIERTO"); break;
      case EMR_POLYLINETO:		log_trace("EMR_POLYLINETO"); break;
      case EMR_POLYPOLYLINE:		log_trace("EMR_POLYPOLYLINE"); break;
      case EMR_POLYPOLYGON:		log_trace("EMR_POLYPOLYGON"); break;
      case EMR_SETWINDOWEXTEX:		log_trace("EMR_SETWINDOWEXTEX"); break;
      case EMR_SETWINDOWORGEX:		log_trace("EMR_SETWINDOWORGEX"); break;
      case EMR_SETVIEWPORTEXTEX:	log_trace("EMR_SETVIEWPORTEXTEX"); break;
      case EMR_SETVIEWPORTORGEX:	log_trace("EMR_SETVIEWPORTORGEX"); break;
      case EMR_SETBRUSHORGEX:		log_trace("EMR_SETBRUSHORGEX"); break;
      case EMR_EOF:			log_trace("EMR_EOF"); break;
      case EMR_SETPIXELV:		log_trace("EMR_SETPIXELV"); break;
      case EMR_SETMAPPERFLAGS:		log_trace("EMR_SETMAPPERFLAGS"); break;
      case EMR_SETMAPMODE:		log_trace("EMR_SETMAPMODE"); break;
      case EMR_SETBKMODE:		log_trace("EMR_SETBKMODE"); break;
      case EMR_SETPOLYFILLMODE:		log_trace("EMR_SETPOLYFILLMODE"); break;
      case EMR_SETROP2:			log_trace("EMR_SETROP2"); break;
      case EMR_SETSTRETCHBLTMODE:	log_trace("EMR_SETSTRETCHBLTMODE"); break;
      case EMR_SETTEXTALIGN:		log_trace("EMR_SETTEXTALIGN"); break;
      case EMR_SETCOLORADJUSTMENT:	log_trace("EMR_SETCOLORADJUSTMENT"); break;
      case EMR_SETTEXTCOLOR:		log_trace("EMR_SETTEXTCOLOR"); break;
      case EMR_SETBKCOLOR:		log_trace("EMR_SETBKCOLOR"); break;
      case EMR_OFFSETCLIPRGN:		log_trace("EMR_OFFSETCLIPRGN"); break;
      case EMR_MOVETOEX:		log_trace("EMR_MOVETOEX"); break;
      case EMR_SETMETARGN:		log_trace("EMR_SETMETARGN"); break;
      case EMR_EXCLUDECLIPRECT:		log_trace("EMR_EXCLUDECLIPRECT"); break;
      case EMR_INTERSECTCLIPRECT:	log_trace("EMR_INTERSECTCLIPRECT"); break;
      case EMR_SCALEVIEWPORTEXTEX:	log_trace("EMR_SCALEVIEWPORTEXTEX"); break;
      case EMR_SCALEWINDOWEXTEX:	log_trace("EMR_SCALEWINDOWEXTEX"); break;
      case EMR_SAVEDC:			log_trace("EMR_SAVEDC"); break;
      case EMR_RESTOREDC:		log_trace("EMR_RESTOREDC"); break;
      case EMR_SETWORLDTRANSFORM:	log_trace("EMR_SETWORLDTRANSFORM"); break;
      case EMR_MODIFYWORLDTRANSFORM:	log_trace("EMR_MODIFYWORLDTRANSFORM"); break;
      case EMR_SELECTOBJECT:		log_trace("EMR_SELECTOBJECT"); break;
      case EMR_CREATEPEN:		log_trace("EMR_CREATEPEN"); break;
      case EMR_CREATEBRUSHINDIRECT:	log_trace("EMR_CREATEBRUSHINDIRECT"); break;
      case EMR_DELETEOBJECT:		log_trace("EMR_DELETEOBJECT"); break;
      case EMR_ANGLEARC:		log_trace("EMR_ANGLEARC"); break;
      case EMR_ELLIPSE:			log_trace("EMR_ELLIPSE"); break;
      case EMR_RECTANGLE:		log_trace("EMR_RECTANGLE"); break;
      case EMR_ROUNDRECT:		log_trace("EMR_ROUNDRECT"); break;
      case EMR_ARC:			log_trace("EMR_ARC"); break;
      case EMR_CHORD:			log_trace("EMR_CHORD"); break;
      case EMR_PIE:			log_trace("EMR_PIE"); break;
      case EMR_SELECTPALETTE:		log_trace("EMR_SELECTPALETTE"); break;
      case EMR_CREATEPALETTE:		log_trace("EMR_CREATEPALETTE"); break;
      case EMR_SETPALETTEENTRIES:	log_trace("EMR_SETPALETTEENTRIES"); break;
      case EMR_RESIZEPALETTE:		log_trace("EMR_RESIZEPALETTE"); break;
      case EMR_REALIZEPALETTE:		log_trace("EMR_REALIZEPALETTE"); break;
      case EMR_EXTFLOODFILL:		log_trace("EMR_EXTFLOODFILL"); break;
      case EMR_LINETO:			log_trace("EMR_LINETO"); break;
      case EMR_ARCTO:			log_trace("EMR_ARCTO"); break;
      case EMR_POLYDRAW:		log_trace("EMR_POLYDRAW"); break;
      case EMR_SETARCDIRECTION:		log_trace("EMR_SETARCDIRECTION"); break;
      case EMR_SETMITERLIMIT:		log_trace("EMR_SETMITERLIMIT"); break;
      case EMR_BEGINPATH:		log_trace("EMR_BEGINPATH"); break;
      case EMR_ENDPATH:			log_trace("EMR_ENDPATH"); break;
      case EMR_CLOSEFIGURE:		log_trace("EMR_CLOSEFIGURE"); break;
      case EMR_FILLPATH:		log_trace("EMR_FILLPATH"); break;
      case EMR_STROKEANDFILLPATH:	log_trace("EMR_STROKEANDFILLPATH"); break;
      case EMR_STROKEPATH:		log_trace("EMR_STROKEPATH"); break;
      case EMR_FLATTENPATH:		log_trace("EMR_FLATTENPATH"); break;
      case EMR_WIDENPATH:		log_trace("EMR_WIDENPATH"); break;
      case EMR_SELECTCLIPPATH:		log_trace("EMR_SELECTCLIPPATH"); break;
      case EMR_ABORTPATH:		log_trace("EMR_ABORTPATH"); break;
      case EMR_GDICOMMENT:		log_trace("EMR_GDICOMMENT"); break;
      case EMR_FILLRGN:			log_trace("EMR_FILLRGN"); break;
      case EMR_FRAMERGN:		log_trace("EMR_FRAMERGN"); break;
      case EMR_INVERTRGN:		log_trace("EMR_INVERTRGN"); break;
      case EMR_PAINTRGN:		log_trace("EMR_PAINTRGN"); break;
      case EMR_EXTSELECTCLIPRGN:	log_trace("EMR_EXTSELECTCLIPRGN"); break;
      case EMR_BITBLT:			log_trace("EMR_BITBLT"); break;
      case EMR_STRETCHBLT:		log_trace("EMR_STRETCHBLT"); break;
      case EMR_MASKBLT:			log_trace("EMR_MASKBLT"); break;
      case EMR_PLGBLT:			log_trace("EMR_PLGBLT"); break;
      case EMR_SETDIBITSTODEVICE:	log_trace("EMR_SETDIBITSTODEVICE"); break;
      case EMR_STRETCHDIBITS:		log_trace("EMR_STRETCHDIBITS"); break;
      case EMR_EXTCREATEFONTINDIRECTW:	log_trace("EMR_EXTCREATEFONTINDIRECTW"); break;
      case EMR_EXTTEXTOUTA:		log_trace("EMR_EXTTEXTOUTA"); break;
      case EMR_EXTTEXTOUTW:		log_trace("EMR_EXTTEXTOUTW"); break;
      case EMR_POLYBEZIER16:		log_trace("EMR_POLYBEZIER16"); break;
      case EMR_POLYGON16:		log_trace("EMR_POLYGON16"); break;
      case EMR_POLYLINE16:		log_trace("EMR_POLYLINE16"); break;
      case EMR_POLYBEZIERTO16:		log_trace("EMR_POLYBEZIERTO16"); break;
      case EMR_POLYLINETO16:		log_trace("EMR_POLYLINETO16"); break;
      case EMR_POLYPOLYLINE16:		log_trace("EMR_POLYPOLYLINE16"); break;
      case EMR_POLYPOLYGON16:		log_trace("EMR_POLYPOLYGON16"); break;
      case EMR_POLYDRAW16:		log_trace("EMR_POLYDRAW16"); break;
      case EMR_CREATEMONOBRUSH:		log_trace("EMR_CREATEMONOBRUSH"); break;
      case EMR_CREATEDIBPATTERNBRUSHPT:	log_trace("EMR_CREATEDIBPATTERNBRUSHPT"); break;
      case EMR_EXTCREATEPEN:		log_trace("EMR_EXTCREATEPEN"); break;
      case EMR_POLYTEXTOUTA:		log_trace("EMR_POLYTEXTOUTA"); break;
      case EMR_POLYTEXTOUTW:		log_trace("EMR_POLYTEXTOUTW"); break;
      case EMR_SETICMMODE:		log_trace("EMR_SETICMMODE"); break;
      case EMR_CREATECOLORSPACE:	log_trace("EMR_CREATECOLORSPACE"); break;
      case EMR_SETCOLORSPACE:		log_trace("EMR_SETCOLORSPACE"); break;
      case EMR_DELETECOLORSPACE:	log_trace("EMR_DELETECOLORSPACE"); break;
      case EMR_GLSRECORD:		log_trace("EMR_GLSRECORD"); break;
      case EMR_GLSBOUNDEDRECORD:	log_trace("EMR_GLSBOUNDEDRECORD"); break;
      case EMR_PIXELFORMAT:		log_trace("EMR_PIXELFORMAT"); break;
      case EMR_DRAWESCAPE :		log_trace("EMR_DRAWESCAPE "); break;
      case EMR_EXTESCAPE:		log_trace("EMR_EXTESCAPE"); break;
      case EMR_STARTDOC:		log_trace("EMR_STARTDOC"); break;
      case EMR_SMALLTEXTOUT:		log_trace("EMR_SMALLTEXTOUT"); break;
      case EMR_FORCEUFIMAPPING:		log_trace("EMR_FORCEUFIMAPPING"); break;
      case EMR_NAMEDESCAPE:		log_trace("EMR_NAMEDESCAPE"); break;
      case EMR_COLORCORRECTPALETTE:	log_trace("EMR_COLORCORRECTPALETTE"); break;
      case EMR_SETICMPROFILEA:		log_trace("EMR_SETICMPROFILEA"); break;
      case EMR_SETICMPROFILEW:		log_trace("EMR_SETICMPROFILEW"); break;
      case EMR_ALPHABLEND:		log_trace("EMR_ALPHABLEND"); break;
      case EMR_SETLAYOUT:		log_trace("EMR_SETLAYOUT"); break;
      case EMR_TRANSPARENTBLT:		log_trace("EMR_TRANSPARENTBLT"); break;
      case EMR_RESERVED_117:		log_trace("EMR_RESERVED_117"); break;
      case EMR_GRADIENTFILL:		log_trace("EMR_GRADIENTFILL"); break;
      case EMR_SETLINKEDUFI:		log_trace("EMR_SETLINKEDUFI"); break;
      case EMR_SETTEXTJUSTIFICATION:	log_trace("EMR_SETTEXTJUSTIFICATION"); break;
      case EMR_COLORMATCHTOTARGETW:	log_trace("EMR_COLORMATCHTOTARGETW"); break;
      case EMR_CREATECOLORSPACEW:	log_trace("EMR_CREATECOLORSPACEW"); break;
    }
    log_trace(" (%08x) \t%08x\n", itype, atom_size);
#endif
      if(atom_size<8 || atom_size%4!=0 || atom_size>1024*1024)
	return DC_ERROR;
      /*@ assert 8 <= atom_size <= 1024*1024; */
      file_recovery->calculated_file_size+=(uint64_t)atom_size;
      if(itype==EMR_EOF)
	return DC_STOP;
      /*@ assert file_recovery->calculated_file_size < file_recovery->file_size + buffer_size/2 - 8 + 1024*1024; */
  }
  return DC_CONTINUE;
}

/*@
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ ensures (\result == 1) ==> (file_recovery_new->extension == file_hint_emf.extension);
  @ ensures (\result == 1) ==> (file_recovery_new->time == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->calculated_file_size >= 0x34);
  @ ensures (\result == 1) ==> (file_recovery_new->file_size == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->min_filesize == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->data_check == &data_check_emf);
  @ ensures (\result == 1) ==> (file_recovery_new->file_check == &file_check_size);
  @ ensures (\result == 1) ==> (file_recovery_new->file_rename== \null);
  @ assigns *file_recovery_new;
  @*/
static int header_check_emf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  static const unsigned char emf_header[4]= { 0x01, 0x00, 0x00, 0x00};
  const struct EMF_HDR *hdr=(const struct EMF_HDR *)buffer;
  const unsigned int atom_size=le32(hdr->emr.nSize);
  if(buffer_size < sizeof(struct EMF_HDR))
    return 0;
  if(memcmp(buffer,emf_header,sizeof(emf_header))==0 &&
      le32(hdr->nBytes) >= 88 &&
      le16(hdr->sReserved)==0 &&
      atom_size>=0x34 && atom_size%4==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_emf.extension;
    if(file_recovery_new->blocksize >= 8)
    {
      file_recovery_new->data_check=&data_check_emf;
      file_recovery_new->file_check=&file_check_size;
      file_recovery_new->calculated_file_size=atom_size;
    }
    return 1;
  }
  return 0;
}

static void register_header_check_emf(file_stat_t *file_stat)
{
  static const unsigned char emf_sign[4]= { ' ','E', 'M','F'};
  register_header_check(0x28, emf_sign,sizeof(emf_sign), &header_check_emf, file_stat);
}
#endif

#if defined(MAIN_emf)
#define BLOCKSIZE 65536u
int main()
{
  const char fn[] = "recup_dir.1/f0000000.emf";
  unsigned char buffer[BLOCKSIZE];
  file_recovery_t file_recovery_new;
  file_recovery_t file_recovery;
  file_stat_t file_stats;

  /*@ assert \valid(buffer + (0 .. (BLOCKSIZE - 1))); */
#if defined(__FRAMAC__)
  Frama_C_make_unknown((char *)buffer, BLOCKSIZE);
#endif

  reset_file_recovery(&file_recovery);
  file_recovery.blocksize=BLOCKSIZE;
  file_recovery_new.blocksize=BLOCKSIZE;
  file_recovery_new.data_check=NULL;
  file_recovery_new.file_stat=NULL;
  file_recovery_new.file_check=NULL;
  file_recovery_new.file_rename=NULL;
  file_recovery_new.calculated_file_size=0;
  file_recovery_new.file_size=0;
  file_recovery_new.location.start=0;

  file_stats.file_hint=&file_hint_emf;
  file_stats.not_recovered=0;
  file_stats.recovered=0;
  register_header_check_emf(&file_stats);
  if(header_check_emf(buffer, BLOCKSIZE, 0u, &file_recovery, &file_recovery_new)!=1)
    return 0;
  /*@ assert file_recovery_new.file_size == 0;	*/
  /*@ assert file_recovery_new.calculated_file_size > 0;	*/
  /*@ assert file_recovery_new.data_check == &data_check_emf; */
  /*@ assert file_recovery_new.file_check == &file_check_size; */
  /*@ assert file_recovery_new.file_rename == \null; */
  /*@ assert file_recovery_new.extension == file_hint_emf.extension; */
  /*@ assert valid_read_string(file_recovery_new.extension); */
  /*@ assert \separated(&file_recovery_new, file_recovery_new.extension); */
  /*@ assert valid_read_string((char *)&fn); */
  memcpy(file_recovery_new.filename, fn, sizeof(fn));
  /*@ assert valid_read_string((char *)&file_recovery_new.filename); */
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  /*X TODO assert valid_read_string(file_recovery_new.extension); */
  file_recovery_new.file_stat=&file_stats;
  {
    unsigned char big_buffer[2*BLOCKSIZE];
    data_check_t res_data_check=DC_CONTINUE;
    memset(big_buffer, 0, BLOCKSIZE);
    memcpy(big_buffer + BLOCKSIZE, buffer, BLOCKSIZE);
    /*@ assert file_recovery_new.data_check == &data_check_emf; */
    /*@ assert file_recovery_new.file_size == 0; */;
    /*@ assert file_recovery_new.file_size <= file_recovery_new.calculated_file_size; */;
    res_data_check=data_check_emf(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    file_recovery_new.file_size+=BLOCKSIZE;
    if(res_data_check == DC_CONTINUE)
    {
      memcpy(big_buffer, big_buffer + BLOCKSIZE, BLOCKSIZE);
#if defined(__FRAMAC__)
      Frama_C_make_unknown((char *)big_buffer + BLOCKSIZE, BLOCKSIZE);
#endif
      data_check_emf(big_buffer, 2*BLOCKSIZE, &file_recovery_new);
    }
  }
  {
    file_recovery_t file_recovery_new2;
    /* Test when another file of the same is detected in the next block */
    file_recovery_new2.blocksize=BLOCKSIZE;
    file_recovery_new2.file_stat=NULL;
    file_recovery_new2.file_check=NULL;
    file_recovery_new2.location.start=BLOCKSIZE;
    file_recovery_new.handle=NULL;	/* In theory should be not null */
    header_check_emf(buffer, BLOCKSIZE, 0, &file_recovery_new, &file_recovery_new2);
    /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  }
  /*@ assert valid_read_string((char *)file_recovery_new.filename); */
  {
    file_recovery_new.handle=fopen(fn, "rb");
    if(file_recovery_new.handle!=NULL)
    {
      file_check_size(&file_recovery_new);
      fclose(file_recovery_new.handle);
    }
  }
  return 0;
}
#endif
