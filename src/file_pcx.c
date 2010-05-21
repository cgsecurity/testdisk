/*

    File: file_pcx.c

    Copyright (C) 2006-2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include "common.h"
#ifdef DEBUG_PCX
#include "log.h"
#endif

static void register_header_check_pcx(file_stat_t *file_stat);
static int header_check_pcx(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_pcx= {
  .extension="pcx",
  .description="PCX bitmap image",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_pcx
};

static const unsigned char pcx_header[1]= {0x0a};
struct pcx_file_entry {
  uint8_t  Manufacturer; /* should always be 0Ah		*/
  uint8_t  Version;
  /* Version
   * 0x00  PCX ver. 2.5 image data
   * 0x02  PCX ver. 2.8 image data, with palette
   * 0x03  PCX ver. 2.8 image data, without palette
   * 0x04  PCX for Windows image data
   * 0x05  PCX ver. 3.0 image data
   */
  uint8_t  Encoding;	/* 0: uncompressed, 1: RLE compressed */
  uint8_t  BitsPerPixel;
  uint16_t XMin; 	/* image width = XMax-XMin	*/
  uint16_t YMin; 	/* image height = YMax-YMin	*/
  uint16_t XMax;
  uint16_t YMax;
  uint16_t VertDPI;
  uint8_t  Palette[48];
  uint8_t  Reserved;
  uint8_t  ColorPlanes;
  /* 4 -- 16 colors
   * 3 -- 24 bit color (16.7 million colors)
   */
  uint16_t BytesPerLine;
  uint16_t PaletteType;
  uint16_t HScrSize; 	/* only supported by		*/
  uint16_t VScrSize; 	/* PC Paintbrush IV or higher 	*/
  uint8_t  Filler[56];
} __attribute__ ((__packed__));

static void register_header_check_pcx(file_stat_t *file_stat)
{
  register_header_check(0, pcx_header,sizeof(pcx_header), &header_check_pcx, file_stat);
}

static int header_check_pcx(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct pcx_file_entry *pcx=(const struct pcx_file_entry *)buffer;
  if(pcx->Manufacturer==0x0a &&
      (pcx->Version<=5 && pcx->Version!=1) &&
      pcx->Encoding <=1 &&
      (pcx->BitsPerPixel==1 || pcx->BitsPerPixel==4 ||
       pcx->BitsPerPixel==8 || pcx->BitsPerPixel==24) &&
      pcx->Reserved==0 &&
      le16(pcx->XMin) <= le16(pcx->XMax) &&
      le16(pcx->YMin) <= le16(pcx->YMax) &&
      pcx->BytesPerLine>0 && pcx->BytesPerLine%2==0 &&
      pcx->Filler[0]==0 && pcx->Filler[1]==0 &&
      pcx->Filler[54]==0 && pcx->Filler[55]==0)
  {
    reset_file_recovery(file_recovery_new);
#ifdef DEBUG_PCX
    log_info("X %u-%u, Y %u-%u\n",
	le16(pcx->XMin), le16(pcx->XMax),
	le16(pcx->YMin), le16(pcx->YMax));
    log_info("ColorPlanes %u\n", pcx->ColorPlanes);
    log_info("BytesPerLine %u - %u\n", pcx->BytesPerLine, (le16(pcx->XMax)-le16(pcx->XMin)+1)*pcx->BitsPerPixel/8);
#endif
    file_recovery_new->extension=file_hint_pcx.extension;
    return 1;
  }
  return 0;
}

