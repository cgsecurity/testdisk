/*

    File: file_ape.c

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
#include <stdio.h>
#include "types.h"
#include "filegen.h"
#include "common.h"

static void register_header_check_ape(file_stat_t *file_stat);
static int header_check_ape(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_ape= {
  .extension="ape",
  .description="Monkey's Audio compressed format",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_ape
};


/* cf https://github.com/fernandotcl/monkeys-audio/blob/master/src/MACLib/APEHeader.h */
struct APE_COMMON_HEADER
{
  char cID[4];		/* should equal 'MAC ' */
  uint16_t nVersion;	/* version number * 1000 (3.81 = 3810) */
};

/*****************************************************************************************
 * APE header structure for old APE files (3.97 and earlier)
 * *****************************************************************************************/
struct APE_HEADER_OLD
{
  char cID[4];			// should equal 'MAC '
  uint16_t nVersion;		// version number * 1000 (3.81 = 3810)
  uint16_t nCompressionLevel;	// the compression level
  uint16_t nFormatFlags;	// any format flags (for future use)
  uint16_t nChannels;		// the number of channels (1 or 2)
  uint32_t nSampleRate;		// the sample rate (typically 44100)
  uint32_t nHeaderBytes;	// the bytes after the MAC header that compose the WAV header
  uint32_t nTerminatingBytes;	// the bytes after that raw data (for extended info)
  uint32_t nTotalFrames;	// the number of frames in the file
  uint32_t nFinalFrameBlocks;	// the number of samples in the final frame
};

/*****************************************************************************************
 * APE_DESCRIPTOR structure (file header that describes lengths, offsets, etc.)
 * *****************************************************************************************/
struct APE_DESCRIPTOR
{
  char cID[4];				// should equal 'MAC '
  uint16_t nVersion;			// version number * 1000 (3.81 = 3810)
  uint16_t pack1;
  uint32_t nDescriptorBytes;		// the number of descriptor bytes (allows later expansion of this header)
  uint32_t nHeaderBytes;		// the number of header APE_HEADER bytes
  uint32_t nSeekTableBytes;		// the number of bytes of the seek table
  uint32_t nHeaderDataBytes;		// the number of header data bytes (from original file)
  uint64_t nAPEFrameDataBytes;		// the number of bytes of APE frame data
  uint32_t nTerminatingDataBytes;	// the terminating data of the file (not including tag data)
  uint8_t cFileMD5[16];			// the MD5 hash of the file (see notes for usage... it's a littly tricky)
} __attribute__ ((__packed__));

/*****************************************************************************************
 * APE_HEADER structure (describes the format, duration, etc. of the APE file)
 * *****************************************************************************************/
struct APE_HEADER
{
  uint16_t nCompressionLevel;	// the compression level (see defines I.E. COMPRESSION_LEVEL_FAST)
  uint16_t nFormatFlags;	// any format flags (for future use)
  uint32_t nBlocksPerFrame;	// the number of audio blocks in one frame
  uint32_t nFinalFrameBlocks;	// the number of audio blocks in the final frame
  uint32_t nTotalFrames;	// the total number of frames
  uint16_t nBitsPerSample;	// the bits per sample (typically 16)
  uint16_t nChannels;		// the number of channels (1 or 2)
  uint32_t nSampleRate;		// the sample rate (typically 44100)
};

static int header_check_ape(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct APE_HEADER_OLD *ape=(const struct APE_HEADER_OLD*)buffer;
  /* Version 3.96 released April 7, 2002, Version 4.06 March 17, 2009 */
  if(le16(ape->nVersion)>=3980)
  {
    const struct APE_DESCRIPTOR *descr=(const struct APE_DESCRIPTOR*)buffer;
    const struct APE_HEADER *apeh=(const struct APE_HEADER*)&buffer[le32(descr->nDescriptorBytes)];
    if(le32(descr->nDescriptorBytes) < sizeof(struct APE_DESCRIPTOR))
      return 0;
    if(le32(descr->nHeaderDataBytes) > 0 && le32(descr->nHeaderDataBytes) < sizeof(struct APE_HEADER))
      return 0;
    if(le32(descr->nDescriptorBytes) >= buffer_size)
      return 0;
    if(le32(descr->nDescriptorBytes) + sizeof(struct APE_HEADER) >= buffer_size)
      return 0;
    if(le16(apeh->nChannels)<1 || le16(apeh->nChannels)>2)
      return 0;
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_ape.extension;
    return 1;
  }
  if(le16(ape->nChannels)<1 || le16(ape->nChannels)>2)
    return 0;
  if(le32(ape->nSampleRate)==0)
    return 0;
  if(le32(ape->nTotalFrames)==0)
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_ape.extension;
  /* 4 + le32(ape->nHeaderBytes) + le32(ape->nTerminatingDataBytes) ? */
  return 1;
}

static void register_header_check_ape(file_stat_t *file_stat)
{
  static const unsigned char ape_header[4]= { 'M', 'A', 'C', ' '};
  register_header_check(0, ape_header,sizeof(ape_header), &header_check_ape, file_stat);
}
