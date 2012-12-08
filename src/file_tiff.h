/*

    File: file_tiff.h

    Copyright (C) 2009 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifdef __cplusplus
extern "C" {
#endif

#define TIFF_BIGENDIAN          	0x4d4d
#define TIFF_LITTLEENDIAN       	0x4949
#define TIFFTAG_IMAGEDESCRIPTION        270     /* info about image */
#define TIFFTAG_MAKE                    271     /* scanner manufacturer name */
#define TIFFTAG_MODEL                   272     /* scanner model name/number */
#define	TIFFTAG_STRIPOFFSETS		273	/* offsets to data strips */
#define	TIFFTAG_STRIPBYTECOUNTS		279	/* bytes counts for strips */
#define TIFFTAG_TILEOFFSETS		324
#define TIFFTAG_TILEBYTECOUNTS		325
#define TIFFTAG_SUBIFD                  330
#define	TIFFTAG_JPEGIFOFFSET		513	/* !pointer to SOI marker */
#define	TIFFTAG_JPEGIFBYTECOUNT		514	/* !JFIF stream length */
#define TIFFTAG_KODAKIFD 		33424
#define TIFFTAG_EXIFIFD                 34665
#define EXIFTAG_MAKERNOTE		37500	/* Manufacturer notes */
#define TIFFTAG_IMAGEOFFSET		0xbcc0
#define TIFFTAG_IMAGEBYTECOUNT		0xbcc1
#define TIFFTAG_ALPHAOFFSET		0xbcc2
#define TIFFTAG_ALPHABYTECOUNT		0xbcc3
#define TIFFTAG_PRINTIM			50341
#define TIFFTAG_DNGVERSION		50706
#define TIFFTAG_DNGPRIVATEDATA		50740	/* &manufacturer's private data */

typedef struct {
        uint16_t  tiff_magic;     /* magic number (defines byte order) */
        uint16_t  tiff_version;   /* TIFF version number */
        uint32_t  tiff_diroff;    /* byte offset to first directory */
} TIFFHeader;

typedef struct {
        uint16_t          tdir_tag;       /* see below */
        uint16_t          tdir_type;      /* data type; see below */
        uint32_t          tdir_count;     /* number of items; length in spec */
        uint32_t          tdir_offset;    /* byte offset to field data */
} TIFFDirEntry;

struct ifd_header {
  uint16_t nbr_fields;
  TIFFDirEntry ifd;
} __attribute__ ((__packed__));

time_t get_date_from_tiff_header(const TIFFHeader *tiff, const unsigned int tiff_size);
const char *find_tag_from_tiff_header(const TIFFHeader *tiff, const unsigned int tiff_size, const unsigned int tag, const char **potential_error);
void file_check_tiff(file_recovery_t *file_recovery);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
