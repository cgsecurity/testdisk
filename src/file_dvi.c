/*

    File: file_dvi.c

    Copyright (C) 2016 Christophe GRENIER <grenier@cgsecurity.org>

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

static void register_header_check_dvi(file_stat_t *file_stat);

const file_hint_t file_hint_dvi= {
  .extension="dvi",
  .description="TeX DVI",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_dvi
};

static int header_check_dvi(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_dvi.extension;
  file_recovery_new->min_filesize=15+buffer[0x14];	/* 15 + comment size */
  return 1;
}

static void register_header_check_dvi(file_stat_t *file_stat)
{
  static const unsigned char dvi_header[12]=  {
    0xf7,			// pre
    0x02,			// version 2
    				// There are exactly 7227 TeX points in 254 centimeters,
				// and TeX82 works with scaled points where there are 2^16 sp in a point,
				// so TeX82 sets the following values
    0x01, 0x83, 0x92, 0xc0,	// num=0x018392c0=25400000
    0x1c, 0x3b, 0x00, 0x00,	// den=0x1c3b0000=7227*2^16=473628672
    				// mag
				// comment size
				// comment
  };
  register_header_check(0, dvi_header, sizeof(dvi_header), &header_check_dvi, file_stat);
}
