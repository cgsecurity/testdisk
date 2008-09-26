/*

    File: file_jpg.c

    Copyright (C) 1998-2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#include <stdio.h>
#include "types.h"
#ifdef HAVE_SETJMP_H
#include <setjmp.h>
#endif
#ifdef HAVE_JPEGLIB_H
#include <jpeglib.h>
#endif
#include "filegen.h"
#include "common.h"
#include "log.h"

extern const file_hint_t file_hint_indd;

static void register_header_check_jpg(file_stat_t *file_stat);
static int header_check_jpg(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);
static void file_check_jpg(file_recovery_t *file_recovery);

const file_hint_t file_hint_jpg= {
  .extension="jpg",
  .description="JPG picture",
  .min_header_distance=0,
  .max_filesize=50*1024*1024,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_jpg
};

static const unsigned char jpg_header_app0[4]= { 0xff,0xd8,0xff,0xe0};
static const unsigned char jpg_header_app1[4]= { 0xff,0xd8,0xff,0xe1};
static const unsigned char jpg_header_com[4]= { 0xff,0xd8,0xff,0xfe};
static const unsigned char jpg_footer[2]= { 0xff,0xd9};
static const unsigned char tiff_header_be[4]= { 'M','M',0x00, 0x2a};
static const unsigned char tiff_header_le[4]= { 'I','I',0x2a, 0x00};

struct tiff_entry {
  uint32_t magic;
  uint32_t ifd0_offset;
} __attribute__ ((__packed__));

struct ifd_entry {
  uint16_t tag;
  uint16_t type;
  uint32_t count;
  uint32_t offset;
} __attribute__ ((__packed__));

struct ifd_header {
  uint16_t nbr_fields;
  struct ifd_entry ifd;
} __attribute__ ((__packed__));

static void register_header_check_jpg(file_stat_t *file_stat)
{
  register_header_check(0, jpg_header_app0,sizeof(jpg_header_app0), &header_check_jpg, file_stat);
  register_header_check(0, jpg_header_app1,sizeof(jpg_header_app1), &header_check_jpg, file_stat);
  register_header_check(0, jpg_header_com,sizeof(jpg_header_com), &header_check_jpg, file_stat);
}

static const char *get_date_from_tiff_header_aux(const struct tiff_entry *tiff, const unsigned int tiff_size, const unsigned int tag)
{
  if(tiff_size < sizeof(struct tiff_entry))
    return NULL;
  if(memcmp(&tiff->magic, tiff_header_be, sizeof(tiff_header_be))==0)
  {
    if(tiff_size < be32(tiff->ifd0_offset)+sizeof(struct ifd_entry))
      return NULL;
    {
      const struct ifd_header *ifd0=(const struct ifd_header *)((const char*)tiff + be32(tiff->ifd0_offset));
      const struct ifd_header *ifd1=NULL;
      const struct ifd_entry *ifd;
      unsigned int j;
      for(j=0, ifd=&ifd0->ifd;
	  (const char*)(ifd+1) <= (const char*)tiff+tiff_size && j<be16(ifd0->nbr_fields);
	  j++, ifd++)
      {
	if(be16(ifd->tag)==tag)
	{
	  if(be32(ifd->offset)+19 < tiff_size)
	    return (const char*)tiff+be32(ifd->offset);
	}
	else if(be16(ifd->tag)==0x8769)	/* Exif IFD Pointer */
	{
	  ifd1=(const struct ifd_header *)((const char*)tiff + be32(ifd->offset));
	}
      }
      if(ifd1!=NULL)
      {	/* Exif */
	for(j=0, ifd=&ifd1->ifd;
	    (const char*)(ifd+1) <= (const char*)tiff+tiff_size && j<be16(ifd1->nbr_fields);
	    j++, ifd++)
	{
	  if(be16(ifd->tag)==tag)
	  {
	    if(be32(ifd->offset)+19 < tiff_size)
	      return (const char*)tiff+be32(ifd->offset);
	  }
	}
      }
    }
  }
  else if(memcmp(&tiff->magic, tiff_header_le, sizeof(tiff_header_le))==0)
  {
    if(tiff_size < le32(tiff->ifd0_offset)+sizeof(struct ifd_entry))
      return NULL;
    {
      const struct ifd_header *ifd0=(const struct ifd_header *)((const char*)tiff + le32(tiff->ifd0_offset));
      const struct ifd_header *ifd1=NULL;
      const struct ifd_entry *ifd;
      unsigned int j;
      for(j=0, ifd=&ifd0->ifd;
	   (const char*)(ifd+1) <= (const char*)tiff+tiff_size && j<le16(ifd0->nbr_fields);
	  j++, ifd++)
      {
	if(le16(ifd->tag)==tag)
	{
	  if(le32(ifd->offset)+19 < tiff_size)
	    return (const char*)tiff+le32(ifd->offset);
	}
	else if(le16(ifd->tag)==0x8769)	/* Exif IFD Pointer */
	{
	  ifd1=(const struct ifd_header *)((const char*)tiff + le32(ifd->offset));
	}
      }
      if(ifd1!=NULL)
      {	/* Exif */
	for(j=0, ifd=&ifd1->ifd;
	    (const char*)(ifd+1) <= (const char*)tiff+tiff_size && j<le16(ifd1->nbr_fields);
	    j++, ifd++)
	{
	  if(le16(ifd->tag)==tag)		/* DateTimeOriginal */
	  {
	    if(le32(ifd->offset)+19 < tiff_size)
	      return (const char*)tiff+le32(ifd->offset);
	  }
	}
      }
    }
  }
  return NULL;
}

static time_t get_date_from_tiff_header(const struct tiff_entry *tiff, const unsigned int tiff_size)
{
  const char *date_asc;
  struct tm tm_time;
  /* DateTimeOriginal */
  date_asc=get_date_from_tiff_header_aux(tiff, tiff_size, 0x9003);
  /* DateTimeDigitalized*/
  if(date_asc==NULL)
    date_asc=get_date_from_tiff_header_aux(tiff, tiff_size, 0x9004);
  if(date_asc==NULL)
    date_asc=get_date_from_tiff_header_aux(tiff, tiff_size, 0x132);
  if(date_asc==NULL)
    return (time_t)0;
  memset(&tm_time, 0, sizeof(tm_time));
  tm_time.tm_sec=(date_asc[17]-'0')*10+(date_asc[18]-'0');      /* seconds 0-59 */
  tm_time.tm_min=(date_asc[14]-'0')*10+(date_asc[15]-'0');      /* minutes 0-59 */
  tm_time.tm_hour=(date_asc[11]-'0')*10+(date_asc[12]-'0');     /* hours   0-23*/
  tm_time.tm_mday=(date_asc[8]-'0')*10+(date_asc[9]-'0');	/* day of the month 1-31 */
  tm_time.tm_mon=(date_asc[5]-'0')*10+(date_asc[6]-'0')-1;	/* month 0-11 */
  tm_time.tm_year=(date_asc[0]-'0')*1000+(date_asc[1]-'0')*100+
    (date_asc[2]-'0')*10+(date_asc[3]-'0')-1900;        	/* year */
  tm_time.tm_isdst=-1;       /* unknown daylight saving time */
  return mktime(&tm_time);
}

static int header_check_jpg(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(file_recovery!=NULL && file_recovery->file_stat!=NULL &&
      file_recovery->file_stat->file_hint==&file_hint_indd)
    return 0;
  if(memcmp(buffer,  jpg_header_app0, sizeof(jpg_header_app0))==0 ||
      memcmp(buffer, jpg_header_app1, sizeof(jpg_header_app1))==0 ||
      memcmp(buffer, jpg_header_com,  sizeof(jpg_header_com))==0)
  {
    unsigned int i=2;
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_jpg.extension;
    file_recovery_new->data_check=NULL;
    file_recovery_new->file_check=&file_check_jpg;
    do
    {
      if(buffer[i]==0xff && buffer[i+1]==0xe0)
      { /* APP0 */
	i+=2+(buffer[i+2]<<8)+buffer[i+3];
      }
      else if(buffer[i]==0xff && buffer[i+1]==0xfe)
      { /* COM */
	i+=2+(buffer[i+2]<<8)+buffer[i+3];
      }
      else if(buffer[i]==0xff && buffer[i+1]==0xe1)
      { /* APP1 Exif information */
	if(i+0x0A < buffer_size && 2+(buffer[i+2]<<8)+buffer[i+3] > 0x0A)
	{
	  unsigned int tiff_size=2+(buffer[i+2]<<8)+buffer[i+3]-0x0A;
	  if(buffer_size - (i+0x0A) < tiff_size)
	    tiff_size=buffer_size - (i+0x0A);
	  file_recovery_new->time=get_date_from_tiff_header((const struct tiff_entry *)&buffer[i+0x0A], tiff_size);
	}
	i+=2+(buffer[i+2]<<8)+buffer[i+3];
      }
      else
      {
	file_recovery_new->min_filesize=288;
	return 1;
      }
    } while(i<6*512 && i<buffer_size);
    file_recovery_new->min_filesize=i;
    return 1;
  }
  return 0;
}

#if defined(HAVE_LIBJPEG) && defined(HAVE_JPEGLIB_H)
struct my_error_mgr {
  struct jpeg_error_mgr pub;	/* "public" fields, must be the first field */

  jmp_buf setjmp_buffer;	/* for return to caller */
};

static void my_output_message (j_common_ptr cinfo);
static void my_error_exit (j_common_ptr cinfo);
static void my_emit_message (j_common_ptr cinfo, int msg_level);

static void my_output_message (j_common_ptr cinfo)
{
  struct my_error_mgr *myerr = (struct my_error_mgr *) cinfo->err;
#ifdef DEBUG
  {
    char buffermsg[JMSG_LENGTH_MAX];
    /* Create the message */
    (*cinfo->err->format_message) (cinfo, buffermsg);
    log_error("test_jpeg error %s\n",buffermsg);
  }
#endif
  longjmp(myerr->setjmp_buffer, 1);
}

static void my_error_exit (j_common_ptr cinfo)
{
  struct my_error_mgr *myerr = (struct my_error_mgr *) cinfo->err;
  (*cinfo->err->output_message) (cinfo);
  /* Return control to the setjmp point */
  longjmp(myerr->setjmp_buffer, 1);
}

static void my_emit_message (j_common_ptr cinfo, int msg_level)
{
  struct my_error_mgr *myerr = (struct my_error_mgr *) cinfo->err;
  struct jpeg_error_mgr *err = &myerr->pub;

  if (msg_level < 0) {
    /* It's a warning message.  Since corrupt files may generate many warnings,
     * the policy implemented here is to show only the first warning,
     * unless trace_level >= 3.
     */
    if (err->num_warnings == 0 || err->trace_level >= 3)
      (*err->output_message) (cinfo);
    /* Always count warnings in num_warnings. */
    err->num_warnings++;
    /* Return control to the setjmp point */
    longjmp(myerr->setjmp_buffer, 1);
  } else {
    /* It's a trace message.  Show it if trace_level >= msg_level. */
    if (err->trace_level >= msg_level)
      (*err->output_message) (cinfo);
  }
}

typedef struct {
  struct jpeg_source_mgr pub;	/* public fields */

  FILE * infile;		/* source stream */
  JOCTET * buffer;		/* start of buffer */
  boolean start_of_file;	/* have we gotten any data yet? */
  unsigned long int file_size;
} my_source_mgr;

#define JPG_INPUT_BUF_SIZE  4096	/* choose an efficiently fread'able size */

/*
 * Initialize source --- called by jpeg_read_header
 * before any data is actually read.
 */

static void jpg_init_source (j_decompress_ptr cinfo)
{
  my_source_mgr * src = (my_source_mgr *) cinfo->src;

  /* We reset the empty-input-file flag for each image,
   * but we don't clear the input buffer.
   * This is correct behavior for reading a series of images from one source.
   */
  src->start_of_file = TRUE;
  src->file_size = 0;
}


/*
 * Fill the input buffer --- called whenever buffer is emptied.
 *
 * In typical applications, this should read fresh data into the buffer
 * (ignoring the current state of next_input_byte & bytes_in_buffer),
 * reset the pointer & count to the start of the buffer, and return TRUE
 * indicating that the buffer has been reloaded.  It is not necessary to
 * fill the buffer entirely, only to obtain at least one more byte.
 *
 * There is no such thing as an EOF return.  If the end of the file has been
 * reached, the routine has a choice of ERREXIT() or inserting fake data into
 * the buffer.  In most cases, generating a warning message and inserting a
 * fake EOI marker is the best course of action --- this will allow the
 * decompressor to output however much of the image is there.  However,
 * the resulting error message is misleading if the real problem is an empty
 * input file, so we handle that case specially.
 *
 * In applications that need to be able to suspend compression due to input
 * not being available yet, a FALSE return indicates that no more data can be
 * obtained right now, but more may be forthcoming later.  In this situation,
 * the decompressor will return to its caller (with an indication of the
 * number of scanlines it has read, if any).  The application should resume
 * decompression after it has loaded more data into the input buffer.  Note
 * that there are substantial restrictions on the use of suspension --- see
 * the documentation.
 *
 * When suspending, the decompressor will back up to a convenient restart point
 * (typically the start of the current MCU). next_input_byte & bytes_in_buffer
 * indicate where the restart point will be if the current call returns FALSE.
 * Data beyond this point must be rescanned after resumption, so move it to
 * the front of the buffer rather than discarding it.
 */

static boolean jpg_fill_input_buffer (j_decompress_ptr cinfo)
{
  my_source_mgr * src = (my_source_mgr *) cinfo->src;
  size_t nbytes;
  nbytes = fread(src->buffer, 1, JPG_INPUT_BUF_SIZE, src->infile);
  if (nbytes <= 0) {
    if (src->start_of_file)	/* Treat empty input file as fatal error */
    {
      // (cinfo)->err->msg_code = JERR_INPUT_EMPTY;
      (*(cinfo)->err->error_exit) ((j_common_ptr)cinfo);;
    }
    // cinfo->err->msg_code = JWRN_JPEG_EOF;
    (*(cinfo)->err->emit_message) ((j_common_ptr)cinfo, -1);
    /* Insert a fake EOI marker */
    src->buffer[0] = (JOCTET) 0xFF;
    src->buffer[1] = (JOCTET) JPEG_EOI;
    nbytes = 2;
  }
  src->pub.next_input_byte = src->buffer;
  src->pub.bytes_in_buffer = nbytes;
  src->start_of_file = FALSE;
  src->file_size += nbytes;
  return TRUE;
}


/*
 * Skip data --- used to skip over a potentially large amount of
 * uninteresting data (such as an APPn marker).
 *
 * Writers of suspendable-input applications must note that skip_input_data
 * is not granted the right to give a suspension return.  If the skip extends
 * beyond the data currently in the buffer, the buffer can be marked empty so
 * that the next read will cause a fill_input_buffer call that can suspend.
 * Arranging for additional bytes to be discarded before reloading the input
 * buffer is the application writer's problem.
 */

static void jpg_skip_input_data (j_decompress_ptr cinfo, long num_bytes)
{
  my_source_mgr * src = (my_source_mgr *) cinfo->src;

  /* Just a dumb implementation for now.  Could use fseek() except
   * it doesn't work on pipes.  Not clear that being smart is worth
   * any trouble anyway --- large skips are infrequent.
   */
  if (num_bytes > 0) {
    while (num_bytes > (long) src->pub.bytes_in_buffer) {
      num_bytes -= (long) src->pub.bytes_in_buffer;
      (void) jpg_fill_input_buffer(cinfo);
      /* note we assume that fill_input_buffer will never return FALSE,
       * so suspension need not be handled.
       */
    }
    src->pub.next_input_byte += (size_t) num_bytes;
    src->pub.bytes_in_buffer -= (size_t) num_bytes;
  }
}

/*
 * An additional method that can be provided by data source modules is the
 * resync_to_restart method for error recovery in the presence of RST markers.
 * For the moment, this source module just uses the default resync method
 * provided by the JPEG library.  That method assumes that no backtracking
 * is possible.
 */


/*
 * Terminate source --- called by jpeg_finish_decompress
 * after all data has been read.  Often a no-op.
 *
 * NB: *not* called by jpeg_abort or jpeg_destroy; surrounding
 * application must deal with any cleanup that should happen even
 * for error exit.
 */

static void jpg_term_source (j_decompress_ptr cinfo)
{
  /* no work necessary here */
}


/*
 * Prepare for input from a stdio stream.
 * The caller must have already opened the stream, and is responsible
 * for closing it after finishing decompression.
 */

static void jpeg_testdisk_src (j_decompress_ptr cinfo, FILE * infile)
{
  my_source_mgr * src;

  /* The source object and input buffer are made permanent so that a series
   * of JPEG images can be read from the same file by calling jpeg_testdisk_src
   * only before the first one.  (If we discarded the buffer at the end of
   * one image, we'd likely lose the start of the next one.)
   * This makes it unsafe to use this manager and a different source
   * manager serially with the same JPEG object.  Caveat programmer.
   */
  if (cinfo->src == NULL) {	/* first time for this JPEG object? */
    cinfo->src = (struct jpeg_source_mgr *)
      (*cinfo->mem->alloc_small) ((j_common_ptr) cinfo, JPOOL_PERMANENT,
				  sizeof(my_source_mgr));
    src = (my_source_mgr *) cinfo->src;
    src->buffer = (JOCTET *)
      (*cinfo->mem->alloc_small) ((j_common_ptr) cinfo, JPOOL_PERMANENT,
				  JPG_INPUT_BUF_SIZE * sizeof(JOCTET));
  }

  src = (my_source_mgr *) cinfo->src;
  src->pub.init_source = jpg_init_source;
  src->pub.fill_input_buffer = jpg_fill_input_buffer;
  src->pub.skip_input_data = jpg_skip_input_data;
  src->pub.resync_to_restart = jpeg_resync_to_restart; /* use default method */
  src->pub.term_source = jpg_term_source;
  src->infile = infile;
  src->pub.bytes_in_buffer = 0; /* forces fill_input_buffer on first read */
  src->pub.next_input_byte = NULL; /* until buffer loaded */
}
#endif

static void file_check_jpg(file_recovery_t *file_recovery)
{
  FILE* infile=file_recovery->handle;
  uint64_t jpeg_size;
#if defined(HAVE_LIBJPEG) && defined(HAVE_JPEGLIB_H)
  static struct my_error_mgr jerr;
  static struct jpeg_decompress_struct cinfo;
#endif
  file_recovery->file_size=0;
  file_recovery->offset_error=0;
#if defined(HAVE_LIBJPEG) && defined(HAVE_JPEGLIB_H)
  {
    JSAMPARRAY buffer;		/* Output row buffer */
    int row_stride;		/* physical row width in output buffer */
    fseek(infile,0,SEEK_SET);
    cinfo.err = jpeg_std_error(&jerr.pub);
    jerr.pub.output_message = my_output_message;
    jerr.pub.error_exit = my_error_exit;
    jerr.pub.emit_message= my_emit_message;
    // jerr.pub.emit_message = my_emit_message;
    /* Establish the setjmp return context for my_error_exit to use. */
    if (setjmp(jerr.setjmp_buffer)) 
    {
      /* If we get here, the JPEG code has signaled an error.
       * We need to clean up the JPEG object and return.
       */
      /* Not accurate */
      // jpeg_size=ftell(infile);
      my_source_mgr * src;
      src = (my_source_mgr *) cinfo.src;
      jpeg_size=src->file_size - src->pub.bytes_in_buffer;
      // log_error("JPG error at offset %llu\n", (long long unsigned)jpeg_size);
      jpeg_destroy_decompress(&cinfo);
      if(jpeg_size>0)
	file_recovery->offset_error=jpeg_size;
      return;
    }
    jpeg_create_decompress(&cinfo);
    cinfo.two_pass_quantize = FALSE;
    cinfo.dither_mode = JDITHER_NONE;
    cinfo.desired_number_of_colors = 0;
    cinfo.dct_method = JDCT_FASTEST;
    cinfo.do_fancy_upsampling = FALSE;
    cinfo.raw_data_out = TRUE;

    jpeg_testdisk_src(&cinfo, infile);
    (void) jpeg_read_header(&cinfo, TRUE);
    (void) jpeg_start_decompress(&cinfo);
    row_stride = cinfo.output_width * cinfo.output_components;
    buffer = (*cinfo.mem->alloc_sarray)
      ((j_common_ptr) &cinfo, JPOOL_IMAGE, row_stride, 1);
    while (cinfo.output_scanline < cinfo.output_height) {
      (void) jpeg_read_scanlines(&cinfo, buffer, 1);
    }
    (void) jpeg_finish_decompress(&cinfo);
    {
      my_source_mgr * src;
      src = (my_source_mgr *) cinfo.src;
      jpeg_size=src->file_size - src->pub.bytes_in_buffer;
    }
    jpeg_destroy_decompress(&cinfo);
  }
#else
  /* Not accurate */
  jpeg_size=ftell(infile);
#endif
//    log_error("JPG size: %llu\n", (long long unsigned)jpeg_size);
  if(jpeg_size<=0)
    return;
#if defined(HAVE_LIBJPEG) && defined(HAVE_JPEGLIB_H)
  if(jerr.pub.num_warnings>0)
  {
    file_recovery->offset_error=jpeg_size;
    return;
  }
#endif
  file_recovery->file_size=jpeg_size;
  file_search_footer(file_recovery, jpg_footer,sizeof(jpg_footer));
}
