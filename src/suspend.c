/*

    File: suspend.c
    A suspending/resuming memory manager for libjpeg
    NOT COMPATIBLE WITH libjpeg-turbo

    Copyright (C) 2009 Christophe GRENIER <grenier@cgsecurity.org>
    Copyright (C) 2008 Michael Cohen <scudette@users.sourceforge.net>, part of pyflag
  
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
 
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif

// This should be large enough to handle most memory requests. On
// linux it can be rediculously large because the system will only
// actually allocate the memory when we write on it.
#define POOL_SIZE 4 * 1024 * 1024

#define AM_MEMORY_MANAGER	/* we define jvirt_Xarray_control structs */
#ifdef HAVE_JPEGLIB_H
#ifdef __MINGW32__
#ifndef HAVE_BOOLEAN
#define HAVE_BOOLEAN
typedef int boolean;
#endif
#endif
#include <jpeglib.h>
#endif
#include "types.h"
#include "common.h"
#include "log.h"

#if defined(HAVE_LIBJPEG) && defined(HAVE_JPEGLIB_H)
static void *alloc_small(j_common_ptr cinfo, int pool_id, size_t sizeofobject);

struct my_memory_mgr {
  struct jpeg_memory_mgr pub;	/* public fields */

  // This is for libjpegs benefit:
  jvirt_sarray_ptr virt_sarray_list;
  jvirt_barray_ptr virt_barray_list;
  JDIMENSION last_rowsperchunk;	/* from most recent alloc_sarray/barray */

  // All memory is allocated to this pool.
  char *pool;
  char *shadow_pool;

  // A highwater mark for pool allocations
  long pool_size;

  // This is the very end of the allocated pool.
  long total_space_allocated;
  long total_space_shadowed;

};

typedef struct my_memory_mgr *my_mem_ptr;
#include "jerror.h"
#include "suspend.h"

#ifndef ALIGN_TYPE		/* so can override from jconfig.h */
#define ALIGN_TYPE  double
#endif

#ifndef MAX_ALLOC_CHUNK		/* may be overridden in jconfig.h */
#define MAX_ALLOC_CHUNK  1000000000L
#endif

#define SIZEOF sizeof

/*
 * The control blocks for virtual arrays.
 * Note that these blocks are allocated in the "small" pool area.
 * System-dependent info for the associated backing store (if any) is hidden
 * inside the backing_store_info struct.
 */

struct jvirt_sarray_control {
  JSAMPARRAY mem_buffer;	/* => the in-memory buffer */
  JDIMENSION rows_in_array;	/* total virtual array height */
  JDIMENSION samplesperrow;	/* width of array (and of memory buffer) */
  JDIMENSION maxaccess;		/* max rows accessed by access_virt_sarray */
  JDIMENSION rows_in_mem;	/* height of memory buffer */
  JDIMENSION rowsperchunk;	/* allocation chunk size in mem_buffer */
  JDIMENSION cur_start_row;	/* first logical row # in the buffer */
  JDIMENSION first_undef_row;	/* row # of first uninitialized row */
  boolean pre_zero;		/* pre-zero mode requested? */
  boolean dirty;		/* do current buffer contents need written? */
  boolean b_s_open;		/* is backing-store data valid? */
  jvirt_sarray_ptr next;	/* link to next virtual sarray control block */
};

struct jvirt_barray_control {
  JBLOCKARRAY mem_buffer;	/* => the in-memory buffer */
  JDIMENSION rows_in_array;	/* total virtual array height */
  JDIMENSION blocksperrow;	/* width of array (and of memory buffer) */
  JDIMENSION maxaccess;		/* max rows accessed by access_virt_barray */
  JDIMENSION rows_in_mem;	/* height of memory buffer */
  JDIMENSION rowsperchunk;	/* allocation chunk size in mem_buffer */
  JDIMENSION cur_start_row;	/* first logical row # in the buffer */
  JDIMENSION first_undef_row;	/* row # of first uninitialized row */
  boolean pre_zero;		/* pre-zero mode requested? */
  boolean dirty;		/* do current buffer contents need written? */
  boolean b_s_open;		/* is backing-store data valid? */
  jvirt_barray_ptr next;	/* link to next virtual barray control block */
};

static void *alloc_small (j_common_ptr cinfo, int pool_id, size_t sizeofobject) {
  struct my_memory_mgr *self = (struct my_memory_mgr *)(cinfo->mem);
  char *obj_ptr = self->pool + self->total_space_allocated;

  //  log_info("allocating %u bytes\n", sizeofobject);

  self->total_space_allocated += sizeofobject;
  if(self->total_space_allocated > self->pool_size)
  {
    log_critical("suspend.c: no memory left\n");
    return NULL;
  }

  return obj_ptr;
}

METHODDEF(JSAMPARRAY) alloc_sarray (j_common_ptr cinfo, int pool_id, 
				    JDIMENSION samplesperrow, JDIMENSION numrows) {
  JSAMPARRAY result;
  JDIMENSION i;
  result = (JSAMPARRAY) alloc_small(cinfo, pool_id, (size_t) (numrows * SIZEOF(JSAMPROW)));
  
  for(i=0; i<numrows; i++) {
    result[i] = (JSAMPROW) alloc_small(cinfo, pool_id, 
				       (size_t) ((size_t) samplesperrow * SIZEOF(JSAMPLE)));
  }
  return result;
}


METHODDEF(jvirt_sarray_ptr) request_virt_sarray (j_common_ptr cinfo, int pool_id, boolean pre_zero,
						 JDIMENSION samplesperrow, JDIMENSION numrows,
						 JDIMENSION maxaccess) {
  my_mem_ptr mem = (my_mem_ptr) cinfo->mem;
  jvirt_sarray_ptr result;
  
  result = (jvirt_sarray_ptr) alloc_small(cinfo, pool_id,
					  SIZEOF(struct jvirt_sarray_control));
  result->mem_buffer = NULL;
  result->rows_in_array = numrows;
  result->samplesperrow = samplesperrow;
  result->maxaccess = maxaccess;
  result->pre_zero = pre_zero;
  result->b_s_open = FALSE;
  result->next = mem->virt_sarray_list;
  mem->virt_sarray_list = result;  
  return result;
};

METHODDEF(void) realize_virt_arrays (j_common_ptr cinfo) {
  my_mem_ptr mem = (my_mem_ptr) cinfo->mem;
  long space_per_minheight, maximum_space, avail_mem;
  long minheights, max_minheights;
  jvirt_sarray_ptr sptr;
  jvirt_barray_ptr bptr;
  
  space_per_minheight = 0;
  maximum_space = 0;
  for (sptr = mem->virt_sarray_list; sptr != NULL; sptr = sptr->next) {
    if (sptr->mem_buffer == NULL) { /* if not realized yet */
      space_per_minheight += (long) sptr->maxaccess *
	(long) sptr->samplesperrow * SIZEOF(JSAMPLE);
      maximum_space += (long) sptr->rows_in_array *
	(long) sptr->samplesperrow * SIZEOF(JSAMPLE);
    }
  }
  for (bptr = mem->virt_barray_list; bptr != NULL; bptr = bptr->next) {
    if (bptr->mem_buffer == NULL) { /* if not realized yet */
      space_per_minheight += (long) bptr->maxaccess *
	(long) bptr->blocksperrow * SIZEOF(JBLOCK);
      maximum_space += (long) bptr->rows_in_array *
	(long) bptr->blocksperrow * SIZEOF(JBLOCK);
    }
  }
  
  if (space_per_minheight <= 0)
    return;			/* no unrealized arrays, no work */
  
  /* Determine amount of memory to actually use */
  avail_mem = maximum_space;
  max_minheights = 1000000000L;
  
  /* Allocate the in-memory buffers and initialize backing store as needed. */
  for (sptr = mem->virt_sarray_list; sptr != NULL; sptr = sptr->next) {
    if (sptr->mem_buffer == NULL) { /* if not realized yet */
      minheights = ((long) sptr->rows_in_array - 1L) / sptr->maxaccess + 1L;
      sptr->rows_in_mem = sptr->rows_in_array;
      sptr->mem_buffer = alloc_sarray(cinfo, JPOOL_IMAGE,
				      sptr->samplesperrow, sptr->rows_in_mem);
      sptr->rowsperchunk = mem->last_rowsperchunk;
      sptr->cur_start_row = 0;
      sptr->first_undef_row = 0;
      sptr->dirty = FALSE;
    }
  }
  
  for (bptr = mem->virt_barray_list; bptr != NULL; bptr = bptr->next) {
    if (bptr->mem_buffer == NULL) { /* if not realized yet */
      minheights = ((long) bptr->rows_in_array - 1L) / bptr->maxaccess + 1L;
      bptr->rows_in_mem = bptr->rows_in_array;
      bptr->mem_buffer = (JBLOCKARRAY)alloc_sarray(cinfo, JPOOL_IMAGE,
				      bptr->blocksperrow, bptr->rows_in_mem);
      bptr->rowsperchunk = mem->last_rowsperchunk;
      bptr->cur_start_row = 0;
      bptr->first_undef_row = 0;
      bptr->dirty = FALSE;
    }
  }
}

METHODDEF(JSAMPARRAY) access_virt_sarray (j_common_ptr cinfo, jvirt_sarray_ptr ptr,
					  JDIMENSION start_row, JDIMENSION num_rows,
					  boolean writable) {  
  if (writable)
    ptr->dirty = TRUE;
  return ptr->mem_buffer + (start_row - ptr->cur_start_row);
}

METHODDEF(void) free_pool (j_common_ptr cinfo, int pool_id) {
  struct my_memory_mgr *self = (struct my_memory_mgr *)(cinfo->mem);
  //  log_info("Freeing pool\n");
  //  self->total_space_allocated = 0;
}

METHODDEF(void) self_destruct (j_common_ptr cinfo) {
  struct my_memory_mgr *self = (struct my_memory_mgr *)(cinfo->mem);
  //log_info("Destroying pool\n");
  //free(self->pool);
  //free(self->shadow_pool);
}

void suspend_memory(j_common_ptr cinfo) {
  struct my_memory_mgr *self = (struct my_memory_mgr *)(cinfo->mem);
  
//  log_info("Suspending at sector %u\n", sector);
  memcpy(self->shadow_pool, self->pool, self->total_space_allocated);
  self->total_space_shadowed = self->total_space_allocated;
};

int resume_memory(j_common_ptr cinfo)
{
  struct my_memory_mgr *self = (struct my_memory_mgr *)(cinfo->mem);
//  log_info("Resuming from sector %u (copying %lu bytes)\n", self->sector, self->total_space_shadowed);
  memcpy(self->pool, self->shadow_pool, self->total_space_shadowed);
  self->total_space_allocated = self->total_space_shadowed;
  return 0;
};

GLOBAL(void) jinit_memory_mgr (j_common_ptr cinfo);
GLOBAL(void) jinit_memory_mgr (j_common_ptr cinfo)
{
  static my_mem_ptr mem=NULL;
  long max_to_use;
  size_t test_mac;
  
  cinfo->mem = NULL;
  if ((SIZEOF(ALIGN_TYPE) & (SIZEOF(ALIGN_TYPE)-1)) != 0)
    ERREXIT(cinfo, JERR_BAD_ALIGN_TYPE);
  test_mac = (size_t) MAX_ALLOC_CHUNK;
  if ((long) test_mac != MAX_ALLOC_CHUNK ||
      (MAX_ALLOC_CHUNK % SIZEOF(ALIGN_TYPE)) != 0)
    ERREXIT(cinfo, JERR_BAD_ALLOC_CHUNK);

  max_to_use = 0;
  if(mem == NULL)
    mem = (struct my_memory_mgr *)MALLOC(sizeof(struct my_memory_mgr));

  // Prepare our memory pools:
  if(mem->pool == NULL)
    mem->pool = (char *)MALLOC(POOL_SIZE);
  if(mem->shadow_pool == NULL)
    mem->shadow_pool = (char *)MALLOC(POOL_SIZE);
  mem->pool_size = POOL_SIZE;

  /* OK, fill in the method pointers */
  mem->pub.alloc_small = alloc_small;
  mem->pub.alloc_large = alloc_small;
  mem->pub.alloc_sarray = alloc_sarray;
  mem->pub.alloc_barray = alloc_sarray;

  mem->pub.request_virt_sarray = request_virt_sarray;
  mem->pub.request_virt_barray = request_virt_sarray;
  mem->pub.realize_virt_arrays = realize_virt_arrays;
  mem->pub.access_virt_sarray = access_virt_sarray;
  mem->pub.access_virt_barray = access_virt_sarray;
  mem->pub.free_pool = free_pool;
  mem->pub.self_destruct = self_destruct;

  /* Make MAX_ALLOC_CHUNK accessible to other modules */
  mem->pub.max_alloc_chunk = MAX_ALLOC_CHUNK;
  
  /* Initialize working state */
  mem->pub.max_memory_to_use = max_to_use;
  mem->virt_sarray_list = NULL;
  mem->virt_barray_list = NULL;
  mem->total_space_allocated = SIZEOF(struct my_memory_mgr);

  /* Declare ourselves open for business */
  cinfo->mem = & mem->pub;
}
#endif
