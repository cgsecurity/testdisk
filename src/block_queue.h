/*
    File: block_queue.h

    Copyright (C) 2024 TestDisk contributors

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

    Thread-safe ring buffer for passing disk blocks from an I/O producer
    thread to one or more signature-scanning consumer threads.
*/
#ifndef _BLOCK_QUEUE_H
#define _BLOCK_QUEUE_H
#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STDINT_H
#include <stdint.h>
#else
#include <inttypes.h>
#endif

/* One entry in the ring buffer.
 * 'data' points into a pre-allocated pool owned by the block_queue_t.
 * Consumers must not free or modify 'data' — it becomes invalid after the
 * next call to block_queue_push() that reuses the same slot.
 * Copy the data before releasing the entry if longer lifetime is needed. */
typedef struct {
	unsigned char	*data;		/* pointer into the queue's buffer pool   */
	uint64_t	 offset;	/* disk byte-offset this block came from  */
	unsigned int	 size;		/* number of valid bytes in data[]        */
	int		 is_last;	/* sentinel: no more blocks will be pushed */
} block_entry_t;

/* Opaque ring-buffer handle */
typedef struct block_queue block_queue_t;

/*
 * block_queue_create - allocate a ring buffer holding 'capacity' slots,
 * each pre-allocated at 'block_size' bytes.
 * Returns NULL on allocation failure.
 */
block_queue_t *block_queue_create(unsigned int capacity,
				  unsigned int block_size);

/*
 * block_queue_push - copy 'size' bytes from 'data' into the next free slot
 * and record the disk 'offset'.  Blocks (sleeps) if the queue is full.
 * Returns 0 on success, -1 if the queue has been destroyed or size exceeds
 * block_size.
 * Do NOT call after block_queue_signal_done().
 */
int block_queue_push(block_queue_t *q, const unsigned char *data,
		     uint64_t offset, unsigned int size);

/*
 * block_queue_pop - retrieve the next available entry into *entry.
 * Blocks if the queue is empty.
 * Returns 0 on success.  When entry->is_last is set the queue is exhausted;
 * further calls to block_queue_pop() will keep returning the sentinel.
 * Returns -1 if q is NULL.
 */
int block_queue_pop(block_queue_t *q, block_entry_t *entry);

/*
 * block_queue_signal_done - called by the producer when no more blocks will
 * be pushed.  Wakes all blocked consumers so they can drain the queue and
 * observe the is_last sentinel.
 */
void block_queue_signal_done(block_queue_t *q);

/*
 * block_queue_destroy - free all resources.  Call only after all producer
 * and consumer threads have finished using the queue.
 */
void block_queue_destroy(block_queue_t *q);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif /* _BLOCK_QUEUE_H */
