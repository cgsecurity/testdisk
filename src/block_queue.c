/*
    File: block_queue.c

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

    Thread-safe ring buffer implementation.  The queue pre-allocates all
    block buffers up front to avoid per-push malloc() overhead on the hot
    I/O path.

    When HAVE_PTHREAD is not defined the push/pop calls run synchronously
    and the whole queue degenerates to a single-slot pass-through so that
    callers compile and function without any threading support.
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
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include "block_queue.h"

#ifdef HAVE_PTHREAD
#include <pthread.h>

/* -----------------------------------------------------------------------
 * Internal slot — one element of the ring buffer
 * ----------------------------------------------------------------------- */
typedef struct {
	unsigned char	*data;		/* pre-allocated buffer of block_size bytes */
	uint64_t	 offset;	/* disk offset recorded at push time        */
	unsigned int	 size;		/* number of valid bytes written by producer */
	int		 is_last;	/* sentinel flag set by signal_done()        */
} ring_slot_t;

/* -----------------------------------------------------------------------
 * Block queue structure
 * ----------------------------------------------------------------------- */
struct block_queue {
	ring_slot_t	*slots;		/* ring buffer array [0..capacity-1]  */
	unsigned int	 capacity;	/* total number of slots              */
	unsigned int	 block_size;	/* bytes allocated per slot           */

	unsigned int	 head;		/* consumer reads from here           */
	unsigned int	 tail;		/* producer writes to here            */
	unsigned int	 count;		/* slots currently filled             */

	int		 done;		/* set by signal_done()               */

	pthread_mutex_t	 mutex;
	pthread_cond_t	 not_empty;	/* signalled when count > 0 or done   */
	pthread_cond_t	 not_full;	/* signalled when count < capacity    */
};

/* -----------------------------------------------------------------------
 * Public API — threaded implementation
 * ----------------------------------------------------------------------- */

block_queue_t *block_queue_create(unsigned int capacity,
				  unsigned int block_size)
{
	unsigned int i;
	block_queue_t *q;

	if (capacity == 0 || block_size == 0)
		return NULL;

	q = (block_queue_t *)malloc(sizeof(block_queue_t));
	if (q == NULL)
		return NULL;

	memset(q, 0, sizeof(block_queue_t));
	q->capacity   = capacity;
	q->block_size = block_size;

	q->slots = (ring_slot_t *)malloc(capacity * sizeof(ring_slot_t));
	if (q->slots == NULL) {
		free(q);
		return NULL;
	}
	memset(q->slots, 0, capacity * sizeof(ring_slot_t));

	/* pre-allocate data buffers for every slot */
	for (i = 0; i < capacity; i++) {
		q->slots[i].data = (unsigned char *)malloc(block_size);
		if (q->slots[i].data == NULL) {
			/* free already-allocated buffers then bail */
			while (i-- > 0)
				free(q->slots[i].data);
			free(q->slots);
			free(q);
			return NULL;
		}
	}

	if (pthread_mutex_init(&q->mutex, NULL) != 0) {
		for (i = 0; i < capacity; i++)
			free(q->slots[i].data);
		free(q->slots);
		free(q);
		return NULL;
	}
	if (pthread_cond_init(&q->not_empty, NULL) != 0) {
		pthread_mutex_destroy(&q->mutex);
		for (i = 0; i < capacity; i++)
			free(q->slots[i].data);
		free(q->slots);
		free(q);
		return NULL;
	}
	if (pthread_cond_init(&q->not_full, NULL) != 0) {
		pthread_cond_destroy(&q->not_empty);
		pthread_mutex_destroy(&q->mutex);
		for (i = 0; i < capacity; i++)
			free(q->slots[i].data);
		free(q->slots);
		free(q);
		return NULL;
	}

	return q;
}

int block_queue_push(block_queue_t *q, const unsigned char *data,
		     uint64_t offset, unsigned int size)
{
	ring_slot_t *slot;

	if (q == NULL || data == NULL)
		return -1;
	if (size > q->block_size)
		return -1;

	pthread_mutex_lock(&q->mutex);

	/* block producer while ring buffer is full */
	while (q->count >= q->capacity && !q->done)
		pthread_cond_wait(&q->not_full, &q->mutex);

	if (q->done) {
		/* queue is being shut down — refuse new data */
		pthread_mutex_unlock(&q->mutex);
		return -1;
	}

	slot           = &q->slots[q->tail];
	memcpy(slot->data, data, size);
	slot->offset   = offset;
	slot->size     = size;
	slot->is_last  = 0;

	q->tail = (q->tail + 1) % q->capacity;
	q->count++;

	pthread_cond_signal(&q->not_empty);
	pthread_mutex_unlock(&q->mutex);

	return 0;
}

int block_queue_pop(block_queue_t *q, block_entry_t *entry)
{
	ring_slot_t *slot;

	if (q == NULL || entry == NULL)
		return -1;

	pthread_mutex_lock(&q->mutex);

	/* block consumer until data is available or the producer is done */
	while (q->count == 0 && !q->done)
		pthread_cond_wait(&q->not_empty, &q->mutex);

	if (q->count == 0) {
		/* done flag set and queue drained — return sentinel */
		entry->data    = NULL;
		entry->offset  = 0;
		entry->size    = 0;
		entry->is_last = 1;
		pthread_mutex_unlock(&q->mutex);
		return 0;
	}

	slot = &q->slots[q->head];
	/* hand the caller a direct pointer into our pre-allocated buffer;
	 * the caller must not hold it past the next push() on this slot */
	entry->data    = slot->data;
	entry->offset  = slot->offset;
	entry->size    = slot->size;
	entry->is_last = 0;

	q->head  = (q->head + 1) % q->capacity;
	q->count--;

	pthread_cond_signal(&q->not_full);
	pthread_mutex_unlock(&q->mutex);

	return 0;
}

void block_queue_signal_done(block_queue_t *q)
{
	if (q == NULL)
		return;

	pthread_mutex_lock(&q->mutex);
	q->done = 1;
	/* wake all blocked consumers so they can observe the done flag */
	pthread_cond_broadcast(&q->not_empty);
	/* wake any blocked producer that is waiting on not_full */
	pthread_cond_broadcast(&q->not_full);
	pthread_mutex_unlock(&q->mutex);
}

void block_queue_destroy(block_queue_t *q)
{
	unsigned int i;

	if (q == NULL)
		return;

	pthread_cond_destroy(&q->not_full);
	pthread_cond_destroy(&q->not_empty);
	pthread_mutex_destroy(&q->mutex);

	for (i = 0; i < q->capacity; i++)
		free(q->slots[i].data);
	free(q->slots);
	free(q);
}

#else /* !HAVE_PTHREAD — synchronous single-slot fallback */

/* -----------------------------------------------------------------------
 * Without pthreads the "queue" is a single heap-allocated slot.
 * push() copies data into it; pop() returns a pointer to that buffer.
 * signal_done() marks it exhausted.  No blocking ever occurs.
 * ----------------------------------------------------------------------- */
struct block_queue {
	unsigned char	*data;
	unsigned int	 block_size;
	uint64_t	 offset;
	unsigned int	 size;
	int		 has_data;	/* 1 if push() wrote something not yet pop()'d */
	int		 done;
};

block_queue_t *block_queue_create(unsigned int capacity,
				  unsigned int block_size)
{
	block_queue_t *q;
	(void)capacity;

	if (block_size == 0)
		return NULL;

	q = (block_queue_t *)malloc(sizeof(block_queue_t));
	if (q == NULL)
		return NULL;

	q->data = (unsigned char *)malloc(block_size);
	if (q->data == NULL) {
		free(q);
		return NULL;
	}
	q->block_size = block_size;
	q->has_data   = 0;
	q->done       = 0;
	return q;
}

int block_queue_push(block_queue_t *q, const unsigned char *data,
		     uint64_t offset, unsigned int size)
{
	if (q == NULL || data == NULL || size > q->block_size)
		return -1;
	memcpy(q->data, data, size);
	q->offset   = offset;
	q->size     = size;
	q->has_data = 1;
	return 0;
}

int block_queue_pop(block_queue_t *q, block_entry_t *entry)
{
	if (q == NULL || entry == NULL)
		return -1;

	if (!q->has_data || q->done) {
		entry->data    = NULL;
		entry->offset  = 0;
		entry->size    = 0;
		entry->is_last = 1;
		return 0;
	}

	entry->data    = q->data;
	entry->offset  = q->offset;
	entry->size    = q->size;
	entry->is_last = 0;
	q->has_data    = 0;
	return 0;
}

void block_queue_signal_done(block_queue_t *q)
{
	if (q != NULL)
		q->done = 1;
}

void block_queue_destroy(block_queue_t *q)
{
	if (q == NULL)
		return;
	free(q->data);
	free(q);
}

#endif /* HAVE_PTHREAD */
