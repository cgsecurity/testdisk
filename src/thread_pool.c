/*
    File: thread_pool.c

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

    Portable POSIX thread pool for parallelising PhotoRec block scanning.
    All threading code is guarded by HAVE_PTHREAD; without pthreads every
    submitted task runs synchronously in the calling thread so the rest of
    the codebase compiles and works unchanged.
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
#include "thread_pool.h"

/* Maximum tasks that can be queued before submit() blocks */
#define THREAD_POOL_QUEUE_CAPACITY 1024

#ifdef HAVE_PTHREAD
#include <pthread.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

/* -----------------------------------------------------------------------
 * Internal task node — singly-linked list used as the pending-task queue
 * ----------------------------------------------------------------------- */
typedef struct task_node {
	thread_task_fn		fn;
	void			*arg;
	struct task_node	*next;
} task_node_t;

/* -----------------------------------------------------------------------
 * Thread pool structure
 * ----------------------------------------------------------------------- */
struct thread_pool {
	pthread_t		*threads;       /* worker thread handles          */
	unsigned int		num_threads;    /* number of worker threads        */

	/* task queue */
	task_node_t		*head;          /* oldest queued task              */
	task_node_t		*tail;          /* newest queued task              */
	unsigned int		queue_size;     /* current number of queued tasks  */

	/* synchronisation */
	pthread_mutex_t		mutex;
	pthread_cond_t		not_empty;      /* signalled when a task is added  */
	pthread_cond_t		not_full;       /* signalled when a task is taken  */
	pthread_cond_t		all_done;       /* signalled when pending == 0     */

	/* in-flight counter: queued + currently executing */
	unsigned int		pending;

	/* shutdown flag */
	int			shutdown;
};

/* -----------------------------------------------------------------------
 * Worker thread entry point
 * ----------------------------------------------------------------------- */
static void *worker_thread(void *arg)
{
	thread_pool_t *pool = (thread_pool_t *)arg;

	for (;;) {
		task_node_t *node;

		pthread_mutex_lock(&pool->mutex);

		/* wait until there is work or we are asked to shut down */
		while (pool->queue_size == 0 && !pool->shutdown)
			pthread_cond_wait(&pool->not_empty, &pool->mutex);

		if (pool->shutdown && pool->queue_size == 0) {
			pthread_mutex_unlock(&pool->mutex);
			break;
		}

		/* dequeue the oldest task */
		node = pool->head;
		pool->head = node->next;
		if (pool->head == NULL)
			pool->tail = NULL;
		pool->queue_size--;

		/* wake a blocked producer if the queue was full */
		pthread_cond_signal(&pool->not_full);
		pthread_mutex_unlock(&pool->mutex);

		/* execute task outside the lock */
		node->fn(node->arg);
		free(node);

		/* decrement the in-flight counter and wake thread_pool_wait() */
		pthread_mutex_lock(&pool->mutex);
		pool->pending--;
		if (pool->pending == 0)
			pthread_cond_broadcast(&pool->all_done);
		pthread_mutex_unlock(&pool->mutex);
	}

	return NULL;
}

/* -----------------------------------------------------------------------
 * Public API — threaded implementation
 * ----------------------------------------------------------------------- */

thread_pool_t *thread_pool_create(unsigned int num_threads)
{
	unsigned int i;
	thread_pool_t *pool;

	if (num_threads == 0)
		num_threads = 1;

	pool = (thread_pool_t *)malloc(sizeof(thread_pool_t));
	if (pool == NULL)
		return NULL;

	memset(pool, 0, sizeof(thread_pool_t));
	pool->num_threads = num_threads;

	if (pthread_mutex_init(&pool->mutex, NULL) != 0) {
		free(pool);
		return NULL;
	}
	if (pthread_cond_init(&pool->not_empty, NULL) != 0) {
		pthread_mutex_destroy(&pool->mutex);
		free(pool);
		return NULL;
	}
	if (pthread_cond_init(&pool->not_full, NULL) != 0) {
		pthread_cond_destroy(&pool->not_empty);
		pthread_mutex_destroy(&pool->mutex);
		free(pool);
		return NULL;
	}
	if (pthread_cond_init(&pool->all_done, NULL) != 0) {
		pthread_cond_destroy(&pool->not_full);
		pthread_cond_destroy(&pool->not_empty);
		pthread_mutex_destroy(&pool->mutex);
		free(pool);
		return NULL;
	}

	pool->threads = (pthread_t *)malloc(num_threads * sizeof(pthread_t));
	if (pool->threads == NULL) {
		pthread_cond_destroy(&pool->all_done);
		pthread_cond_destroy(&pool->not_full);
		pthread_cond_destroy(&pool->not_empty);
		pthread_mutex_destroy(&pool->mutex);
		free(pool);
		return NULL;
	}

	for (i = 0; i < num_threads; i++) {
		if (pthread_create(&pool->threads[i], NULL, worker_thread, pool) != 0) {
			/* signal already-created threads to shut down */
			pthread_mutex_lock(&pool->mutex);
			pool->shutdown = 1;
			pthread_cond_broadcast(&pool->not_empty);
			pthread_mutex_unlock(&pool->mutex);
			while (i-- > 0)
				pthread_join(pool->threads[i], NULL);
			free(pool->threads);
			pthread_cond_destroy(&pool->all_done);
			pthread_cond_destroy(&pool->not_full);
			pthread_cond_destroy(&pool->not_empty);
			pthread_mutex_destroy(&pool->mutex);
			free(pool);
			return NULL;
		}
	}

	return pool;
}

int thread_pool_submit(thread_pool_t *pool, thread_task_fn fn, void *arg)
{
	task_node_t *node;

	if (pool == NULL || fn == NULL)
		return -1;

	node = (task_node_t *)malloc(sizeof(task_node_t));
	if (node == NULL)
		return -1;
	node->fn   = fn;
	node->arg  = arg;
	node->next = NULL;

	pthread_mutex_lock(&pool->mutex);

	/* block producer while queue is at capacity */
	while (pool->queue_size >= THREAD_POOL_QUEUE_CAPACITY && !pool->shutdown)
		pthread_cond_wait(&pool->not_full, &pool->mutex);

	if (pool->shutdown) {
		pthread_mutex_unlock(&pool->mutex);
		free(node);
		return -1;
	}

	/* enqueue */
	if (pool->tail == NULL)
		pool->head = node;
	else
		pool->tail->next = node;
	pool->tail = node;
	pool->queue_size++;
	pool->pending++;   /* includes tasks currently executing */

	pthread_cond_signal(&pool->not_empty);
	pthread_mutex_unlock(&pool->mutex);

	return 0;
}

void thread_pool_wait(thread_pool_t *pool)
{
	if (pool == NULL)
		return;

	pthread_mutex_lock(&pool->mutex);
	while (pool->pending > 0)
		pthread_cond_wait(&pool->all_done, &pool->mutex);
	pthread_mutex_unlock(&pool->mutex);
}

void thread_pool_destroy(thread_pool_t *pool)
{
	unsigned int i;

	if (pool == NULL)
		return;

	/* wait for queued work to drain, then signal shutdown */
	thread_pool_wait(pool);

	pthread_mutex_lock(&pool->mutex);
	pool->shutdown = 1;
	pthread_cond_broadcast(&pool->not_empty);
	pthread_mutex_unlock(&pool->mutex);

	for (i = 0; i < pool->num_threads; i++)
		pthread_join(pool->threads[i], NULL);

	pthread_cond_destroy(&pool->all_done);
	pthread_cond_destroy(&pool->not_full);
	pthread_cond_destroy(&pool->not_empty);
	pthread_mutex_destroy(&pool->mutex);
	free(pool->threads);
	free(pool);
}

unsigned int thread_pool_get_nproc(void)
{
#if defined(_SC_NPROCESSORS_ONLN)
	long n = sysconf(_SC_NPROCESSORS_ONLN);
	if (n > 0)
		return (unsigned int)n;
#endif
	return 1;
}

#else /* !HAVE_PTHREAD — synchronous fallback */

/* -----------------------------------------------------------------------
 * Stub pool: tasks execute immediately in the calling thread.
 * The pool pointer is a non-NULL sentinel so callers need not NULL-check.
 * ----------------------------------------------------------------------- */
struct thread_pool {
	int dummy;
};

static thread_pool_t fallback_pool = { 0 };

thread_pool_t *thread_pool_create(unsigned int num_threads)
{
	(void)num_threads;
	return &fallback_pool;
}

int thread_pool_submit(thread_pool_t *pool, thread_task_fn fn, void *arg)
{
	(void)pool;
	if (fn == NULL)
		return -1;
	fn(arg);
	return 0;
}

void thread_pool_wait(thread_pool_t *pool)
{
	(void)pool;
	/* nothing to wait for — all tasks ran synchronously */
}

void thread_pool_destroy(thread_pool_t *pool)
{
	/* do not free the static fallback_pool */
	(void)pool;
}

unsigned int thread_pool_get_nproc(void)
{
	return 1;
}

#endif /* HAVE_PTHREAD */
