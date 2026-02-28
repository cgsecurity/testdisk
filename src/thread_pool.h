/*
    File: thread_pool.h

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
*/
#ifndef _THREAD_POOL_H
#define _THREAD_POOL_H
#ifdef __cplusplus
extern "C" {
#endif

/* Function pointer type for tasks submitted to the thread pool */
typedef void (*thread_task_fn)(void *arg);

/* Opaque thread pool handle */
typedef struct thread_pool thread_pool_t;

/*
 * thread_pool_create - allocate and start a thread pool with num_threads workers.
 * Returns NULL on allocation failure or if pthreads unavailable (use fallback).
 */
thread_pool_t *thread_pool_create(unsigned int num_threads);

/*
 * thread_pool_submit - enqueue a task for execution by a worker thread.
 * Blocks if the queue is at capacity (1024 tasks).
 * Returns 0 on success, -1 on error.
 * When HAVE_PTHREAD is not defined, executes fn(arg) synchronously.
 */
int thread_pool_submit(thread_pool_t *pool, thread_task_fn fn, void *arg);

/*
 * thread_pool_wait - block until all currently queued tasks have completed.
 */
void thread_pool_wait(thread_pool_t *pool);

/*
 * thread_pool_destroy - wait for all tasks, then stop workers and free memory.
 */
void thread_pool_destroy(thread_pool_t *pool);

/*
 * thread_pool_get_nproc - detect the number of available CPU processors.
 * Returns 1 if detection fails or pthreads unavailable.
 */
unsigned int thread_pool_get_nproc(void);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif /* _THREAD_POOL_H */
