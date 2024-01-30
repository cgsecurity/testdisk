/*
    File: list_sort.c

    Copyright (C) 2011 Christophe GRENIER <grenier@cgsecurity.org>

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
#include "types.h"
#include "list.h"
#include "list_sort.h"

#define MAX_LIST_LENGTH_BITS 20

/*
 * Returns a list organized in an intermediate format suited
 * to chaining of merge() calls: null-terminated, no reserved or
 * sentinel head node, "prev" links not maintained.
 */
/*@
  @ decreases 0;
  @*/
static struct td_list_head *merge(
    int (*cmp)(const struct td_list_head *a, const struct td_list_head *b),
    struct td_list_head *a, struct td_list_head *b)
{
  struct td_list_head head, *tail = &head;

  /*@
    @ loop invariant \valid_function(cmp);
    @ loop invariant \valid(tail);
    @ loop invariant \valid(a);
    @ loop invariant \valid(b);
    @*/
  while (a && b) {
    /* if equal, take 'a' -- important for sort stability */
    if ((*cmp)(a, b) <= 0) {
      tail->next = a;
      a = a->next;
    } else {
      tail->next = b;
      b = b->next;
    }
    tail = tail->next;
  }
  tail->next = a?a:b;
  return head.next;
}

/*
 * Combine final list merge with restoration of standard doubly-linked
 * list structure.  This approach duplicates code from merge(), but
 * runs faster than the tidier alternatives of either a separate final
 * prev-link restoration pass, or maintaining the prev links
 * throughout.
 */
/*@
  @ decreases 0;
  @*/
static void merge_and_restore_back_links(
    int (*cmp)(const struct td_list_head *a, const struct td_list_head *b),
    struct td_list_head *head,
    struct td_list_head *a, struct td_list_head *b)
{
  struct td_list_head *tail = head;

  while (a && b) {
    /* if equal, take 'a' -- important for sort stability */
    if ((*cmp)(a, b) <= 0) {
      tail->next = a;
      a->prev = tail;
      a = a->next;
    } else {
      tail->next = b;
      b->prev = tail;
      b = b->next;
    }
    tail = tail->next;
  }
  tail->next = a ? a : b;

  do {
    /*
     * In worst cases this loop may run many iterations.
     * Continue callbacks to the client even though no
     * element comparison is needed, so the client's cmp()
     * routine can invoke cond_resched() periodically.
     */
    (*cmp)(tail->next, tail->next);

    tail->next->prev = tail;
    tail = tail->next;
  } while (tail->next);

  tail->next = head;
  head->prev = tail;
}

/**
 * td_list_sort - sort a list
 * @head: the list to sort
 * @cmp: the elements comparison function
 *
 * This function implements "merge sort", which has O(nlog(n))
 * complexity.
 *
 * The comparison function @cmp must return a negative value if @a
 * should sort before @b, and a positive value if @a should sort after
 * @b. If @a and @b are equivalent, and their original relative
 * ordering is to be preserved, @cmp must return 0.
 */
void td_list_sort(struct td_list_head *head,
    int (*cmp)(const struct td_list_head *a, const struct td_list_head *b))
{
  struct td_list_head *part[MAX_LIST_LENGTH_BITS+1]; /* sorted partial lists
							-- last slot is a sentinel */
  unsigned int lev;  /* index into part[] */
  unsigned int max_lev = 0;
  struct td_list_head *list;

  if (td_list_empty(head))
    return;

  memset(part, 0, sizeof(part));

  head->prev->next = NULL;
  list = head->next;

  /*@
    @ loop invariant \valid_function(cmp);
    @*/
  while (list) {
    struct td_list_head *cur = list;
    list = list->next;
    cur->next = NULL;

    /*@
      @ loop invariant \valid_function(cmp);
      @*/
    for (lev = 0; part[lev]; lev++) {
      cur = merge(cmp, part[lev], cur);
      part[lev] = NULL;
    }
    if (lev > max_lev) {
      if (lev >= MAX_LIST_LENGTH_BITS)
      {
	// list passed to td_list_sort() too long for efficiency
	lev--;
      }
      max_lev = lev;
    }
    part[lev] = cur;
  }

  /*@
    @ loop invariant \valid_function(cmp);
    @*/
  for (lev = 0; lev < max_lev; lev++)
    if (part[lev])
      list = merge(cmp, part[lev], list);

  merge_and_restore_back_links(cmp, head, part[max_lev], list);
}
