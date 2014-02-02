/*

    File: list.h

    Copyright (C) 2006-2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifndef _LIST_H
#define _LIST_H
/*
 * These are non-NULL pointers that will result in page faults
 * under normal circumstances, used to verify that nobody uses
 * non-initialized list entries.
 */
#define LIST_POISON1  ((void *) 0x00100100)
#define LIST_POISON2  ((void *) 0x00200200)

/*
 * Simple doubly linked list implementation.
 * Copied from Linux Kernel 2.6.12.3
 *
 * Some of the internal functions ("__xxx") are useful when
 * manipulating whole lists rather than single entries, as
 * sometimes we already know the next/prev entries and we can
 * generate better code by using them directly rather than
 * using the generic single-entry routines.
 */

struct td_list_head {
	struct td_list_head *next, *prev;
};

#define TD_LIST_HEAD_INIT(name) { &(name), &(name) }

#define TD_LIST_HEAD(name) \
	struct td_list_head name = TD_LIST_HEAD_INIT(name)

#define TD_INIT_LIST_HEAD(ptr) do { \
	(ptr)->next = (ptr); (ptr)->prev = (ptr); \
} while (0)

/*
 * Insert a new entry between two known consecutive entries.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __td_list_add(struct td_list_head *newe,
			      struct td_list_head *prev,
			      struct td_list_head *next)
{
	next->prev = newe;
	newe->next = next;
	newe->prev = prev;
	prev->next = newe;
}

/**
 * td_list_add - add a new entry
 * @newe: new entry to be added
 * @head: list head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 */
static inline void td_list_add(struct td_list_head *newe, struct td_list_head *head)
{
	__td_list_add(newe, head, head->next);
}

/**
 * td_list_add_tail - add a new entry
 * @newe: new entry to be added
 * @head: list head to add it before
 *
 * Insert a new entry before the specified head.
 * This is useful for implementing queues.
 */
static inline void td_list_add_tail(struct td_list_head *newe, struct td_list_head *head)
{
	__td_list_add(newe, head->prev, head);
}

/*
 * Delete a list entry by making the prev/next entries
 * point to each other.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __td_list_del(struct td_list_head * prev, struct td_list_head * next)
{
	next->prev = prev;
	prev->next = next;
}

/**
 * td_list_del - deletes entry from list.
 * @entry: the element to delete from the list.
 * Note: td_list_empty on entry does not return true after this, the entry is
 * in an undefined state.
 */
static inline void td_list_del(struct td_list_head *entry)
{
	__td_list_del(entry->prev, entry->next);
	entry->next = (struct td_list_head*)LIST_POISON1;
	entry->prev = (struct td_list_head*)LIST_POISON2;
}

/**
 * td_list_del_init - deletes entry from list and reinitialize it.
 * @entry: the element to delete from the list.
 */
static inline void td_list_del_init(struct td_list_head *entry)
{
	__td_list_del(entry->prev, entry->next);
	TD_INIT_LIST_HEAD(entry);
}

/**
 * td_list_move - delete from one list and add as another's head
 * @list: the entry to move
 * @head: the head that will precede our entry
 */
static inline void td_list_move(struct td_list_head *list, struct td_list_head *head)
{
        __td_list_del(list->prev, list->next);
        td_list_add(list, head);
}

/**
 * td_list_move_tail - delete from one list and add as another's tail
 * @list: the entry to move
 * @head: the head that will follow our entry
 */
static inline void td_list_move_tail(struct td_list_head *list,
				  struct td_list_head *head)
{
        __td_list_del(list->prev, list->next);
        td_list_add_tail(list, head);
}

/**
 * td_list_empty - tests whether a list is empty
 * @head: the list to test.
 */
static inline int td_list_empty(const struct td_list_head *head)
{
	return head->next == head;
}

/**
 * td_list_empty_careful - tests whether a list is
 * empty _and_ checks that no other CPU might be
 * in the process of still modifying either member
 *
 * NOTE: using td_list_empty_careful() without synchronization
 * can only be safe if the only activity that can happen
 * to the list entry is td_list_del_init(). Eg. it cannot be used
 * if another CPU could re-td_list_add() it.
 *
 * @head: the list to test.
 */
static inline int td_list_empty_careful(const struct td_list_head *head)
{
	struct td_list_head *next = head->next;
	return (next == head) && (next == head->prev);
}

static inline void __td_list_splice(struct td_list_head *list,
				 struct td_list_head *head)
{
	struct td_list_head *first = list->next;
	struct td_list_head *last = list->prev;
	struct td_list_head *at = head->next;

	first->prev = head;
	head->next = first;

	last->next = at;
	at->prev = last;
}

/**
 * td_list_splice - join two lists
 * @list: the new list to add.
 * @head: the place to add it in the first list.
 */
static inline void td_list_splice(struct td_list_head *list, struct td_list_head *head)
{
	if (!td_list_empty(list))
		__td_list_splice(list, head);
}

/**
 * td_list_splice_init - join two lists and reinitialise the emptied list.
 * @list: the new list to add.
 * @head: the place to add it in the first list.
 *
 * The list at @list is reinitialised
 */
static inline void td_list_splice_init(struct td_list_head *list,
				    struct td_list_head *head)
{
	if (!td_list_empty(list)) {
		__td_list_splice(list, head);
		TD_INIT_LIST_HEAD(list);
	}
}

/**
 * td_list_entry - get the struct for this entry
 * @ptr:	the &struct td_list_head pointer.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the td_list_struct within the struct.
 */
#define td_list_entry(ptr, type, member) \
	((type *)((char *)(ptr)-(unsigned long long)(&((type *)0)->member)))

#define td_list_entry_const(ptr, type, member) \
	((type *)((const char *)(ptr)-(unsigned long long)(&((type *)0)->member)))

/**
 * __td_list_for_each	-	iterate over a list
 * @pos:	the &struct td_list_head to use as a loop counter.
 * @head:	the head for your list.
 *
 */
#define td_list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)

/**
 * td_list_for_each_prev	-	iterate over a list backwards
 * @pos:	the &struct td_list_head to use as a loop counter.
 * @head:	the head for your list.
 */
#define td_list_for_each_prev(pos, head) \
	for (pos = (head)->prev; pos != (head); \
        	pos = pos->prev)

/**
 * td_list_for_each_safe	-	iterate over a list safe against removal of list entry
 * @pos:	the &struct td_list_head to use as a loop counter.
 * @n:		another &struct td_list_head to use as temporary storage
 * @head:	the head for your list.
 */
#define td_list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)

/**
 * td_list_for_each_prev_safe	-	iterate over a list backwards safe against removal of list entry
 * @pos:	the &struct td_list_head to use as a loop counter.
 * @n:		another &struct td_list_head to use as temporary storage
 * @head:	the head for your list.
 */
#define td_list_for_each_prev_safe(pos, n, head) \
	for (pos = (head)->prev, n = pos->prev; pos != (head); \
		pos = n, n = pos->prev)

/**
 * td_list_for_each_entry	-	iterate over list of given type
 * @pos:	the type * to use as a loop counter.
 * @head:	the head for your list.
 * @member:	the name of the td_list_struct within the struct.
 */
#define td_list_for_each_entry(pos, head, member)				\
	for (pos = td_list_entry((head)->next, typeof(*pos), member);	\
	     &pos->member != (head); 	\
	     pos = td_list_entry(pos->member.next, typeof(*pos), member))

/**
 * td_list_for_each_entry_reverse - iterate backwards over list of given type.
 * @pos:	the type * to use as a loop counter.
 * @head:	the head for your list.
 * @member:	the name of the td_list_struct within the struct.
 */
#define td_list_for_each_entry_reverse(pos, head, member)			\
	for (pos = td_list_entry((head)->prev, typeof(*pos), member);	\
	     &pos->member != (head); 	\
	     pos = td_list_entry(pos->member.prev, typeof(*pos), member))

/**
 * td_list_prepare_entry - prepare a pos entry for use as a start point in
 *			td_list_for_each_entry_continue
 * @pos:	the type * to use as a start point
 * @head:	the head of the list
 * @member:	the name of the td_list_struct within the struct.
 */
#define td_list_prepare_entry(pos, head, member) \
	((pos) ? : td_list_entry(head, typeof(*pos), member))

/**
 * td_list_for_each_entry_continue -	iterate over list of given type
 *			continuing after existing point
 * @pos:	the type * to use as a loop counter.
 * @head:	the head for your list.
 * @member:	the name of the td_list_struct within the struct.
 */
#define td_list_for_each_entry_continue(pos, head, member) 		\
	for (pos = td_list_entry(pos->member.next, typeof(*pos), member);	\
	     &pos->member != (head);	\
	     pos = td_list_entry(pos->member.next, typeof(*pos), member))

/**
 * td_list_for_each_entry_safe - iterate over list of given type safe against removal of list entry
 * @pos:	the type * to use as a loop counter.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the td_list_struct within the struct.
 */
#define td_list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = td_list_entry((head)->next, typeof(*pos), member),	\
		n = td_list_entry(pos->member.next, typeof(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = n, n = td_list_entry(n->member.next, typeof(*n), member))


static inline void td_list_add_sorted(struct td_list_head *newe, struct td_list_head *head,
    int (*compar)(const struct td_list_head *a, const struct td_list_head *b))
{
  struct td_list_head *pos;
  td_list_for_each(pos, head)
  {
    if(compar(newe,pos)<0)
    {
      __td_list_add(newe, pos->prev, pos);
      return ;
    }
  }
  td_list_add_tail(newe, head);
}

static inline int td_list_add_sorted_uniq(struct td_list_head *newe, struct td_list_head *head,
    int (*compar)(const struct td_list_head *a, const struct td_list_head *b))
{
  struct td_list_head *pos;
  td_list_for_each(pos, head)
  {
    const int res=compar(newe,pos);
    if(res<0)
    {
      __td_list_add(newe, pos->prev, pos);
      return 0;
    }
    else if(res==0)
      return 1;
  }
  td_list_add_tail(newe, head);
  return 0;
}

typedef struct alloc_list_s alloc_list_t;
struct alloc_list_s
{
  struct td_list_head list;
  uint64_t start;
  uint64_t end;
  unsigned int data;
};

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
