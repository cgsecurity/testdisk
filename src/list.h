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

/*@
  inductive reachable_forward{L}(struct td_list_head *root, struct td_list_head *node) {
    case root_reachable_forward{L}:
      \forall struct td_list_head *root; reachable_forward(root,root) ;
    case next_reachable{L}:
      \forall struct td_list_head *root,*node;
      \valid(root) && reachable_forward(root->next,node) ==> reachable_forward(root,node);
  }

  inductive reachable_backward{L}(struct td_list_head *root, struct td_list_head *node) {
    case root_reachable_backward{L}:
      \forall struct td_list_head *root; reachable_backward(root,root) ;
    case prev_reachable{L}:
      \forall struct td_list_head *root,*node;
      \valid(root) && reachable_backward(root->prev,node) ==> reachable_backward(root,node);
  }
  @*/
  // root->next->prev == root

/*@ predicate finite{L}(struct td_list_head *root) = reachable_forward(root->next,root) && reachable_backward(root->prev,root); */


/*
      \forall struct td_list_head *l1;
        reachable(l, l1) && \valid(l1) ==> \valid(l1->next) && l1->next->prev == l1;
*/
/*@ inductive list_separated3{L}(struct td_list_head *root, struct td_list_head *node, struct td_list_head *elt) {
     case node_is_root{L}:
       \forall struct td_list_head *root, *elt; \separated(root, elt) ==> list_separated3(root, root, elt);
     case node_reachable{L}:
       \forall struct td_list_head *root, *node, *elt;
       \valid(node) && \separated(node, elt) && list_separated3(root, node->next, elt) ==> list_separated3(root, node, elt);
 }

 */
/*@ predicate list_separated{L}(struct td_list_head *root, struct td_list_head *elt) = list_separated3(root, root->next, elt); */

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
/*@
  @ requires \valid(newe);
  @ requires \valid(prev);
  @ requires \valid(next);
  @ requires separation: \separated(newe, \union(prev,next));
  @ requires prev == next || \separated(prev,next,newe);
  @ requires finite(prev);
  @ requires finite(next);
  @ requires prev->next == next;
  @ requires next->prev == prev;
  @ requires list_separated(prev, newe);
  @ requires list_separated(next, newe);
  @ terminates \true;
  @ ensures prev->next == newe;
  @ ensures newe->prev == prev;
  @ ensures newe->next == next;
  @ ensures next->prev == newe;
  @ ensures newe->next->prev == newe;
  @ ensures newe->prev->next == newe;
  @ assigns next->prev,newe->next,newe->prev,prev->next;
  @*/
static inline void __td_list_add(struct td_list_head *newe,
			      struct td_list_head *prev,
			      struct td_list_head *next)
{
        /*@ assert finite(prev); */
        /*@ assert finite(next); */
        /*@ assert reachable_forward(prev->next,prev); */
        /*@ assert reachable_forward(next->next,next); */
        /*@ assert reachable_backward(prev->prev,prev); */
        /*@ assert reachable_backward(next->prev,next); */

        /*@ assert reachable_forward(next,prev); */
	newe->next = next;
	newe->prev = prev;
	prev->next = newe;
	next->prev = newe;
	/*@ assert next->prev == newe; */
	/*@ assert newe->next == next; */
	/*@ assert newe->prev == prev; */
	/*@ assert prev->next == newe; */
	/*@ assert reachable_forward(prev,newe); */
	/*@ assert reachable_backward(next,newe); */
}

/**
 * td_list_add - add a new entry
 * @newe: new entry to be added
 * @head: list head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 */
/*@
  @ requires \valid(newe);
  @ requires \valid(head);
  @ requires \valid(head->next);
  @ requires separation: \separated(newe, \union(head,head->next));
  @ requires finite(head);
  @ requires finite(head->next);
  @ requires list_separated(head, newe);
  @ terminates \true;
  @ ensures head->next == newe;
  @ ensures newe->prev == head;
  @ ensures newe->next == \old(head->next);
  @ ensures \old(head->next)->prev == newe;
  @ assigns head->next,newe->prev,newe->next,\old(head->next)->prev;
  @*/
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
/*@
  @ requires \valid(newe);
  @ requires \valid(head);
  @ requires \valid(head->prev);
  @ requires separation: \separated(newe, head);
  @ requires \separated(newe, \union(head->prev, head));
  @ requires head->prev == head || \separated(head->prev, head, newe);
  @ requires finite(head->prev);
  @ requires list_separated(head->prev, newe);
  @ requires list_separated(head, newe);
  @ requires finite(head);
  @ terminates \true;
  @ ensures head->prev == newe;
  @ ensures newe->next == head;
  @ ensures newe->prev == \old(head->prev);
  @ ensures \old(head->prev)->next == newe;
  @ assigns head->prev,newe->next,newe->prev,\old(head->prev)->next;
  @*/
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
/*@
  @ requires \valid(prev);
  @ requires \valid(next);
  @ requires prev == next || \separated(prev,next);
  @ terminates \true;
  @ ensures next->prev == prev;
  @ ensures prev->next == next;
  @ assigns next->prev,prev->next;
  @*/
static inline void __td_list_del(struct td_list_head * prev, struct td_list_head * next)
{
	next->prev = prev;
	prev->next = next;
	/*@ assert next->prev == prev; */
	/*@ assert prev->next == next; */
}

/**
 * td_list_del - deletes entry from list.
 * @entry: the element to delete from the list.
 * Note: td_list_empty on entry does not return true after this, the entry is
 * in an undefined state.
 */
/*@
  @ requires \valid(entry);
  @ requires \valid(entry->prev);
  @ requires \valid(entry->next);
  @ requires \separated(entry, \union(entry->prev,entry->next));
  @ requires entry->prev == entry->next || \separated(entry->prev,entry->next);
  @ terminates \true;
  @ ensures  \old(entry->prev)->next == \old(entry->next);
  @ ensures  \old(entry->next)->prev == \old(entry->prev);
  @ assigns \old(entry->prev)->next, \old(entry->next)->prev, entry->next, entry->prev;
  @*/
static inline void td_list_del(struct td_list_head *entry)
{
	__td_list_del(entry->prev, entry->next);
	/*@ assert entry->prev->next == entry->next; */
	/*@ assert entry->next->prev == entry->prev; */
	entry->next = (struct td_list_head*)LIST_POISON1;
	entry->prev = (struct td_list_head*)LIST_POISON2;
	/*@ assert \at(entry->prev,Pre)->next == \at(entry->next,Pre); */
	/*@ assert \at(entry->next,Pre)->prev == \at(entry->prev,Pre); */
}

#if 0
/**
 * td_list_del_init - deletes entry from list and reinitialize it.
 * @entry: the element to delete from the list.
 */
static inline void td_list_del_init(struct td_list_head *entry)
{
	__td_list_del(entry->prev, entry->next);
	TD_INIT_LIST_HEAD(entry);
}
#endif

#if 0
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
#endif

/**
 * td_list_empty - tests whether a list is empty
 * @head: the list to test.
 */
/*@
  @ requires \valid_read(head);
  @ terminates \true;
  @ assigns  \nothing;
  @*/
static inline int td_list_empty(const struct td_list_head *head)
{
	return head->next == head;
}

#if 0
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
#endif

/**
 * td_list_entry - get the struct for this entry
 * @ptr:	the &struct td_list_head pointer.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the td_list_struct within the struct.
 */
#define td_list_entry(ptr, type, member) \
	((type *)((char *)(ptr)-(size_t)(&((type *)0)->member)))

#define td_list_entry_const(ptr, type, member) \
	((type *)((const char *)(ptr)-(size_t)(&((type *)0)->member)))

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


/**
 * td_list_first_entry - get the first element from a list
 * @ptr:	the list head to take the element from.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_head within the struct.
 *
 * Note, that list is expected to be not empty.
 */

#define td_list_first_entry(ptr, type, member) \
	td_list_entry((ptr)->next, type, member)


/**
 * td_list_last_entry - get the last element from a list
 * @ptr:	the list head to take the element from.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_head within the struct.
 *
 * Note, that list is expected to be not empty.
 */
#define td_list_last_entry(ptr, type, member) \
	td_list_entry((ptr)->prev, type, member)


/**
 * td_list_next_entry - get the next element in list
 * @pos:	the type * to cursor
 * @member:	the name of the list_head within the struct.
 */
#define td_list_next_entry(pos, member) \
	td_list_entry((pos)->member.next, typeof(*(pos)), member)

/**
 * td_list_prev_entry - get the prev element in list
 * @pos:	the type * to cursor
 * @member:	the name of the list_head within the struct.
 */
#define td_list_prev_entry(pos, member) \
	td_list_entry((pos)->member.prev, typeof(*(pos)), member)


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
