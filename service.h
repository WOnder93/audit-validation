/*
* service.h - Header file for ausearch-string.c
* Copyright (c) 2014 Red Hat Inc., Durham, North Carolina.
* All Rights Reserved.
*
* This software may be freely redistributed and/or modified under the
* terms of the GNU General Public License as published by the Free
* Software Foundation; either version 2, or (at your option) any
* later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; see the file COPYING. If not, write to the
* Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*
* Authors:
*   Steve Grubb <sgrubb@redhat.com>
*/

#ifndef SERVICE_HEADER
#define SERVICE_HEADER


/* This is the node of the linked list. message & item are the only elements
 * at this time. Any data elements that are per item goes here. */
typedef struct _snode{
  char *str;		// The string
  struct _snode* next;	// Next string node pointer
} snode;

/* This is the linked list head. Only data elements that are 1 per
 * event goes here. */
typedef struct {
  snode *head;		// List head
  snode *cur;		// Pointer to current node
  unsigned int cnt;	// How many items in this list
} slist;

void slist_create(slist *l);
static inline void slist_first(slist *l) { l->cur = l->head; }
void slist_last(slist *l);
snode *slist_next(slist *l);
static inline snode *slist_get_cur(slist *l) { return l->cur; }
void slist_append(slist *l, snode *node);
void slist_clear(slist* l);
void slist_remove(slist* l);
void dump_list(slist *s);
/* append a string if its not already on the list */
int slist_add_if_uniq(slist *l, const char *str);
/* Search for the service */
int slist_find(slist *l, const char *str);

#endif

