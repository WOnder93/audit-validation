/*
* service.c - Minimal linked list library for strings
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

#include "service.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>	// for printf

void slist_create(slist *l)
{
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}

void slist_last(slist *l)
{
        register snode* cur;
	
	if (l->head == NULL)
		return;

	// Start with cur in hopes that we don't start at beginning
	if (l->cur)
		cur = l->cur;
	else
	        cur = l->head;

	// Loop until no next value
	while (cur->next)
		cur = cur->next;
	l->cur = cur;
}

snode *slist_next(slist *l)
{
	if (l->cur == NULL)
		return NULL;
	l->cur = l->cur->next;
	return l->cur;
}

void slist_append(slist *l, snode *node)
{
	snode* newnode;

	newnode = malloc(sizeof(snode));

	if (node->str)
		newnode->str = node->str;
	else
		newnode->str = NULL;

	newnode->next = NULL;

	// Make sure cursor is at the end
	slist_last(l);

	// if we are at top, fix this up
	if (l->head == NULL)
		l->head = newnode;
	else	// Otherwise add pointer to newnode
		l->cur->next = newnode;

	// make newnode current
	l->cur = newnode;
	l->cnt++;
}

void slist_clear(slist* l)
{
	snode* nextnode;
	register snode* current;

	current = l->head;
	while (current) {
		nextnode=current->next;
		free(current->str);
		free(current);
		current=nextnode;
	}
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}

void slist_remove(slist *l)
{
	snode *prev = NULL, *cur, *current;

	current = l->cur; // Mark where we are
	if (current == NULL)
		return;
	cur = l->head;
	while (cur) {
		if (cur == current) {
			// Found it
			if (l->head == cur) {
				l->head = cur->next;
				l->cur = l->head;
			}
			if (prev) {
				prev->next = cur->next;
				l->cur = prev;
			}
			free(cur->str);
			free(cur);
			l->cnt--;
			break;
		} else {
			prev = cur;
			cur = cur->next;
		}
	}
}

/* This function will add a service if not existing. If it does exist,
   cur points to the entry. */
int slist_add_if_uniq(slist *l, const char *str)
{
	snode sn;
        register snode *cur;

       	cur = l->head;
	while (cur) {
		if (strcmp(str, cur->str) == 0) {
			l->cur = cur;
			return 0;
		} else 
			cur = cur->next;
	}

	/* No matches, append to the end */
	sn.str = strdup(str);
	slist_append(l, &sn);
	return 1;
}


int slist_find(slist *l, const char *str)
{
        register snode *cur;

       	cur = l->head;
	while (cur) {
		if (strcmp(str, cur->str) == 0) {
			l->cur = cur;
			return 1;
		} else 
			cur = cur->next;
	}

	/* No matches */
	return 0;
}

void dump_list(slist *l)
{
	snode *cur;
	printf("head: %p\n", l->head);
	printf("cur: %p\n", l->cur);
	printf("cnt: %d\n", l->cnt);
	if (l->head == NULL)
		return;
	cur = l->head;
	do {
		printf("cur: %p\n", cur);
		printf("str: %s\n", cur->str);
		printf("next: %p\n", cur->next);
	} while ((cur = cur->next));
}

