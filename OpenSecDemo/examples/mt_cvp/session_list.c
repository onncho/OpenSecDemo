/***************************************************************************
 *                                                                         *
 * session_list.c : Sample OPSEC CVP Server                                *
 *                                                                         *
 * This is a part of the Check Point OPSEC SDK                             *
 * Copyright (c) 1994-2001 Check Point Software Technologies, Ltd.         *
 * All rights reserved.                                                    *
 *                                                                         *
 * This source code is only intended as a supplement to the                *
 * Check Point OPSEC SDK and related documentation provided with the SDK   *
 * and shall be used in accordance with the standard                       *
 * End-User License Agreement.                                             *
 * See related documentation for detailed information                      *
 * regarding the Check Point OPSEC SDK.                                    *
 *                                                                         *
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 * The 'session list' is used to keep track of session that have ended but *
 * their associated worker threads have not yet sent their last message.   *
 * In this manner, events that are on the event queue of the CVP server    *
 * main thread and are associated with sessions for which the end handler  *
 * already been called, can safely be discarded.                           *
 *                                                                         *
 * The list is created by the server main thread at startup. Sessions are  *
 * added to it when the associated end handler is invoked. Sessions are    *
 * deleted from it when the 'last' message from the worker thread is       *
 * processed. Each event handled by the main thread is tested for the      *
 * validity of the sessions it is associated with.                         *
 *                                                                         *
 * Note: A better solution here may include:                               *
 *       1) Using some other key that is not the session pointer. A        *
 *          unique ID would do.                                            *
 *       2) A better seach algorithm than traversing through the list.     *
 *                                                                         *
 *       This implementation is a simplified example.                      *
 *                                                                         *
 ***************************************************************************/


#include <stdlib.h>
#include <opsec/opsec.h>
#include "session_list.h"

static list_el * session_list_get_first(dying_session_lst *lst);
static list_el * session_list_get_next(dying_session_lst *lst);

dying_session_lst*
create_session_list(void)
{
	dying_session_lst *lst = (dying_session_lst *)calloc(1, sizeof(dying_session_lst));

	return lst;
}

static list_el *
session_list_get_first(dying_session_lst *lst)
{
	if (!lst) return NULL;

	if (lst->num_elements == 0) return NULL;

	lst->current = lst->first;

	return lst->first;
}

static list_el *
session_list_get_next(dying_session_lst *lst)
{
	if (!lst) return NULL;

	if (lst->current->next) {
		lst->current = lst->current->next;
		return lst->current;
	} else 
		return NULL;
}

int
session_list_add(dying_session_lst *lst, OpsecSession *session)
{
	list_el   *el;
	
	if (!lst || !session) return -1;

	el = (list_el *)calloc(1, sizeof(list_el));
	if (!el) return -1;

	el->session = session;
	
	if (lst->num_elements == 0) {
		lst->first = lst->last = el;
	} else {
		lst->last->next = el;
		el->prev        = lst->last;
		lst->last       = el;
	}

	lst->num_elements++;
	
	return 0;
}

int
session_list_delete(dying_session_lst *lst, OpsecSession *session)
{
	list_el   *el;
	
	if (!lst || !session || (lst->num_elements == 0)) return -1;

	el = session_list_get_first(lst);
	
	while (el && (el->session != session) && (el = session_list_get_next(lst)));
	if (!el) return 0;

	if (el->prev) el->prev->next = el->next;
	else lst->first = el->next;

	if (el->next) el->next->prev = el->prev;
	else lst->last = el->prev;

	free(el);

	lst->num_elements--;
	if (lst->num_elements == 0) lst->current = NULL;
	
	return 0;
}

int
session_list_destroy(dying_session_lst *lst)
{
	list_el  *el;
	list_el  *next_el;

	if (!lst) return 0;

	el = session_list_get_first(lst);
	if (el) {
		do {
			next_el = el->next;
			free(el);
			el = next_el;
		} while(el);
	}

	free(lst);
	
	return 0;
}

int
session_is_in_list(dying_session_lst *lst, OpsecSession *session)
{
	list_el  *el;
	
	if (!lst) return -1;

	if (!session) return 0;

	if (lst->num_elements == 0) return 0;

	el = session_list_get_first(lst);

	while (el && (el->session != session) && (el = session_list_get_next(lst)));

	return (el?1:0);	
}
