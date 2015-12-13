#ifndef _SESSION_LIST_H_
#define _SESSION_LIST_H_

/***************************************************************************
 *                                                                         *
 * session_list.h : Sample OPSEC CVP Server                                *
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
 * See session_list.c for further explanations.                            *
 *                                                                         *
 ***************************************************************************/


typedef struct _list_el {
	struct _list_el   *next;
	struct _list_el   *prev;
	OpsecSession      *session;
} list_el;

typedef struct _dying_session_lst {
	int       num_elements;
	list_el  *first;
	list_el  *last;
	list_el  *current;
} dying_session_lst;

dying_session_lst * create_session_list(void);
int                 session_list_add(dying_session_lst *lst, OpsecSession *session);
int                 session_list_delete(dying_session_lst *lst, OpsecSession *session);
int                 session_list_destroy(dying_session_lst *lst);
int                 session_is_in_list(dying_session_lst *lst, OpsecSession *session);

#endif
