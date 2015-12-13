/***************************************************************************
 *                                                                         *
 * os_wrappers.c : Sample OPSEC CVP Server                                 *
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
 * This file contains the realization of the inter thread communication    *
 * tools. For the sake of simplicity, the OPSEC mainloop and events are    *
 * used. A generalized realization should make use of 'standard' OS tools. *
 *                                                                         *
 * The code is designed to compile and run in Windows NT and in Solaris2   *
 * using Solaris native threads (by linking with the 'thread' library). In *
 * order to use other thread IS changes should be made to the              *
 * OS_create_thread function.                                              *
  ***************************************************************************/


#include <stdio.h>
#include <opsec/opsec.h>
#include <opsec/opsec_event.h>

#include "os_wrappers.h"

int
OS_raise_event(OpsecEnv *env, long event_no, void *raise_data)
{
	return opsec_raise_event (env, event_no, raise_data);
}

int
OS_unraise_event(OpsecEnv *env,  long event_no, void *raise_data)
{
	return opsec_unraise_event (env, event_no, raise_data);
}

long
OS_create_event()
{
	return opsec_new_event_id ();
}

int
OS_set_event_handler(OpsecEnv *env, long event_no, OpsecEventHandler handler, void *set_data)
{
	return opsec_set_event_handler (env, event_no, handler, set_data);
}

int
OS_del_event_handler(OpsecEnv *env, long event_no, OpsecEventHandler handler, void *set_data)
{
	return opsec_del_event_handler (env, event_no, handler, set_data);
}

int
OS_wait_on_events(OpsecEnv *env)
{
	return opsec_mainloop(env);
}

void
OS_schedule(OpsecEnv *env, long time , void(*func)(void*), void *opaque)
{
	opsec_schedule(env, time, func, opaque);
}	

void
OS_thread_cleanup(OS_thr *thr_h)
{
	if (!thr_h) return;
	if (thr_h->env) opsec_env_destroy(thr_h->env);
	free(thr_h);
}

OS_thr * OS_create_thread (ThreadFuncType thread_func, void * data) {

	ThrID     thread_id;
	OS_thr   *thr_h = NULL;

	thr_h = (OS_thr *)calloc(1, sizeof(OS_thr));
	if (!thr_h) return NULL;

	thr_h->env = opsec_init(OPSEC_EOL);
	if (!thr_h->env) {
		free(thr_h);
		return NULL;
	}

	thr_h->event_id = OS_create_event();
	thr_h->data     = data;
	
#ifdef WIN32
	CreateThread(NULL, 0, thread_func, (void *)thr_h, 0, &thread_id);
#else
	thr_create(NULL, NULL, thread_func, (void *)thr_h, NULL, &thread_id); /* != 0) */
#endif

	thr_h->thread_id = thread_id;

	return thr_h;
}

/*
 * A helper function for debug printing in 'verbose' mode.
 */

char *
OS_command_name(OS_command command)
{
	switch (command) {
		case OS_COMM_RQ_BEGIN:
			return "OS_COMM_RQ_BEGIN";
		case OS_COMM_RQ_END:
			return "OS_COMM_RQ_END";
		case OS_COMM_RECEIVE_CHUNK:
			return "OS_COMM_RECEIVE_CHUNK";
		case OS_COMM_SEND_CHUNK:
			return "OS_COMM_SEND_CHUNK";
		case OS_COMM_START_SENDING:
			return "OS_COMM_START_SENDING";
		case OS_COMM_PROCESS:
			return "OS_COMM_PROCESS";
		case OS_MSG_SEND_SUCCESS:
			return "OS_MSG_SEND_SUCCESS";
		case OS_WORKER_THREAD_READY:
			return "OS_WORKER_THREAD_READY";
		case OS_WORKER_THREAD_ERR:
			return "OS_WORKER_THREAD_ERR";
		default:
			return "UNKNOWN COMMAND";
	}
}

