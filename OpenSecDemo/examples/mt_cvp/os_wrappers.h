#ifndef _OS_WRAPPERS_H
#define _OS_WRAPPERS_H

/***************************************************************************
 *                                                                         *
 * os_wrappers.h : Sample OPSEC CVP Server                                 *
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
 * Inter thread communication commands:                                    *
 * ------------------------------------                                    *
 *                                                                         *
 * OS_COMM_RQ_BEGIN (main thread to worker thread) - instructs the worker  * 
 * thread to gear up for activity - the worker thread chooses a temp file  *
 * name and opens it for writing.                                          *
 *                                                                         *
 * OS_COMM_RQ_END (main thread to worker thread) - instructs the worker    *
 * thread to unregister its event handler and exit.                        *
 *                                                                         *
 * OS_COMM_RECEIVE_CHUNK (both directions) - used to inform the peer       *
 * thread that it should receive a data chunk. The worker thread writes    *
 * the chunk to the temporary file and the main thread sends it to the     *
 * client.                                                                 *
 *                                                                         *
 * OS_COMM_SEND_CHUNK (main thread to worker thread) - used by the main    *
 * thread to instruct the worker thread to read a chunk from the temporary *
 * file and send it to the main thread.                                    *
 *                                                                         *
 * OS_COMM_START_SENDING (main thread to worker thread) - used by the main *
 * thread to inform the worker thread that it will be asked to send chunks *
 * in the near future.                                                     *
 *                                                                         *
 * OS_COMM_PROCESS (worker thread to main thread) - used by the worker     *
 * thread to inform the main thread that the last incoming chunk has been  *
 * written to the disk and that it may start processing the file.          *
 *                                                                         *
 * OS_MSG_SEND_SUCCESS (main thread to worker thread) - the main thread    *
 * informs the worker thread that the previously supplied chunk was sent   *
 * to the CVP client.                                                      *
 *                                                                         *
 * OS_MSG_LAST (worker thread to main thread) - this is the last message   *
 * sent by the worker thread before it exits. The main thread can then     *
 * delete all references to the session with which the worker thread was   *
 * associated.                                                             *
 *                                                                         *
 * OS_WORKER_THREAD_READY (worker thread to main thread) - this is the     *
 * message sent by the worker thread when it is ready to start receiving   *
 * messages from the main thread. This message will casue the main thread  *
 * resume the session.                                                     *
 *                                                                         *
 * OS_WORKER_THREAD_ERR (worker thread to main thread) - used by the       *
 * worker thread to inform the main thread of a fatal error (that will     *
 * lead to session close - by the main thread).                            *
 *                                                                         *
 ***************************************************************************/

#ifdef WIN32
#include <winsock.h>
#include <winbase.h>
typedef DWORD ThrID;
#define ThreadFuncType LPTHREAD_START_ROUTINE
#define ThreadFuncReturnType DWORD WINAPI
#else
#include <unistd.h>
#include <thread.h>
/* use Solaris native threads (should link with -lthread) */
typedef thread_t ThrID;
#define ThreadFuncReturnType void *
typedef void * (*ThreadFuncType) (void *);
#endif
#include "opsec/opsec_event.h"

typedef struct _OS_thr {
	ThrID          thread_id;
	OpsecEnv      *env;
	long           event_id;
	void          *data;
} OS_thr;

typedef enum _OS_command {
	OS_COMM_RQ_BEGIN,
	OS_COMM_RQ_END,
	OS_COMM_RECEIVE_CHUNK,
	OS_COMM_SEND_CHUNK,
	OS_COMM_START_SENDING,
	OS_COMM_PROCESS,
	OS_MSG_SEND_SUCCESS,
	OS_MSG_LAST,
	OS_WORKER_THREAD_READY,
	OS_WORKER_THREAD_ERR
} OS_command;

typedef struct _OS_raise_data {
	OpsecSession  *session;
	OS_command     command_type;
	void          *data;
	int            data_len;
	int            chunk_size;
} OS_raise_data;
	

int      OS_raise_event(OpsecEnv *env, long event_no, void *raise_data);
int      OS_unraise_event(OpsecEnv *env,  long event_no, void *raise_data);
long     OS_create_event();
int      OS_set_event_handler(OpsecEnv *env, long event_no, OpsecEventHandler handler, void *set_data);
int      OS_del_event_handler(OpsecEnv *env, long event_no, OpsecEventHandler handler, void *set_data);
int      OS_wait_on_events(OpsecEnv *env);
void     OS_schedule(OpsecEnv *env, long time , void(*func)(void*), void *opaque);
void     OS_thread_cleanup(OS_thr *thr_h);
OS_thr * OS_create_thread (ThreadFuncType thread_func, void * data);
char   * OS_command_name(OS_command command);

/*
 * The temporary directory where the temporary files will be written to
 * by the worker threads.
 */

#ifdef WIN32
#define   _TMPDIR   "c:\\temp\\"
#else
#define   _TMPDIR   "/tmp/"
#endif

#endif
