/***************************************************************************
 *                                                                         *
 * cvp_worker.c : Sample OPSEC CVP Server                                  *
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
 * All of the I/O related activity of the CVP server is off-loaded to a    *
 * worker thread, in order to enable the CVP main thread to be responsive  *
 * to OPSEC events. In this example, the CVP server does not really inspect*
 * the file content, therefore the worker thread merely writes the file to *
 * the disk and then reads it as is in order for it to be sent back to the *
 * CVP client. In 'real life' the worker thread would probably also        *
 * 'inspect' the content as well.                                          *
 *                                                                         *
 * Upon creation, the worker thread registers an event handler for the     *
 * event ID dictated by the main thread. Via this handler, all commands    *
 * are received (see os_wrappers.h for command list). The entry function   *
 * also schedules the sending of a 'ready' message to the worker thread.   *
 * The thread either recevies or sends data chunks from/to the main        *
 * thread.                                                                 *
 *                                                                         *
 * When the thread recevies the end command it de-registers the event      *
 * handler. This results in the wait on event blocking function to return. *
 * The worker thread then signals the main thread that it is exiting and   *
 * exits after cleaning up the memory used.                                *
 *                                                                         *
 ***************************************************************************/

#include <stdio.h>
#include <errno.h>
#include <opsec/opsec.h>
#include <opsec/opsec_event.h>

#include "os_wrappers.h"


typedef struct _worker_opaque {
	char  *s_filename;
	char   s_tempname[50];
	FILE  *s_fp;

	int    action;
	int    s_chunk_size;

	char   s_buf[4096];
	int    s_buf_len;
	char   s_buf_full;

	char   s_eof;
	char   s_sending;
	OpsecSession *session;
} worker_opaque;

#define WO(_data)   ((worker_opaque *)(_data))

#define WT_STATUS_OK      0
#define WT_STATUS_ERR    -1

extern char        *ProgName;
extern long         cvp_server_event_id;
extern OpsecEnv    *env;
extern int          verbose_;

static int cvp_worker_ev_handler(OpsecEnv * env, long event_no, void *raise_data, void *set_data);
static int cvp_worker_start_sending(worker_opaque *wo);
static int cvp_worker_send_success_handler(worker_opaque *wo);
static int cvp_worker_send_chunk_handler(worker_opaque *wo);
static int cvp_worker_send_chunk_to_dst(worker_opaque *wo, char *buf, int len);
static int cvp_worker_chunk_handler(worker_opaque *wo, char *chunk, int len);
static int cvp_worker_end_rq(OpsecEnv *env, long event_no, void *set_data, worker_opaque *wo);
static int cvp_worker_begin_rq(worker_opaque *wo);


static int
signal_server_thread(OpsecSession  *session, OS_command command_type, 
                  void *data, int data_len, int chunk_size)
{
	char *t_buf = NULL;
	OS_raise_data    *raise_d = NULL;

	if (verbose_)
		fprintf(stderr, "\nsignal_server_thread: signaling session %x with command %s\n\n",
	    	    session, OS_command_name(command_type));
	
	if ((data != NULL) && (data_len != -1)) {
		t_buf = (char *)malloc(data_len);
		memcpy(t_buf, data, data_len);
	}

	raise_d = (OS_raise_data *)calloc(1, sizeof(OS_raise_data));
	if (!raise_d) {
		free(t_buf);
		return WT_STATUS_ERR;
	}
	
	raise_d->command_type = command_type;
	raise_d->data         = t_buf;
	raise_d->data_len     = data_len;
	raise_d->session      = session;
	raise_d->chunk_size   = chunk_size;
	
	if (OS_raise_event(env, cvp_server_event_id, (void *)raise_d)) {
		free(raise_d);
		free(t_buf);
		fprintf(stderr, "signal_server_thread: Could not signal server thread for session %x with command %s",
		        session, OS_command_name(command_type));
		return WT_STATUS_ERR;
	}

	return WT_STATUS_OK;
}

void
send_ready_signal(void *opq)
{
	worker_opaque *wo = (worker_opaque *)opq;

	signal_server_thread(wo->session, OS_WORKER_THREAD_READY, NULL, 0, 0);
}

/***************************************************************************
 * This is the entry point to the worker thread. The data received as input*
 * is the OS_thr data (see os_wrappers.h) that includes the event ID to be *
 * listened on and the session pointer to which this thread is associated. *
 *                                                                         *
 * The function creates an event handler, schedules an event for sending   *
 * the 'ready' message to the main thread and wiats for further events.    *
 ***************************************************************************/

#ifdef WIN32
DWORD WINAPI cvp_worker_entry_func(void *data)
#else
void * cvp_worker_entry_func(void *data)
#endif
{
	OS_thr         *thr_h     = (OS_thr *)data;
	OpsecEnv       *env       = thr_h->env;
	worker_opaque  *work_opq  = NULL;

	work_opq = (worker_opaque *)calloc(1, sizeof(worker_opaque));
	
	work_opq->session = (OpsecSession *)thr_h->data;
	
	OS_set_event_handler(env, thr_h->event_id, (OpsecEventHandler)cvp_worker_ev_handler, (void *)work_opq);

	OS_schedule(env, 0, (void (*)(void *))send_ready_signal, (void *)work_opq);

	OS_wait_on_events(env);

	signal_server_thread(work_opq->session, OS_MSG_LAST, NULL, 0, 0);

	OS_thread_cleanup(thr_h);
	
	free(work_opq);

	return 0;
}

/***************************************************************************
 * Handle the activity related with preparing for receving data:           *
 * 1) Choose file name for storing the data.                               *
 * 2) Open it.                                                             *
 ***************************************************************************/

static int
cvp_worker_begin_rq(worker_opaque *wo)
{
	/* choose a file name for the local copy ... */
	sprintf(wo->s_tempname, "%s%x.tmp", _TMPDIR, wo);
	fprintf(stderr, "cvp_worker_begin_rq: (session %x) Temporary file name: %s\n", wo->session, wo->s_tempname);

	/* ..and open it */
	wo->s_fp = fopen(wo->s_tempname, "wb");
	if (wo->s_fp == NULL) {
		fprintf(stderr, "%s: (session %x) cvp_worker_begin_rq: fopen('%s', 'wb') failed: %s\n",
			ProgName, wo->session, wo->s_tempname, strerror(errno));
		return WT_STATUS_ERR;
	}

	return WT_STATUS_OK;
}

/***************************************************************************
 * Handle the activity related with folding up:                            *
 * 1) Close the temporary file.                                            *
 * 2) Delete it.                                                           *
 * 3) Delete the event handler - that will enable the blocking wait in the *
 *    entry function to exit. This will make the thread exit as well.      *
 ***************************************************************************/

static int
cvp_worker_end_rq(OpsecEnv *env, long event_no, void *set_data, worker_opaque *wo)
{
	/* close the scratch file */
	if (wo->s_fp) {
		if (fclose(wo->s_fp) != 0)
			fprintf(stderr, "%s: (session %x) cvp_worker_end_rq: fclose('%s') failed: %s\n",
				ProgName, wo->session, wo->s_tempname,
				strerror(errno));
		wo->s_fp = NULL; 
	}

	if (wo->s_tempname[0]) {

		/* remove the scratch file */
		if (remove(wo->s_tempname) < 0) {
			fprintf(stderr, "%s: (session %x) cvp_worker_end_rq: remove '%s' failed: %s\n",
				ProgName, wo->session, wo->s_tempname,
				strerror(errno));
		}
		wo->s_tempname[0] = '\0';
	}

	OS_del_event_handler(env, event_no, 
	                     (OpsecEventHandler)cvp_worker_ev_handler, 
	                     set_data);
	
	return WT_STATUS_OK;
	
}

/***************************************************************************
 * Receive an incoming chunk and store it (write it) in the temporary file.*
 * If the last buffer has been written, signal the main thread that it can *
 * start processing the data.                                              *
 ***************************************************************************/
static int
cvp_worker_chunk_handler(worker_opaque *wo, char *chunk, int len)
{
	if (chunk == NULL) {	/* EOF received ? */
		fprintf(stderr, "cvp_worker_chunk_handler: (session %x) Received EOF\n", wo->session);
		/* close the scratch file.. */
		if (fclose(wo->s_fp) != 0) {
			fprintf(stderr, "%s: (session %x) cvp_worker_chunk_handler: fclose('%s') failed: %s\n",
				ProgName, wo->s_tempname, strerror(errno));
			return WT_STATUS_ERR;
		}
		wo->s_fp = NULL;

		/* .. and process it */
		if (signal_server_thread(wo->session, OS_COMM_PROCESS, NULL, 0, 0))
			return WT_STATUS_ERR;

		return WT_STATUS_OK;
	}

	fprintf(stderr, "cvp_worker_chunk_handler: (session %x) Received chunk (buff = %x, len = %d)\n", wo->session, chunk, len);
	if ((int)fwrite(chunk, 1, len, wo->s_fp) != len) {
		fprintf(stderr, "%s: (session %x) cvp_worker_chunk_handler: fwrite(%d, '%s') failed: %s\n",
		        ProgName, wo->session, len, wo->s_tempname, strerror(errno));
		return WT_STATUS_ERR;
	}

	return WT_STATUS_OK;
}

/***************************************************************************
 * Helper function for sending one chunk to the main thread.               *
 ***************************************************************************/

static int
cvp_worker_send_chunk_to_dst(worker_opaque *wo, char *buf, int len)
{
	char *t_buf = NULL;
	OS_raise_data *raise_d = NULL;

	if (signal_server_thread(wo->session, OS_COMM_RECEIVE_CHUNK, buf, len, 0))
		return WT_STATUS_ERR;

	return WT_STATUS_OK;
}

/***************************************************************************
 *  Read a chunk from the temporary file and send it to the main thread.   *
 ***************************************************************************/
static int
cvp_worker_send_chunk_handler(worker_opaque *wo)
{
	FILE *fp  = wo->s_fp;
	char *buf = wo->s_buf;

	/* need to read data from file ? */
	if (! wo->s_buf_full) {
		fprintf(stderr, "cvp_worker_chunk_handler: (session %x) Reading data from file\n", wo->session);
		wo->s_buf_len = fread(buf, 1, wo->s_chunk_size, fp);

		if (wo->s_buf_len == 0) {
			/* fread error ? */
			if (ferror(fp)) {
				fprintf(stderr, "%s: (session %x) cvp_worker_chunk_handler: fread('%s') failed: %s\n",
					ProgName, wo->session, wo->s_tempname, strerror(errno));
				return WT_STATUS_ERR;
			}

			/* reached end of file */
			fprintf(stderr, "cvp_worker_chunk_handler: (session %x) Reached the end of file\n", wo->session);
			wo->s_buf_len = -1;
			wo->s_eof = 1;
			buf = NULL;
		}

		/* have something to send */
		wo->s_buf_full = 1;
	}

	/* send data */
	fprintf(stderr, "cvp_worker_chunk_handler: (session %x) Will try to send chunk (len = %d)\n",
			wo->session, wo->s_buf_len);
	if (cvp_worker_send_chunk_to_dst(wo, buf, wo->s_buf_len) == 0) {

		/* just sent eof ? */
		if (buf == NULL)
			/* send completed */
			wo->s_sending = 0;
	}
	else {
		fprintf(stderr, "cvp_worker_chunk_handler: (session %x) Failed to send. Waiting for next cts signal\n", wo->session);	
		/* wait for next clear to send signal */
	}

	return WT_STATUS_OK;
}

static int
cvp_worker_send_success_handler(worker_opaque *wo)
{
	wo->s_buf_full = 0;
	
	return WT_STATUS_OK;
}

/***************************************************************************
 * Open the temporary file for reading in preparation for sending data     *
 * back tot he main thread.                                                *
 ***************************************************************************/
static int
cvp_worker_start_sending(worker_opaque *wo)
{
	fprintf(stderr, "cvp_worker_start_sending: (session %x) Temporary file name: %s\n", wo->session, wo->s_tempname?wo->s_tempname:"NULL");

	wo->s_fp = fopen(wo->s_tempname, "rb");
	rewind(wo->s_fp);
	if (wo->s_fp == NULL) {
		fprintf(stderr, "%s: cvp_worker_start_sending: (session %x) fopen('%s', 'rb') failed: %s\n",
		        ProgName, wo->session, wo->s_tempname, strerror(errno));
		return WT_STATUS_ERR;
	}
	return WT_STATUS_OK;
}

/***************************************************************************
 * Event dispatcher for the worker thread.                                 *
 * For a description of the events see os_wrappers.h                       *
 ***************************************************************************/
static int 
cvp_worker_ev_handler(OpsecEnv * env, long event_no, void *raise_data, void *set_data)
{
	OS_raise_data   *r_data = raise_data;
	worker_opaque   *wo     = WO(set_data);
	int              rc     = WT_STATUS_OK;

	switch (r_data->command_type) {
		
		case OS_COMM_RQ_BEGIN:
			wo->s_chunk_size = r_data->chunk_size;
			rc = cvp_worker_begin_rq(wo);
			break;
		
		case OS_COMM_RQ_END:
			rc = cvp_worker_end_rq(env, event_no, set_data, wo);
			break;
			
		case OS_COMM_RECEIVE_CHUNK:
			rc = cvp_worker_chunk_handler(wo, r_data->data, r_data->data_len);
			break;
		
		case OS_COMM_SEND_CHUNK:
			rc = cvp_worker_send_chunk_handler(wo);
			break;

		case OS_MSG_SEND_SUCCESS:
			rc = cvp_worker_send_success_handler(wo);
			break;

		case OS_COMM_START_SENDING:
			rc = cvp_worker_start_sending(wo);
			break;

		default:
			rc = WT_STATUS_ERR;
			break;
	}

	if (r_data->data) free(r_data->data);
	free(r_data);

	if (rc != WT_STATUS_OK)
		signal_server_thread(wo->session, OS_WORKER_THREAD_ERR, NULL, 0, 0);

	return WT_STATUS_OK;
	
}

