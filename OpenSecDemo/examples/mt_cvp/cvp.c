/***************************************************************************
 *                                                                         *
 * cvp.c : Sample OPSEC CVP Server                                         *
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
 * This is a sample for a Multi-Threaded CVP Anti Virus server.            *
 *                                                                         *
 * This server is based on the cvp_av_server example also included in the  *
 * OPSEC SDK. The same functionality as in the cvp_av_server is            *
 * accomplished here with one diffrence. The I/O related funcionality      *
 * of reading and writing the inspected file to the disk has been moved    *
 * to a worker thread.                                                     *
 *                                                                         *
 * The worker thread is also written around an OPSEC environment and       *
 * main-loop but this is done for the sake of simplicity. The OPSEC main-  *
 * loop of the worker thread is used only as a driver for events - no use  *
 * is made of other OPSEC functionality. See text in OS_wrappers.c and     *
 * cvp_worker.c for further details.                                       *
 *                                                                         *
 * The server operates as followes:                                        *
 *                                                                         *
 *   1. When the session is created (start_handler) the session is         *
 *      suspended and a worker thread for the session created. Once the    *
 *      worker thread has indicated that it is ready (WORKER_THREAD_READY  *
 *      command), the session is resumed.                                  *
 *                                                                         *
 *   2. Receives all data from the client. Every chunk that is received    *
 *      is transferred to the worker thread using the OS_COMM_RECEIVE_CHUNK*
 *      command.                                                           *
 *                                                                         *
 *   3. Processes the file and determines the data safety. This is done in *
 *      context of the main thread since no I/O is involved and for the    *
 *      sake of simplicity of this example.                                *
 *                                                                         *
 *   4. Sends a reply and the file back to the client.                     *
 *      Note that since the server asks for the whole data stream          *
 *      before it starts processing it, the file must be sent back         *
 *      (modified or not) since the client does not hold a copy            *
 *      of the file.                                                       *
 *                                                                         *
 *      The worker thread is instructed to start sending the file -        *
 *      using the OS_COMM_START_SENDING command. Every time the            *
 *      cts_signal_handler is called the main thread finds out whether     *
 *      there is a chunk already waiting to be sent and if not, instructs  *
 *      worker thread to read the next chunk from the file using the       *
 *      OS_COMM_SEND_CHUNK command.                                        *
 *                                                                         *
 *                                                                         *
 ***************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#ifdef WIN32
#include <winsock.h>
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "opsec/opsec.h"
#include "opsec/opsec_error.h"
#include "opsec/cvp.h"
#include "opsec/av_over_cvp.h"

#include "os_wrappers.h"
#include "session_list.h"

/*
 * Global definitions
 */
#define	DEFAULT_CHUNK_SIZE	4096

/*
 *  The following structure will be hanged on the session opaque
 */
struct srv_opaque {
	char  *s_filename;

	int    action;
	int    s_chunk_size;

	char   s_sending;

	int    waiting_for_chunk;
	char  *waiting_chunk;
	int    waiting_chunk_size;

	OS_thr *thr_h;
};

#define SO(session) ((struct srv_opaque*)SESSION_OPAQUE(session))


/*
 * Globals
 */
int                         verbose_ = 0;
char                       *ProgName = "Unknown";
long                        cvp_server_event_id = 0;
OpsecEnv                   *env = NULL;
static dying_session_lst   *d_sess_lst = NULL;


/*
 * Prototypes
 */
static int        cts_signal_handler(OpsecSession *session, int flow);
static int        cvp_server_send_chunk_handler(OpsecSession *session, char *data, int len);
static OpsecEnv * cvp_server_get_worker_thr_env(OpsecSession *session);
static int        signal_worker_thread(OpsecSession *session, OS_command command, char *buf, int len, int chunk_size);
static int        set_cts_size(OpsecSession *session);
static void       print_request_parameters(char *filename, int ftype, int proto, char *command, int action);
static int        fix_file(OpsecSession *session);
static int        process_file(OpsecSession *session, int *opinion, char *log_msg, char *warning);
static int        process_and_send(OpsecSession *session);
static int        send_chunk(OpsecSession *session);
static int        request_handler(OpsecSession *session, OpsecInfo *info);
static int        chunk_handler(OpsecSession *session, char *buf, int len);
static int        cts_signal_handler(OpsecSession *session, int flow);
static int        start_handler(OpsecSession *session);
static void       end_handler(OpsecSession *session);
static int        cvp_server_send_chunk_handler(OpsecSession *session, char *data, int len);
static int        cvp_server_ev_handler(OpsecEnv * env, long event_no, void *raise_data, void *set_data);

#ifdef WIN32
DWORD WINAPI      cvp_worker_entry_func(void *data);
#else
void            * cvp_worker_entry_func(void *data);
#endif


static OpsecEnv *
cvp_server_get_worker_thr_env(OpsecSession *session)
{
	if (!session) return NULL;

	return SO(session)->thr_h->env;
}

/***************************************************************************
 *                                                                         *
 * A wrapper for sending an event to the worker thread.                    *
 *                                                                         *
 ***************************************************************************/
static int
signal_worker_thread(OpsecSession *session, OS_command command, char *buf, int len, int chunk_size)
{
	char          *t_buf   = NULL;
	OS_raise_data *raise_d = NULL;
	OpsecEnv      *worker_thread_env = cvp_server_get_worker_thr_env(session);

	if (verbose_)
		fprintf(stderr, "\nsignal_worker_thread: signaling session %x with command %s\n\n",
	    	    session, OS_command_name(command));

	if (buf != NULL) {
		t_buf = malloc(len);
		memcpy(t_buf, buf, len);
	}

	raise_d = (OS_raise_data *)calloc(1, sizeof(OS_raise_data));
	if (!raise_d) {
		free(t_buf);
		return OPSEC_SESSION_ERR;
	}
	
	raise_d->command_type = command;
	raise_d->data         = t_buf;
	raise_d->data_len     = len;
	raise_d->chunk_size   = chunk_size;
	
	if (OS_raise_event(worker_thread_env, SO(session)->thr_h->event_id, (void *)raise_d)) {
		free(raise_d);
		free(t_buf);
		return OPSEC_SESSION_ERR;
	}

	return OPSEC_SESSION_OK;
}


 /* -----------------------------------------------------------------------------
  |  set_cts_size:
  |  -------------
  |
  |  Description:
  |  ------------
  |  Tune the CLEAR_TO_SEND mechanism - we want to send chunks of
  |  DEFAULT_CHUNK_SIZE, or as much as possible if this is too big
  |
  |  Parameters:
  |  -----------
  |  session - Pointer to an OpsecSession object.
  |
  |  Returned value:
  |  ---------------
  |  The smaller of DEFAULT_CHUNK_SIZE and the maximum possible chunk size.
   ----------------------------------------------------------------------------- */
static int set_cts_size(OpsecSession *session)
{
	int	size = DEFAULT_CHUNK_SIZE;

	/*
	 * return value will be the minimum between the input 'size'
	 * argument and the maximum allowed quantity (dependednt on the client)
	 */
	size = cvp_cts_chunk_size(session, size);
	if (size < 0) {
		fprintf(stderr, "%s: could not set cts size\n", ProgName);
		return OPSEC_SESSION_ERR;
	}

	/* store for future usage */
	SO(session)->s_chunk_size = size;
	
	return size;
}

/* -----------------------------------------------------------------------------------
 |
 | print_request_parameters
 | ------------------------
 |
 | Description:
 | ------------
 | Print the meaning of the parameters obtained from the opsec_info
 |
 | Parameters:
 | -----------
 | filename - See CVP documentation.
 | ftype    - See CVP documentation.
 | proto    - See CVP documentation.
 | command  - See CVP documentation.
 | action   - See CVP documentation.
 |
 | Returned value:
 | ---------------
 | None
 |
 -------------------------------------------------------------------------------------- */
static void 
print_request_parameters(char *filename, int ftype, int proto, char *command, int action)
{
	char *action_s,
	     *ftype_s,
	     *proto_s;

	switch (action) {
		case CVP_RDONLY:
			action_s = "CVP_RDONLY";
			break;
		case CVP_RDWR:
			action_s = "CVP_RDWR";
			break;
		case CVP_NONE:
			action_s = "CVP_NONE";
			break;
		default:
			action_s = "unknown";
	}

	switch (ftype) {
		case CVP_UNSPECIFIED_CONTENT:
			ftype_s = "CVP_UNSPECIFIED_CONTENT";
			break;
		case CVP_BIN_CONTENT:
			ftype_s = "CVP_BIN_CONTENT";
			break;
		case CVP_TEXT_CONTENT:
			ftype_s = "CVP_TEXT_CONTENT";
			break;
		case CVP_COMPOUND_CONTENT:
			ftype_s = "CVP_COMPOUND_CONTENT";
			break;
		default:
			ftype_s = "unknown";
	}

	switch (proto) {
		case CVP_HTTP_PROTOCOL:
			proto_s = "HTTP";
			break;
		case CVP_SMTP_PROTOCOL:
			proto_s = "SMTP";
			break;
		case CVP_FTP_PROTOCOL:
			proto_s = "FTP";
			break;
		case CVP_UNKNOWN_PROTOCOL:
		default:
			proto_s = "unknown";
	}

 	fprintf(stderr,
 		"Request parameters: Filename=%s, File-type=%s, Protocol=%s, Command=%s, Action=%s\n",
		                     (filename) ? filename : "unknown",
		                     ftype_s,
		                     proto_s,
		                     (command)  ? command  : "unknown",
		                     action_s);
	return;
}

static int 
fix_file(OpsecSession *session)
{
	/* 
	   In real life Anti-Virus's, this function fixes the data stream,
	   if any viruses are found in it.
	   This sample does not contain any logic for cleanning files.
	 */
	return OPSEC_SESSION_OK;
}

 /* -----------------------------------------------------------------------------
  |  process_file:
  |  -------------
  |
  |  Description:
  |  ------------
  |  Determined if the file is ok.
  |  A log message and warning will be sent, according to the processing result.
  |  In real life this function will do the real processing of the file.
  |
  |  Note that in this case, the server is the only one holding the data
  |  (the client does not hold a copy of it). Thus, the server has to send
  |  the file back to the client weather it was modified or not.
  |
  |  Parameters:
  |  -----------
  |  session - Pointer to an OpsecSession object.
  |  opinion - out parameter, which will contain the server's opinion.
  |  warning - out parameter, which will contain a warning from the server.
  |
  |  Returned value:
  |  ---------------
  |  OPSEC_SESSION_OK if successful, OPSEC_SESSION_ERR otherwise.
   ----------------------------------------------------------------------------- */
static int 
process_file(OpsecSession *session, int *opinion, char *log_msg, char *warning)
{
	char *filename = SO(session)->s_filename;

	/* Is this an infected file ? */
	if (strncmp(filename, "virus", 5) == 0) {
		fprintf(stderr, "process_file: Found virus in file !\n");

		/* Is the server allowd to fix the virus ? */
		if (SO(session)->action != CVP_RDWR) {

			*opinion = CVP_CONTENT_UNSAFE | CVP_CONTENT_NOT_MODIFIED;
			sprintf(log_msg, "Found virus. CVP server is not allowed to modify content.");
			strcpy(warning, "file was scanned and found infected");
		}
		else {
			/* Fix the file */
			fix_file(session);
			*opinion = CVP_CONTENT_SAFE | CVP_ORIGINAL_CONTENT_UNSAFE | CVP_CONTENT_MODIFIED;
			
			sprintf(log_msg, "CVP server fixed infected file");
			strcpy(warning, "file was scanned and fixed");
		}
	}
	else {
		/* File is ok */
		*opinion = CVP_CONTENT_SAFE | CVP_CONTENT_NOT_MODIFIED;

		sprintf(log_msg, "files beginning with '%c' are known to be safe", filename[0]);
		strcpy(warning, "file was scanned and found safe");
	}

	/* then start sending the file */
	SO(session)->s_sending = 1;
	
	return OPSEC_SESSION_OK;
}

 /* -----------------------------------------------------------------------------
  |  process_and_send:
  |  -----------------
  |
  |  Description:
  |  ------------
  |  Process the complete file, send a reply, and follow with the file content.
  |
  |  Parameters:
  |  -----------
  |  session - Pointer to an OpsecSession object.
  |
  |  Returned value:
  |  ---------------
  |  OPSEC_SESSION_OK if successful, OPSEC_SESSION_ERR otherwise.
   ----------------------------------------------------------------------------- */
static int 
process_and_send(OpsecSession *session)
{
	OpsecInfo *info     = NULL;
	char      *filename = SO(session)->s_filename;
	char       log_msg[4096];
	char       warning[4096];
	int        opinion = 0;
	int        rc = OPSEC_SESSION_OK;

	/*
	   Here, the server should scan the file.
	 */
	process_file(session, &opinion, log_msg, warning);

	/* create and populate the OpsecInfo */
	if (!(info = opsec_info_init()))
		return OPSEC_SESSION_ERR;
	opsec_info_set(info, "warning", warning, NULL);

	/* send the reply */
	fprintf(stderr, "process_and_send: Will send reply\n log: %s\n warning: %s\n",
			(log_msg) ? log_msg : "none" , (warning) ? warning : "none");
	rc = cvp_send_reply(session, opinion, log_msg, info);

	opsec_info_destroy(info);

	if (rc != OPSEC_SESSION_OK) {
		fprintf(stderr, "process_and_send: Failed to send reply\n");
		return OPSEC_SESSION_ERR;
	}

	/* send the file */
	fprintf(stderr, "process_and_send: Will send file to client\n");

	/* Ask the worker thread to prepare for reading the temporary file */
	if (signal_worker_thread(session, OS_COMM_START_SENDING, NULL, 0, 0))
		return OPSEC_SESSION_ERR;

	/* Trigger the CTS events that will drive the chunk sending the the
	   CVP client
	 */
	return cts_signal_handler(session, DST_FLOW);
}

 /* -----------------------------------------------------------------------------
  |  send_chunk:
  |  -----------
  |
  |  Description:
  |  ------------
  |  Send a single chunk to the client.
  |  Alternate between reading data from the scratch file and sending the data.
  |
  |  Parameters:
  |  -----------
  |  session - Pointer to an OpsecSession object.
  |
  |  Returned value:
  |  ---------------
  |  OPSEC_SESSION_OK if successful, OPSEC_SESSION_ERR otherwise.
   ----------------------------------------------------------------------------- */
static int 
send_chunk(OpsecSession *session)
{
	char *chunk       = NULL;
	int   chunk_size  = 0;
	
	if (SO(session)->waiting_chunk) {
		/*
		 * If there is a chunk stored on the session opaque try to send it.
		 * If the chunk is not sent eventually, the chunk data will be put
		 * on the session opaque once more for a re-try by the 
		 * cvp_server_send_chunk_handler() function.
		 */
		chunk      = SO(session)->waiting_chunk;
		chunk_size = SO(session)->waiting_chunk_size;

		SO(session)->waiting_chunk      = NULL;
		SO(session)->waiting_chunk_size = 0;
		
		cvp_server_send_chunk_handler(session, chunk, chunk_size);
		return OPSEC_SESSION_OK;
	}

	/*
	 * If we signaled the worker thread to send a chunk and it has not 
	 * done so, avoid signalling it again until it does.
	 */
	if (SO(session)->waiting_for_chunk)
		return OPSEC_SESSION_OK;
	/*
	 * If we are still here, it means we need to tell the worker thread 
	 * that we are interested in the next chunk.
	 */
	if (signal_worker_thread(session, OS_COMM_SEND_CHUNK, NULL, 0, 0))
		return OPSEC_SESSION_ERR;

	SO(session)->waiting_for_chunk = 1;
	
	return OPSEC_SESSION_OK;
}


/* -------------------------------------------------------------------------------------
                                 CVP   server   handlers
   ------------------------------------------------------------------------------------- */

 /* -----------------------------------------------------------------------------
  |  request_handler:
  |  ----------------
  |
  |  Description:
  |  ------------
  |  This is the CVP server's request handler.
  |  This server, first gets all the data from client and stores it in a local file,
  |  then it processes the whole file, sends a reply and sends the (possibly modified)
  |  data back.
  |
  |  Parameters:
  |  -----------
  |  session - Pointer to an OpsecSession object.
  |  info    - A pointer to an OpsecInfo data structure containing additional
  |            information about the transaction.
  |
  |  Returned value:
  |  ---------------
  |  OPSEC_SESSION_OK if successful, OPSEC_SESSION_ERR otherwise.
   ----------------------------------------------------------------------------- */
static int 
request_handler(OpsecSession *session, OpsecInfo *info)
{
	char *filename  = NULL,
	     *command   = NULL;
	int   ftype, proto, action, ret_mode;

	fprintf(stderr, "CVP server request handler invoked\n");

	/*
	 * Retrieve request parameters
	 */
	if (av_cvp_get_request_params(info, &filename, &ftype, &proto, &command, &action, &ret_mode) < 0)
		return OPSEC_SESSION_ERR;

	print_request_parameters(filename, ftype, proto, command, action);

	SO(session)->action = action;
	
	/*
	   keep file name (the pointer is not valid after the return)
	 */
	SO(session)->s_filename = (filename) ? strdup(filename) : strdup("unknown");

	/* tune clear-to-send signal */
	if (set_cts_size(session) < 0)
		return OPSEC_SESSION_ERR;

	/*
	 * we will never attempt to send anything directly from the client to the destination
	 */
	if (cvp_change_buffer_status(session, CVP_SKIP_DST, CVP_INFINITY) < 0)
		return OPSEC_SESSION_ERR;
	
	/*
	 * we need all the data
	 */
	if (cvp_change_buffer_status(session, CVP_TRANSFER_SRV, CVP_INFINITY) < 0)
		return OPSEC_SESSION_ERR;

	/*
	 * Alert the worker thread that the icoming data is about to arive.
	 */
	if (signal_worker_thread(session, OS_COMM_RQ_BEGIN, NULL, 0, SO(session)->s_chunk_size))
		return OPSEC_SESSION_ERR;

	return OPSEC_SESSION_OK;
}

 /* -----------------------------------------------------------------------------
  |  chunk_handler:
  |  --------------
  |
  |  Description:
  |  ------------
  |  This is the CVP server's chunk handler.
  |  It sends the chunks to the worker thread to be accumulated in a local file.
  |
  |  Parameters:
  |  -----------
  |  session - Pointer to an OpsecSession object.
  |  buf     - chunk, from the client.
  |  len     - chunk length.
  |
  |  Returned value:
  |  ---------------
  |  OPSEC_SESSION_OK if successful, OPSEC_SESSION_ERR otherwise.
   ----------------------------------------------------------------------------- */
static int 
chunk_handler(OpsecSession *session, char *buf, int len)
{
	
	fprintf(stderr, "CVP server chunk handler invoked\n");

	if (signal_worker_thread(session, OS_COMM_RECEIVE_CHUNK, buf, len, 0))
		return OPSEC_SESSION_ERR;

	return OPSEC_SESSION_OK;
}

 /* -----------------------------------------------------------------------------
  |  cts_signal_handler:
  |  -------------------
  |
  |  Description:
  |  ------------
  |  This is the CVP server's clear_to_send signal handler.
  |  It sends one chunk and waits for the next cts signal.
  |
  |  Parameters:
  |  -----------
  |  session - Pointer to an OpsecSession object.
  |
  |  Returned value:
  |  ---------------
  |  OPSEC_SESSION_OK if successful, OPSEC_SESSION_ERR otherwise.
   ----------------------------------------------------------------------------- */
static int 
cts_signal_handler(OpsecSession *session, int flow)
{
	int	rc = OPSEC_SESSION_OK;

	fprintf(stderr, "CVP server cts signal handler invoked\n");

	/* Check CTS direction */
	if( !(flow & DST_FLOW) )
		return OPSEC_SESSION_OK;
	
	/* are we trying to send something ? */
	if (SO(session)->s_sending == 0)
		return OPSEC_SESSION_OK;

	/* send a single chunk */
	if ((rc = send_chunk(session)) != OPSEC_SESSION_OK)
		fprintf(stderr, "cts_signal_handler: Failed to send chunk\n");

	return rc;
}

 /* -----------------------------------------------------------------------------
  |  start_handler:
  |  --------------
  |
  |  Description:
  |  ------------
  |  This is the CVP server's start handler.
  |  It initializes the per-session application-level opaque structure.
  |  It also creates the worker thread that will store the data for this session.
  |
  |  Parameters:
  |  -----------
  |  session - Pointer to an OpsecSession object.
  |
  |  Returned value:
  |  ---------------
  |  OPSEC_SESSION_OK if successful, OPSEC_SESSION_ERR otherwise.
   ----------------------------------------------------------------------------- */
static int 
start_handler(OpsecSession *session)
{
	fprintf(stderr, "CVP server start handler invoked\n");

	opsec_suspend_session_read(session);

	SESSION_OPAQUE(session) = (void*)calloc(1, sizeof(struct srv_opaque));

	SO(session)->thr_h = OS_create_thread(cvp_worker_entry_func, session);
	if (!SO(session)->thr_h) {
		fprintf(stderr, "%s: failed to create worker thread for session (%x)\n",
		        ProgName, session);
		return OPSEC_SESSION_ERR;
	}
		
	return OPSEC_SESSION_OK;
}

 /* -----------------------------------------------------------------------------
  |  end_handler:
  |  ------------
  |
  |  Description:
  |  ------------
  |  This is the CVP server's end handler.
  |  Deallocate the per session application-level storage
  |  Alert the worker thread that it should fold-up.
  |  Store the session pointer in the 'dying' session list so that messages
  |  coming in from the worker thread (until it exits) will not be treated.
  |
  |  Parameters:
  |  -----------
  |  session - Pointer to an OpsecSession object.
  |
  |  Returned value:
  |  ---------------
  |  None.
   ----------------------------------------------------------------------------- */
static void 
end_handler(OpsecSession *session)
{
	fprintf(stderr, "CVP server end handler invoked\n\n");
	signal_worker_thread(session, OS_COMM_RQ_END, NULL, 0, 0);

	/* free memory */
	if(SO(session)->s_filename)
		free(SO(session)->s_filename);

	free(SESSION_OPAQUE(session));
	SESSION_OPAQUE(session) = NULL;

	session_list_add(d_sess_lst, session);
}

/***************************************************************************
 * This function tries to send a chunk to the CVP client. If it does not   *
 * succeed, it stores the data on the session opaque in order to try again *
 * the next time a CTS signal is fired. If it succeeds, it signals the     *
 * worker thread to read the next chunk from the temporary file and send   *
 * it over.                                                                *
 ***************************************************************************/
static int
cvp_server_send_chunk_handler(OpsecSession *session, char *data, int len)
{
	if (cvp_send_chunk_to_dst(session, data, len) != 0) {
		/* wait for next clear to send signal */
		fprintf(stderr, "cvp_server_send_chunk_handler: Failed to send. Waiting for next cts signal\n");
		SO(session)->waiting_chunk = data;
		SO(session)->waiting_chunk_size = len;
	} else {
		free(data);
		if (signal_worker_thread(session, OS_MSG_SEND_SUCCESS, NULL, 0, 0))
			return OPSEC_SESSION_ERR;
	}

	return OPSEC_SESSION_OK;
}

/***************************************************************************
 * Event dispatcher for the main thread. This handler sipatches events from*
 * the worker threads. For a description of the events see os_wrappers.h.  *
 *                                                                         *
 * Each event is being tested for validity of the associated session. See  *
 * session_list.c for a detailed explanation.                              *
 ***************************************************************************/

static int 
cvp_server_ev_handler(OpsecEnv * env, long event_no, void *raise_data, void *set_data)
{
	OS_raise_data   *r_data = raise_data;

	if (r_data->command_type == OS_MSG_LAST) {
			session_list_delete(d_sess_lst, r_data->session);
			free(r_data);
			return OPSEC_SESSION_OK;
	}

	if (session_is_in_list(d_sess_lst, r_data->session)) {
		if (r_data->data) free(r_data->data);
		free(r_data);
		return OPSEC_SESSION_OK;
	}

	switch (r_data->command_type) {
		
		case OS_COMM_RECEIVE_CHUNK:
			SO(r_data->session)->waiting_for_chunk = 0;
			cvp_server_send_chunk_handler(r_data->session, r_data->data, r_data->data_len);
			break;

		case OS_COMM_PROCESS:
			process_and_send(r_data->session);
			break;

		case OS_WORKER_THREAD_READY:
			opsec_resume_session_read(r_data->session);
			break;

		case OS_WORKER_THREAD_ERR:
			opsec_end_session(r_data->session);
			break;
			
		default:
			break;
	}

	free(r_data);

	return OPSEC_SESSION_OK;
	
}



/* -------------------------------------------------------------------------------------
                                        M A I N

	The '-v' flag will make the CVP server print all of the events of the inter-
	thread communication.
                                       
   ------------------------------------------------------------------------------------- */
int main(int ac, char *av[])
{
	OpsecEntity         *server;

	ProgName = av[0];

	if(ac == 2 && !strcmp(av[1], "-v"))
		verbose_ = 1;

	d_sess_lst = create_session_list();
	if (!d_sess_lst){
		fprintf(stderr, "%s: create_session_list failed\n",	ProgName);
		exit(1);
	}

	/*
	 * Create environment
	 */
	env = opsec_init(OPSEC_EOL);

	if (env == NULL) {
		fprintf(stderr, "%s: Server thread opsec_init failed (%s)\n",
			ProgName, opsec_errno_str(opsec_errno));
		exit(1);
	}

	/*
	 *  Initialize entity
	 */
	server = opsec_init_entity(env, CVP_SERVER,
	                                OPSEC_ENTITY_NAME, "cvp_server",
	                                CVP_REQUEST_HANDLER, request_handler,
	                                CVP_SERVER_CHUNK_HANDLER, chunk_handler,
	                                CVP_CTS_SIGNAL_HANDLER, cts_signal_handler,
	                                OPSEC_SESSION_START_HANDLER, start_handler,
	                                OPSEC_SESSION_END_HANDLER, end_handler,
	                                OPSEC_SERVER_PORT, (int)htons(18181),
	                                OPSEC_EOL);
	if (server == NULL) {
		fprintf(stderr, "%s: opsec_init_entity failed (%s)\n",
			ProgName, opsec_errno_str(opsec_errno));
		exit(1);
	}

	if (opsec_start_server(server) < 0) {
		fprintf(stderr, "%s: opsec_start_server failed (%s)\n",
			ProgName, opsec_errno_str(opsec_errno));
		exit(1);
	}
	fprintf(stderr, "\nServer is running\n");

	cvp_server_event_id = opsec_new_event_id();

	if (opsec_set_event_handler (env, cvp_server_event_id, 
	                             (OpsecEventHandler) cvp_server_ev_handler, NULL)) {
		fprintf(stderr, "%s: Server thread opsec_set_event_handler failed (%s)\n",
			ProgName, opsec_errno_str(opsec_errno));
		exit(1);
	}

	opsec_mainloop(env);

	fprintf(stderr, "%s: Server thread opsec_mainloop returned\n", ProgName);

	/*
	 * Destroy OPSEC server entity and environment
	 */
	opsec_destroy_entity(server);
	opsec_env_destroy(env);

	session_list_destroy(d_sess_lst);
	
	return 0;
}
