/***************************************************************************
 *                                                                         *
 * cvp_av_server.c : Sample OPSEC CVP Server                               *
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
 * This is a sample for a CVP Anti Virus server.                           *
 *                                                                         *
 * The server operates as followes:                                        *
 *                                                                         *
 *   1. Receives all data from the client.                                 *
 *                                                                         *
 *   2. Processes the file and determines the data safty.                  *
 *                                                                         *
 *   3. Sends a reply and the file back to the client.                     *
 *      Note that since the server asks for the whole data stream          *
 *      before it starts processing it, the file must be sent back         *
 *      (modified or not) since the client does not hold a copy            *
 *      of the file.                                                       *
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


/*
   Global definitions
 */
#define	DEFAULT_CHUNK_SIZE	4096

/*
   The following structure will be hanged on the session opaque
 */
struct srv_opaque {
	char  *s_filename;
	char   s_tempname[L_tmpnam];
	FILE  *s_fp;

	int    action;
	int    s_chunk_size;

	char   s_buf[DEFAULT_CHUNK_SIZE];
	int    s_buf_len;
	char   s_buf_full;

	char   s_eof;
	char   s_sending;
};

#define SO(session) ((struct srv_opaque*)SESSION_OPAQUE(session))

char *ProgName = "Unknown";

/*
 * Prototypes
 */
 static int cts_signal_handler(OpsecSession *session, int flow);


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
void print_request_parameters(char *filename, int ftype, int proto, char *command, int action)
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

int fix_file(OpsecSession *session)
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
static int process_file(OpsecSession *session, int *opinion, char *log_msg, char *warning)
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
static int process_and_send(OpsecSession *session)
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

	/* open the scratch file */
	SO(session)->s_fp = fopen(SO(session)->s_tempname, "rb");
	if (SO(session)->s_fp == NULL) {
		fprintf(stderr, "%s: fopen('%s', 'rb') failed: %s\n",
			ProgName, SO(session)->s_tempname, strerror(errno));
		return OPSEC_SESSION_ERR;
	}

	/* and send it */
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
static int send_chunk(OpsecSession *session)
{
	FILE *fp  = SO(session)->s_fp;
	char *buf = SO(session)->s_buf;

	/* need to read data from file ? */
	if (! SO(session)->s_buf_full) {
		fprintf(stderr, "send_chunk: Reading data from file\n");
		SO(session)->s_buf_len = fread(buf, 1, SO(session)->s_chunk_size, fp);

		if (SO(session)->s_buf_len == 0) {
			/* fread error ? */
			if (ferror(fp)) {
				fprintf(stderr, "%s: fread('%s') failed: %s\n",
					ProgName, SO(session)->s_tempname, strerror(errno));
				return OPSEC_SESSION_ERR;
			}

			/* reached end of file */
			fprintf(stderr, "send_chunk: Reached the end of file\n");
			SO(session)->s_buf_len = -1;
			SO(session)->s_eof = 1;
			buf = NULL;
		}

		/* have something to send */
		SO(session)->s_buf_full = 1;
	}

	/* send data */
	fprintf(stderr, "send_chunk: Will try to send chunk (len = %d)\n",
			SO(session)->s_buf_len);
	if (cvp_send_chunk_to_dst(session, buf, SO(session)->s_buf_len) == 0) {

		/* just sent eof ? */
		if (buf == NULL)
			/* send completed */
			SO(session)->s_sending = 0;

		/* no data to send till we read more */
		SO(session)->s_buf_full = 0;
	}
	else {
		fprintf(stderr, "send_chunk: Failed to send. Waiting for next cts signal\n");	
		/* wait for next clear to send signal */
	}

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
static int request_handler(OpsecSession *session, OpsecInfo *info)
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

	/* choose a file name for the local copy ... */
	(void)tmpnam(SO(session)->s_tempname);
	fprintf(stderr, "request_handler: Temporary file name: %s\n", SO(session)->s_tempname);

	/* ..and open it */
	SO(session)->s_fp = fopen(SO(session)->s_tempname, "wb");
	if (SO(session)->s_fp == NULL) {
		fprintf(stderr, "%s: fopen('%s', 'wb') failed: %s\n",
			ProgName, SO(session)->s_tempname, strerror(errno));
		return OPSEC_SESSION_ERR;
	}

	return OPSEC_SESSION_OK;
}

 /* -----------------------------------------------------------------------------
  |  chunk_handler:
  |  --------------
  |
  |  Description:
  |  ------------
  |  This is the CVP server's chunk handler.
  |  It accumulates all incoming chunks in the local scratch file.
  |  When EOF arrives, it starts the processing of the local scratch file.
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
static int chunk_handler(OpsecSession *session, char *buf, int len)
{
	fprintf(stderr, "CVP server chunk handler invoked\n");

	if (buf == NULL) {	/* EOF received ? */
		fprintf(stderr, "chunk_handler: Received EOF\n");
		/* close the scratch file.. */
		if (fclose(SO(session)->s_fp) != 0) {
			fprintf(stderr, "%s: fclose('%s') failed: %s\n",
				ProgName, SO(session)->s_tempname, strerror(errno));
			return OPSEC_SESSION_ERR;
		}
		SO(session)->s_fp = NULL;

		/* .. and process it */
		return process_and_send(session);
	}

	fprintf(stderr, "chunk_handler: Received chunk (buff = %x, len = %d\n", buf, len);
	if ((int)fwrite(buf, 1, len, SO(session)->s_fp) != len) {
		fprintf(stderr, "%s: fwrite(%d, '%s') failed: %s\n",
			ProgName, len, SO(session)->s_tempname,	strerror(errno));
		return OPSEC_SESSION_ERR;
	}
	
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
static int cts_signal_handler(OpsecSession *session, int flow)
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
  |
  |  Parameters:
  |  -----------
  |  session - Pointer to an OpsecSession object.
  |
  |  Returned value:
  |  ---------------
  |  OPSEC_SESSION_OK if successful, OPSEC_SESSION_ERR otherwise.
   ----------------------------------------------------------------------------- */
static int start_handler(OpsecSession *session)
{
	fprintf(stderr, "CVP server start handler invoked\n");

	SESSION_OPAQUE(session) = (void*)calloc(1, sizeof(struct srv_opaque));
	
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
  |  remove the scratch file, if used.
  |
  |  Parameters:
  |  -----------
  |  session - Pointer to an OpsecSession object.
  |
  |  Returned value:
  |  ---------------
  |  None.
   ----------------------------------------------------------------------------- */
static void end_handler(OpsecSession *session)
{
	fprintf(stderr, "CVP server end handler invoked\n\n");

	/* close the scratch file */
	if (SO(session)->s_fp) {
		if (fclose(SO(session)->s_fp) != 0)
			fprintf(stderr, "%s: fclose('%s') failed: %s\n",
				ProgName, SO(session)->s_tempname,
				strerror(errno));
		SO(session)->s_fp = NULL; 
	}

	if (SO(session)->s_tempname[0]) {

		/* remove the scratch file */
		if (remove(SO(session)->s_tempname) < 0) {
			fprintf(stderr, "%s: remove '%s' failed: %s\n",
				ProgName, SO(session)->s_tempname,
				strerror(errno));
		}
		SO(session)->s_tempname[0] = '\0';
	}

	/* free memory */
	if(SO(session)->s_filename)
		free(SO(session)->s_filename);

	free(SESSION_OPAQUE(session));
	SESSION_OPAQUE(session) = NULL;
}


/* -------------------------------------------------------------------------------------
                                        M A I N
   ------------------------------------------------------------------------------------- */
int main(int ac, char *av[])
{
	OpsecEnv    *env;
	OpsecEntity *server;

	ProgName = av[0];

	/*
	 * Create environment
	 */
	env = opsec_init(OPSEC_EOL);

	if (env == NULL) {
		fprintf(stderr, "%s: opsec_init failed (%s)\n",
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

	opsec_mainloop(env);

	fprintf(stderr, "%s: opsec_mainloop returned\n", ProgName);

	/*
	 * Destroy OPSEC server entity and environment
	 */
	opsec_destroy_entity(server);
	opsec_env_destroy(env);

	return 0;
}
