/***************************************************************************
 *                                                                         *
 * cvp_caching_server.c : Sample OPSEC CVP Server                          *
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
 * This CVP server is an example of a caching server.                      *
 *                                                                         *
 * The server responds to two kind of data flows:                          *
 *   1. Request  - sent on an outbound direction.                          *
 *                 The server checks whether it is allowed to send data to *
 *                 source, and if it already has the requested data.       *
 *                 If both conditions are met, the data will be sent to    *
 *                 the source, from the server.                            *
 *                 Otherwise, the server will let the requets pass.        *
 *                                                                         *
 *   2. Response - sent on an inbound direction.                           *
 *                 The server will add the received data to its cache      *
 *                 repository.                                             *
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
   Global definitions (arbitrarily chosen)
 */
#define	CF_DEFAULT_CHUNK_SIZE	4096

#define MALLOC_ERR  0
#define OPSEC_ERR   1

#define	DEFAULT_CHUNK_SIZE	4096

#define SEND_TO_DST  0
#define SEND_TO_SRC  1
#define LET_THROUGH  2

/*
   The following structure will be hanged on the session opaque
 */
struct srv_opaque {
	char   s_mode;
	int    allow_send_to_src;
	char   seen_eof;

	FILE  *cache_file;
	int	   s_chunk_size;

	char  *s_buf;
	int	   s_buf_len;
	char   s_buf_full;

	char   s_src_sending;
};

#define SO(sess) ((struct srv_opaque*)SESSION_OPAQUE(sess))

char *cache_file = "url_file.htm";
char *ProgName   = "Unknown";


/*
 * Prototypes
 */
 static int cts_signal_handler(OpsecSession *session, int flow);


/*
 * Cache API
 *
 * The following two API's are place-holders for caching data.
 * In this sample they were naivly implemented, and do not really perform caching.
 */

 /* -----------------------------------------------------------------------------
  |  is_in_cache:
  |  ------------
  |
  |  Description:
  |  ------------
  |  'is_in_cache' checks wheather certain data exists in the cache repository.
  |  Since this server constantly sends the same cache data, this function just
  |  opens the file, containing the URL page, which will be sent.
  |
  |  Parameters:
  |  -----------
  |  session  - Pointer to an OpsecSession object.
  |  filename - See CVP documentation.
  |  ftype    - See CVP documentation.
  |  proto    - See CVP documentation.
  |  command  - See CVP documentation.
  |  action   - See CVP documentation.
  |
  |  Returned value:
  |  ---------------
  |  '1' if URL file is successfuly opened, 0 otherwise.
   ----------------------------------------------------------------------------- */
int is_in_cache(OpsecSession *session, char *filename, int ftype, int proto, char *command, int action)
{
	if (!(SO(session)->cache_file = fopen(cache_file, "r")))
		return 0;

	return 1;
}

 /* -----------------------------------------------------------------------------
  |  accomulate_data:
  |  ----------------
  |
  |  Description:
  |  ------------
  |  'accomulate_data' stores data into the server's cache repository.
  |  Note that this function perform no real action in this sample.
  |
  |  Parameters:
  |  -----------
  |  session - Pointer to an OpsecSession object.
  |  buff    - buffer to store.
  |  len     - length (in bytes) of the buffer.
  |
  |  Returned value:
  |  ---------------
  |  OPSEC_SESSION_OK
   ----------------------------------------------------------------------------- */
int accomulate_data(OpsecSession *session, char *buff, int len)
{
	return OPSEC_SESSION_OK;
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

 /* -----------------------------------------------------------------------------
  |  set_cts_size:
  |  -------------
  |
  |  Description:
  |  ------------
  |  Tune the CLEAR_TO_SEND mechanism - we want to send chunks of
  |  DEFAULT_CHUNK_SIZE, or as much as possible if this is too big.
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
	size = cvp_cts_src_chunk_size(session, size);
	if (size < 0) {
		fprintf(stderr, "%s: could not set cts size\n", ProgName);
		return OPSEC_SESSION_ERR;
	}

	/* store for future usage */
	SO(session)->s_chunk_size = size;
	
	return size;
}


/* -------------------------------------------------------------------------------------
                           LET_THROUGH, working mode functions
   ------------------------------------------------------------------------------------- */

 /* -----------------------------------------------------------------------------
  |  let_through_request_handler:
  |  ----------------------------
  |
  |  Description:
  |  ------------
  |  Lets data through without any further examination.
  |  Further data does not arrive at the server.
  |
  |  Parameters:
  |  -----------
  |  session - Pointer to an OpsecSession object.
  |
  |  Returned value:
  |  ---------------
  |  OPSEC_SESSION_OK if successful, OPSEC_SESSION_ERR otherwise.
   ----------------------------------------------------------------------------- */
static int let_through_request_handler(OpsecSession *session)
{
	fprintf(stderr, "let_through_request_handler: Sending reply & EOF to client\n");
	
	/* tell cvp client what the status is */
	if (cvp_send_reply(session, CVP_CONTENT_SAFE | CVP_CONTENT_NOT_MODIFIED,
			"ok by default", NULL) != 0)
		return OPSEC_SESSION_ERR;

	/* the server will not need any further data */
	if (cvp_change_buffer_status(session, CVP_SKIP_SRV, CVP_INFINITY) < 0)
		return OPSEC_SESSION_ERR;

	/* pass all remaining data from input buffer to destination... */
	if (cvp_change_buffer_status(session, CVP_TRANSFER_DST, CVP_INFINITY) < 0)
		return OPSEC_SESSION_ERR;

	/* ...then signal eof */
	if (cvp_send_chunk_to_dst(session, NULL, -1) != 0)
		return OPSEC_SESSION_ERR;

	return OPSEC_SESSION_OK;
}


/* -------------------------------------------------------------------------------------
                            SEND_TO_SRC, working mode functions
   ------------------------------------------------------------------------------------- */

 /* -----------------------------------------------------------------------------
  |  send_to_src_send_data:
  |  ----------------------
  |
  |  Description:
  |  ------------
  |  This function sends data to the connection source.
  |  It consists of a 'while' loop which reads data from the url_file
  |  (in 'chunk_size' chunks) and sends it to the client.
  |  
  |  If sending fails, it will wait to the next clear-to-send signal.
  |
  |  Parameters:
  |  -----------
  |  session - Pointer to an OpsecSession object.
  |
  |  Returned value:
  |  ---------------
  |  OPSEC_SESSION_OK if successful, OPSEC_SESSION_ERR otherwise.
   ----------------------------------------------------------------------------- */
static int send_to_src_send_data(OpsecSession *session)
{
	int rc = OPSEC_SESSION_OK;

	while (rc == OPSEC_SESSION_OK) {

		/* Do we need to read from file ? */
		if (!(SO(session)->s_buf_full)) {
		
		SO(session)->s_buf_len = fread (SO(session)->s_buf,
		                                1,
		                                SO(session)->s_chunk_size,
		                                SO(session)->cache_file);

			if (SO(session)->s_buf_len == 0) {

			
				/* fread error ? */
				if (ferror(SO(session)->cache_file)) {
					fprintf(stderr, "send_to_src_send_data: Fread failed\n");
					return OPSEC_SESSION_ERR;
				}

				/* reached end of file */
				fprintf(stderr, "send_to_src_send_data: Reached the end of file\n");
				SO(session)->s_buf_len  = -1;
			}
			else
				/* have something to send */
				SO(session)->s_buf_full = 1;
		}

		/* send data */
		fprintf(stderr, "send_to_src_send_data: Will try to send chunk (len = %d)\n",
				SO(session)->s_buf_len);

		/* should send EOF ? */
		if(SO(session)->s_buf_len == -1) {

			if(cvp_send_chunk_to_src(session, NULL, -1))
				fprintf(stderr, "send_to_src_send_data: Failed to send EOF to dst\n");
			else
				fprintf(stderr, "send_to_src_send_data: Sent EOF to dst\n");
			
			/* just sent eof */
			SO(session)->s_src_sending = 0;
		
			break;
		}

		rc = cvp_send_chunk_to_src(session, SO(session)->s_buf, SO(session)->s_buf_len);
		if(rc == 0) {
			fprintf(stderr, "send_to_src_send_data: Sent %d bytes to client\n", SO(session)->s_buf_len);

			/* no data to send till we read more */
			SO(session)->s_buf_full = 0;
			SO(session)->s_buf_len = -1;
		}
		else {
			/* Failed to send chunk */
			fprintf(stderr, "send_to_src_send_data: Failed to send. Waiting for next cts signal\n");	
			if ((rc == CVP_DATA_FLOW_DIRECTION_ERR) || (rc == CVP_SEND_TO_SRC_DISABLED)) {
				fprintf(stderr, "send_to_src_send_data: Illegal status (%d)\n", rc);
				return OPSEC_SESSION_ERR;
			}
			/* wait for next clear to send signal */
			break;
		}
	}

	return OPSEC_SESSION_OK;
}

 /* -----------------------------------------------------------------------------
  |  send_to_src_request_handler:
  |  ----------------------------
  |
  |  Description:
  |  ------------
  |  This is the 'send to source' request handler.
  |  The function instructs the client to do not pass any data to the destination,
  |  and send all the data to the server.
  |  (Once all the request data will be received in the server it will send back 
  |   the relating cache data).
  |
  |  Parameters:
  |  -----------
  |  session - Pointer to an OpsecSession object.
  |
  |  Returned value:
  |  ---------------
  |  OPSEC_SESSION_OK if successful, OPSEC_SESSION_ERR otherwise.
   ----------------------------------------------------------------------------- */
static int send_to_src_request_handler(OpsecSession *session)
{
	fprintf(stderr, "send_to_src_request_handler invoked\n");

	/* tune clear-to-send signal */
	if (set_cts_size(session) < 0)
		return OPSEC_SESSION_ERR;

	if (! (SO(session)->s_buf = (char *)calloc(SO(session)->s_chunk_size+1, sizeof(char))) ) {
		fprintf(stderr, "send_to_src_request_handler: Calloc failed. exiting.\n");
		exit(MALLOC_ERR);
	}

	/* 
	 * tell cvp client what the status is 
	 */

        if (cvp_send_reply(session, CVP_CONTENT_SAFE | CVP_CONTENT_NOT_MODIFIED,
                        "ok by default", NULL) != 0)
                return OPSEC_SESSION_ERR;

	/*
	 * We will never attempt to send anything from the client to the destination.
	 */
	if (cvp_change_buffer_status(session, CVP_SKIP_DST, CVP_INFINITY) < 0)
		return OPSEC_SESSION_ERR;
	
	/*
	 * we need all the data
	 */
	if (cvp_change_buffer_status(session, CVP_TRANSFER_SRV, CVP_INFINITY) < 0)
		return OPSEC_SESSION_ERR;

	return OPSEC_SESSION_OK;
}

 /* -----------------------------------------------------------------------------
  |  send_to_src_chunk_handler:
  |  --------------------------
  |
  |  Description:
  |  ------------
  |  This is the 'send to source' chunk handler.
  |  The function receives the request chunks from the client.
  |  When EOF is received, it will invoke the 'send_to_src_send_data' function,
  |  which will send the cache data to the client.
  |
  |  Note that, since this is only a sample server, it doen not do any
  |  processing of the data, received from the client.
  |
  |  Parameters:
  |  -----------
  |  session - Pointer to an OpsecSession object.
  |  chunk   - from the client.
  |  len     - length (in bytes) of the chunk.
  |
  |  Returned value:
  |  ---------------
  |  OPSEC_SESSION_OK if successful, OPSEC_SESSION_ERR otherwise.
   ----------------------------------------------------------------------------- */
static int send_to_src_chunk_handler(OpsecSession *session, char *chunk, int len)
{
	fprintf(stderr, "send_to_src_chunk_handler invoked\n");

	/*
	 * Check if EOF
	 */
	if (!chunk) {
		fprintf(stderr, "send_to_src_chunk_handler: Got EOF\n");
		SO(session)->s_src_sending = 1;
		SO(session)->seen_eof      = 1;
		
		/* process as much data as we have */
		return send_to_src_send_data(session);
	}

	/*
	 * Any processing of a chunk from the client should be done here.
	 */

	return OPSEC_SESSION_OK;
}


/* -------------------------------------------------------------------------------------
                            SEND_TO_DST, working mode functions
   ------------------------------------------------------------------------------------- */

 /* -----------------------------------------------------------------------------
  |  send_to_dst_request_handler:
  |  ----------------------------
  |
  |  Description:
  |  ------------
  |  This is the 'send to destination' request handler.
  |
  |  The handler, instructs the client to send all the data to the server.
  |  Since this is a cache server, it assumes the data is safe
  |  (and therefore, sends a 'safe data' reply).
  |
  |  Parameters:
  |  -----------
  |  session - Pointer to an OpsecSession object.
  |
  |  Returned value:
  |  ---------------
  |  OPSEC_SESSION_OK if successful, OPSEC_SESSION_ERR otherwise.
   ----------------------------------------------------------------------------- */
int send_to_dst_request_handler(OpsecSession *session)
{
	int opinion = 0;

	fprintf(stderr, "send_to_dst_request_handler invoked\n");

	/* In oprder to cache, we need all the data. */
	if (cvp_change_buffer_status(session, CVP_TRANSFER_SRV, CVP_INFINITY) < 0)
		return OPSEC_SESSION_ERR;

	/* Yet, no data will be sent back to client. Therefore transfer all to dstination. */
	if (cvp_change_buffer_status(session, CVP_TRANSFER_DST, CVP_INFINITY) < 0)
		return OPSEC_SESSION_ERR;

	opinion = CVP_CONTENT_SAFE | CVP_CONTENT_NOT_MODIFIED;
	if (cvp_send_reply(session, opinion, "Cache server: Assuming safe data", NULL) != 0)
		return OPSEC_SESSION_ERR;

	return OPSEC_SESSION_OK;
}

 /* -----------------------------------------------------------------------------
  |  send_to_dst_chunk_handler:
  |  --------------------------
  |
  |  Description:
  |  ------------
  |  This is the 'send to destination' chunk handler.
  |
  |  The handler stores each chunk it receives.
  |  No modification of the data is done.
  |
  |  When EOF is received, the handler invokes the CTS handler.
  |
  |  Parameters:
  |  -----------
  |  session - Pointer to an OpsecSession object.
  |
  |  Returned value:
  |  ---------------
  |  OPSEC_SESSION_OK if successful, OPSEC_SESSION_ERR otherwise.
   ----------------------------------------------------------------------------- */
int send_to_dst_chunk_handler(OpsecSession *session, char *chunk, int len)
{
	int rc = 0;

	fprintf(stderr, "send_to_dst_chunk_handler invoked\n");

	if (chunk) {
		/* Add chunk to database */
		if (accomulate_data(session, chunk, len))
			return OPSEC_SESSION_ERR;
	}
	else { /* received EOF */
		fprintf(stderr, "send_to_dst_chunk_handler: Received EOF\n");
		SO(session)->seen_eof = 1;
			
		cts_signal_handler(session, DST_FLOW);
	}

	return OPSEC_SESSION_OK;
}


 /* -------------------------------------------------------------------------------------
                                     CVP server handlers
    ------------------------------------------------------------------------------------- */

 /* -----------------------------------------------------------------------------
  |  deny_request:
  |  -------------
  |
  |  Description:
  |  ------------
  |  This function is used for sending a 'cannot handle reply' reply to the client.
  |  If no failure occures, it will return OPSEC_SESSION_END.
  |  This return value will cause the closing of the session (see OPSEC documentation).
  |
  |  Parameters:
  |  -----------
  |  session - Pointer to an OpsecSession object.
  |
  |  Returned value:
  |  ---------------
  |  OPSEC_SESSION_END if successful, OPSEC_SESSION_ERR otherwise.
   ----------------------------------------------------------------------------- */
int deny_request(OpsecSession *session)
{
	fprintf(stderr, "deny_request: Unable to process request\n");
	
	/* tell cvp client what the status is */
	if (cvp_send_reply(session, CVP_CANNOT_HANDLE_REQUEST, "Unable to process request", NULL) != 0)
		return OPSEC_SESSION_ERR;

	/* the server will not need any further data */
	if (cvp_change_buffer_status(session, CVP_SKIP_SRV, CVP_INFINITY) < 0)
		return OPSEC_SESSION_ERR;

	/* do not pass any remaining data to destination... */
	if (cvp_change_buffer_status(session, CVP_SKIP_DST, CVP_INFINITY) < 0)
		return OPSEC_SESSION_ERR;

	/* ...then signal EOF */
	if (cvp_send_chunk_to_dst(session, NULL, -1) != 0)
		return OPSEC_SESSION_ERR;

	return OPSEC_SESSION_END;
}

/* -----------------------------------------------------------------------------
  |  request_handler:
  |  ----------------
  |
  |  Description:
  |  ------------
  |  This is the CVP server's request handler.
  |  It checks the connection parameter and determines
  |  the server's handling scheme accordingly.
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
	char *filename    = NULL,
	     *command     = NULL,
	     *src_flow    = NULL,
	     *dual_flow   = NULL;
	char *direction   = NULL;
	int   ftype, proto, action, ret_mode,
	      send_to_src = 0,
	      request     = 0,
	      response    = 0;
	
	int   rc = OPSEC_SESSION_OK;


	fprintf(stderr, "CVP server request handler invoked\n");

	/*
	 * Retrieve request parameters
	 */
	if (av_cvp_get_request_params(info, &filename, &ftype, &proto, &command, &action, &ret_mode) < 0)
		return OPSEC_SESSION_ERR;
	
	print_request_parameters(filename, ftype, proto, command, action);

	/*
	 * Check connection direction
	 */
	direction = opsec_info_get(info, "direction", NULL);
	if (!direction) {
		fprintf(stderr, "request_handler: cannot find 'direction' in OpsecInfo\n");
		return deny_request(session);
	}

	fprintf(stderr, "request_handler: Direction = %s\n", direction);

	/* Check source flow availability */
	src_flow = opsec_info_get(info, "allow_send_to_source", NULL);
	if(!src_flow || strcmp(src_flow, "true")) {
		fprintf(stderr, "request_handler: Server is not allowed to send to source\n");
	
		/* The server is not allowed to send to source. This is ok if the direction is response */
		if (!strcmp(direction, "request")) {
			/* Send deny
			   (cache server must be allowed to send to source on outbound direction) */
			fprintf(stderr, "request_handler: Unable to send to source on outbound connection\n");
			return deny_request(session);
		}
	}
	else
		fprintf(stderr, "request_handler: Server is allowed to send to source\n");
	

	/*
	 * Determine working mode
	 */
	if (strcmp(direction, "request") == 0) {
		if (is_in_cache(session, filename, ftype, proto, command, action)) {
			SO(session)->s_mode = SEND_TO_SRC;
			fprintf(stderr, "CVP server working mode: %s\n", "SEND_TO_SRC");
			rc = send_to_src_request_handler(session);
		}
		else {
			fprintf(stderr, "Requested data not found in cache repository\n");
			SO(session)->s_mode = LET_THROUGH;
			fprintf(stderr, "CVP server working mode: %s\n", "LET_THROUGH");
			rc = let_through_request_handler(session);
		}
	}
	else {
		SO(session)->s_mode = SEND_TO_DST;
		fprintf(stderr, "CVP server working mode: %s\n", "SEND_TO_DST");
		rc = send_to_dst_request_handler(session);
	}
	
	return rc;
}

 /* -----------------------------------------------------------------------------
  |  chunk_handler:
  |  --------------
  |
  |  Description:
  |  ------------
  |  This is the CVP server's chunk handler.
  |  It perform the action relevant to this session mode.
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
	fprintf(stderr, "CVP server chunk handler invoked: Received chunk (buff=%x len=%d)\n",
	           buf, len);

	switch (SO(session)->s_mode) {
		case SEND_TO_SRC:
			return send_to_src_chunk_handler(session, buf, len);
		
		case SEND_TO_DST:
			return send_to_dst_chunk_handler(session, buf, len);
		
		case LET_THROUGH:
			return OPSEC_SESSION_OK;
		
		default:
			fprintf(stderr, "%s: unexpected mode in chunk handler\n", ProgName);
			return OPSEC_SESSION_ERR;
	}
}

 /* -----------------------------------------------------------------------------
  |  cts_signal_handler:
  |  -------------------
  |
  |  Description:
  |  ------------
  |  This is the CVP server's clear_to_send handler.
  |  It deals with CTS for both flow directions,
  |  and performs the action relevant to this session mode.
  |
  |  Parameters:
  |  -----------
  |  session - Pointer to an OpsecSession object.
  |  flow    - to which the CTS is intended.
  |
  |  Returned value:
  |  ---------------
  |  OPSEC_SESSION_OK if successful, OPSEC_SESSION_ERR otherwise.
   ----------------------------------------------------------------------------- */
static int cts_signal_handler(OpsecSession *session, int flow)
{
	fprintf(stderr, "CVP server cts signal handler invoked\n");

	if (SO(session)->s_mode == LET_THROUGH)
		return OPSEC_SESSION_OK;

	if ((flow & DST_FLOW) && (SO(session)->seen_eof)) {
		if ( !(cvp_send_chunk_to_dst(session, NULL, -1)) )
			fprintf(stderr, "cts_signal_handler: Sent EOF on destination flow\n");
		/* else, if failed, wait for the next clear-to-send signal */
	}

	if ((flow & SRC_FLOW) && (SO(session)->s_src_sending))
		if ((send_to_src_send_data(session)) != OPSEC_SESSION_OK) {
			fprintf(stderr, "cts_signal_handler: failed to send data to source\n");
			return OPSEC_SESSION_ERR;
		}

	return OPSEC_SESSION_OK;
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
  |  It deallocate the per session application-level storage and
  |  removes the cache file, if used.
  |
  |  Parameters:
  |  -----------
  |  session - Pointer to an OpsecSession object.
  |
  |  Returned value:
  |  ---------------
  |  OPSEC_SESSION_OK if successful, OPSEC_SESSION_ERR otherwise.
   ----------------------------------------------------------------------------- */
static void end_handler(OpsecSession *session)
{
	fprintf(stderr, "CVP server end handler invoked\n");

	/* close the cache file */
	if (SO(session)->cache_file) {
		if (fclose(SO(session)->cache_file) != 0)
			fprintf(stderr, "%s: fclose failed: %s\n", ProgName, strerror(errno));
		SO(session)->cache_file = NULL; 
	}

	if (SESSION_OPAQUE(session)) {
		free(SESSION_OPAQUE(session));
		SESSION_OPAQUE(session) = NULL;
	}
}

 /* -----------------------------------------------------------------------------
  |  
  |  Main
  |  
   ----------------------------------------------------------------------------- */
int
main(int ac, char *av[])
{
	OpsecEnv    *env = NULL;
	OpsecEntity *server = NULL;

	ProgName = av[0];

	/*
	 * Create environment
	 */
	env = opsec_init(OPSEC_EOL);

	if (env == NULL) {
		fprintf(stderr, "%s: opsec_init failed (%s)\n",
			ProgName, opsec_errno_str(opsec_errno));
		exit(OPSEC_ERR);
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
		exit(OPSEC_ERR);
	}

	if (opsec_start_server(server) < 0) {
		fprintf(stderr, "%s: opsec_start_server failed (%s)\n",
			ProgName, opsec_errno_str(opsec_errno));
		exit(OPSEC_ERR);
	}
	fprintf(stderr, "\nServer is running\n");

	opsec_mainloop(env);

	/* Destroy OPSEC server entity and environment */
	opsec_destroy_entity(server);
	opsec_env_destroy(env);

	fprintf(stderr, "%s: opsec_mainloop returned\n", ProgName);
	
	return 0;
}

