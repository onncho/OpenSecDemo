 /*************************************************************************\
 *                                                                         *
 * cvp_filter_server.c : Sample OPSEC CVP Server                           *
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
 \*************************************************************************/

 /*************************************************************************\
 * This is a sample for a CVP filter server.                               *
 *                                                                         *
 * The server operates as followes:                                        *
 *                                                                         *
 * 1. The server asks the client for chunks of agreed size, one by one     *
 *                                                                         *
 * 2. When the server accumulates a full chunk it process it               *
 *                                                                         *
 * 3. Modified chunks are sent to the client                               *
 *                                                                         *
 * 4. When the server finish inspecting a chunk, the flow of data is       *
 *    resumed                                                              *
 *                                                                         *
 * 5. When the server gets EOF, it send the opinion and EOF to the client  *
 *                                                                         *
 \*************************************************************************/

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
 * Global definitions
 */

#define	DEFAULT_CHUNK_SIZE      4096

#define MODIFIED_CHUNK          1
#define CHUNK_OK                0

#define SENT_CHUNK              0
#define DIDNT_SEND_CHUNK        1

/*
 * The following structure will be hanged on the session opaque
 */

struct srv_opaque {

	int    s_chunk_size;            /* the working and sending chunk size                            */
	char   *curr_chunk;             /* a pointer to the current chunk                                */
	int    curr_chunk_len;          /* the amount of data in the current chunk                       */
	int    curr_chunk_status;       /* the status of the current chunk                               */
	int    got_eof;                 /* a flag indicating that EOF arrived                            */
	char   s_sending;               /* a flag indicating that there is data waiting to be sent       */
	int    modified;                /* a flag indicating whether the server modified the data stream */
	char   *file_name;              /* the name of the inspected file                                */
};

#define SO(session) ((struct srv_opaque*)SESSION_OPAQUE(session))


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
	 * Return value will be the minimum between the input 'size' argument 
	 * and the maximum allowed quantity (dependednt on the client)
	 */
	size = cvp_cts_chunk_size(session, size);
	if (size < 0) {
		fprintf(stderr, "set_cts_size: could not set cts size\n");
		return -1;
	}

	/* Store for future usage */
	SO(session)->s_chunk_size = size;

	return size;
}

/* -----------------------------------------------------------------------------------
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

/*--------------------------------------------------------------------------------------
 | send_chunk
 | ----------
 |
 | Description:
 | ------------
 | This function sends a chunk to the client. If it fails to send the chunk it waits for the 
 | next clear to send event. 
 | 
 | Parameters:
 | -----------
 |  session - Pointer to an OpsecSession object.
 | 
 | Returned value:
 | ---------------
 | SENT_CHUNK or DIDNT_SEND_CHUNK  
 --------------------------------------------------------------------------------------- */

static int send_chunk(OpsecSession *session) 
{
	int   rc = 0;
 
	rc = cvp_send_chunk_to_dst(session, SO(session)->curr_chunk, SO(session)->curr_chunk_len);
	if  (rc != 0) {

		SO(session)->s_sending = 1;
       	        return DIDNT_SEND_CHUNK;
       	}
	SO(session)->s_sending = 0;
	return SENT_CHUNK;	
}

/*--------------------------------------------------------------------------------------
 | send_reply_and_eof
 | ------------------
 |
 | Description:
 | ------------
 | This function sends the reply and EOF to the CVP client
 |
 | Parameters:
 | -----------
 |  session - Pointer to an OpsecSession object.
 |
 | Returned value:
 | ---------------
 | OPSEC_SESSION_OK if succeeded, OPSEC_SESSION_ERR otherwise.
 --------------------------------------------------------------------------------------- */

static int send_reply_and_eof(OpsecSession *session) 
{
	int  rc = OPSEC_SESSION_OK;
	char log[256];
	int  opinion;

	/*
	 * send EOF
	 */

        rc = cvp_send_chunk_to_dst(session, NULL, -1);
	if (rc != 0)
		return OPSEC_SESSION_ERR;

	/*
	 * form and send the opnion
	 */

	if (SO(session)->modified)
       		opinion =  CVP_CONTENT_SAFE | CVP_CONTENT_MODIFIED;
        else
                opinion =  CVP_CONTENT_SAFE | CVP_CONTENT_NOT_MODIFIED;

        sprintf(log, "filter server finshed inspecting file %s", SO(session)->file_name);
        rc = cvp_send_reply(session, opinion, log, NULL);
        if (rc != 0) {

                fprintf(stderr, "Failed to send reply\n");
                return OPSEC_SESSION_ERR;
        }

        fprintf(stderr,"sent reply to client\n log = %s\n opinion = %d\n", log, opinion);
	return OPSEC_SESSION_OK;
}

/*--------------------------------------------------------------------------------------
 | flow_control
 | ------------
 |
 | Description:
 | ------------
 | This function manage the CVP data flow
 |
 | Parameters:
 | -----------
 |  session - Pointer to an OpsecSession object.
 |
 | Returned value:
 | ---------------
 | OPSEC_SESSION_OK if succeeded, OPSEC_SESSION_ERR otherwise.
 --------------------------------------------------------------------------------------- */

static int flow_control(OpsecSession *session) 
{
	int rc = OPSEC_SESSION_OK;

	if (SO(session)->curr_chunk_status == CHUNK_OK) {

		rc = cvp_change_buffer_status(session, CVP_TRANSFER_DST, SO(session)->curr_chunk_len);

	} else {

		rc = cvp_change_buffer_status(session, CVP_SKIP_DST, SO(session)->curr_chunk_len);
	}
	if (rc != 0)
		return OPSEC_SESSION_ERR;

	if (SO(session)->got_eof) {

		rc = send_reply_and_eof(session);

	} else {

		rc = cvp_change_buffer_status(session, CVP_TRANSFER_SRV, SO(session)->s_chunk_size);
		SO(session)->curr_chunk_len = 0;
	}
	if (rc != 0)
                return OPSEC_SESSION_ERR;
	else
		return OPSEC_SESSION_OK;
}

/*--------------------------------------------------------------------------------------
 | filter_process_and_send
 | -----------------------
 |
 | Description:
 | ------------
 | This function should contain the core filter technology in a real server.
 |
 | Parameters:
 | -----------
 | session - Pointer to an OpsecSession object.
 | 
 | Returned value:
 | ---------------
 | OPSEC_SESSION_OK if send_chunk() didn't send the chunk, the value returned by 
 | flow_control() if send_chunk() succeeded.
 --------------------------------------------------------------------------------------- */

static int filter_process_and_send(OpsecSession *session) 
{
	int rc = SENT_CHUNK;

	/*
	 * Here we would have implamented the filter
	 */
	
	if (SO(session)->curr_chunk_status == MODIFIED_CHUNK) {

		rc = send_chunk(session);

		/* 
		 * if we failed sending the chunk, wait for the next CTS event
		 */

		if (rc == DIDNT_SEND_CHUNK)  {

               		return (OPSEC_SESSION_OK);
                }
	}
	return flow_control(session);
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
  |  It gets the data parmaeters from the client and initiate the flow of data 
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
	int   rc = OPSEC_SESSION_OK;

	fprintf(stderr, "CVP server request handler invoked\n");

	/*
	 * Retrieve request parameters
	 */

	if (av_cvp_get_request_params(info, &filename, &ftype, &proto, &command, &action, &ret_mode) < 0)
		return OPSEC_SESSION_ERR;

	print_request_parameters(filename, ftype, proto, command, action);

	/*
	 * Make sure we are allowed to modify the file and check the client return mode
	 */

	if (action != CVP_RDWR) {

		fprintf(stderr, "Client doesn't allow server to modify data. Aborting.\n");
		cvp_send_reply(session, 
		               CVP_CANNOT_HANDLE_REQUEST, 
		               "filter failed because client doesn't allow content to be modified", 
		               NULL); 
		return OPSEC_SESSION_END;
	}
	if (ret_mode == CVP_REPLY_FIRST) {

		/* 
		 * This sample server forms its opinion only after processing data.
		 */ 
		
		fprintf(stderr, "Client return mode is CVP_REPLY_FIRST. Aborting.\n");
		cvp_send_reply(session,
		               CVP_CANNOT_HANDLE_REQUEST,
		               "filter failed because client doesn't allow to send reply after sending data",
		               NULL);
		return OPSEC_SESSION_END;
	} 

	if (filename)
		SO(session)->file_name = strdup(filename);
	else
		SO(session)->file_name = strdup("unknown");
	
	/* Tune clear-to-send signal */

	if (set_cts_size(session) < 0)
		return OPSEC_SESSION_ERR;

	/*
	 * Ask the client for the first chunk
	 */

	rc = cvp_change_buffer_status(session, CVP_TRANSFER_SRV, SO(session)->s_chunk_size);
	if (rc == -1) 
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
  |  It accumulates incoming data until it has a full chunk, then it starts
  |  the filtering process.
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
	int chunk_length = SO(session)->curr_chunk_len;

	fprintf(stderr, "CVP server chunk handler invoked\n");

	if (buf == NULL) {	/* EOF received ? */

		fprintf(stderr, "chunk_handler: Received EOF\n");
		SO(session)->got_eof = 1;

	} else {

		SO(session)->curr_chunk_len += len;
		if (SO(session)->curr_chunk_len > SO(session)->s_chunk_size){

			fprintf(stderr, "Error, got more data then asked for\n");	
			return OPSEC_SESSION_ERR;
		}  
		memcpy(SO(session)->curr_chunk + chunk_length, buf, len);
		if (SO(session)->curr_chunk_len < SO(session)->s_chunk_size)
			return OPSEC_SESSION_OK;
	}
	return filter_process_and_send(session);
}

 /* -----------------------------------------------------------------------------
  |  cts_signal_handler:
  |  -------------------
  |
  |  Description:
  |  ------------
  |  This is the CVP server's clear_to-send handler.
  |  If there is a chunk waiting to be sent, it tries to send it.
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

	fprintf(stderr, "CVP server cts handler invoked\n");

	/* If we have data to send, send it */

	if (SO(session)->s_sending) {

		rc = send_chunk(session);

		/* 
                 * if we failed sending the chunk, wait for the next CTS event
                 */

                if (rc == DIDNT_SEND_CHUNK)  {

			return (OPSEC_SESSION_OK);
                }
		rc = flow_control(session);
	}        
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

	if(!(SESSION_OPAQUE(session) = (void*)calloc(1, sizeof(struct srv_opaque)))) {
		fprintf(stderr, "ERROR - unable to allocate session opaque\n");
		return OPSEC_SESSION_ERR;
	}
	
	SO(session)->curr_chunk = (void*)calloc(1, DEFAULT_CHUNK_SIZE);
	if (!SO(session)->curr_chunk) {
		fprintf(stderr, "ERROR - unable to allocate chunk\n");
		free(SESSION_OPAQUE(session));
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

	/* Free memory */

	if (SO(session)->curr_chunk) 
		free (SO(session)->curr_chunk);
	if (SO(session)->file_name)
		free(SO(session)->file_name);
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
	char        *ProgName;
	
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
