/***************************************************************************
 *                                                                         *
 * ela_client.c : Sample OPSEC ELA Client                                  *
 *                                                                         *
 * This is a part of the Check Point OPSEC SDK                             *
 * Copyright (c) 1994-2000 Check Point Software Technologies, Ltd.         *
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
 * This is an example of a common use of ELA API.                          *
 * The client sends three logs once a session is up and active (this is    *
 * made sure using the OPSEC_SESSION_ESTABLISHED_HANDLER).                 *
 * Generally, external log events will cause the client's logs sending.    *
 *                                                                         *
 * Note that most definitions and values in this application are chosen    *
 * for the sake of this sample and will be replaced in real life           *
 * applications.                                                           *
 *                                                                         *
 ***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef WIN32
#include <winsock.h>
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "opsec/opsec.h"
#include "opsec/opsec_error.h"
#include "opsec/ela.h"
#include "opsec/ela_opsec.h"

/*
    --------------------
     Global definitions
    --------------------
 */

/*
   The following structure will be hanged on the session opaque
 */
typedef struct _Info{
	OpsecEntity	*server;
	OpsecEntity	*client;
	Ela_CONTEXT	*ctx;
}Info;

#define SESSION_INFO(s) ((Info *)SESSION_OPAQUE(s))

#define ELA_PORT  18187


/*
 * Although the next two structures relate to Ela_CONTEXT they can be
 * stored using the SESSION_OPAQUE macro if they are session specific.
 */
struct _FormatFields{
	Ela_FF *product;
	Ela_FF *user;
}FormatFields;

struct _Resolvers{
	Ela_ResInfo *uid2name;
	Ela_ResInfo *comp;
}Resolvers;

/*
   Arbitrary values definitions used for logs data
 */
#define PROD_ID 1
#define INFO_ID 2
#define SRC_IP  "127.0.0.1"


/*
    ------------------
     Global functions
    ------------------
 */


 /* -----------------------------------------------------------------------------
  |  compose_and_send_log:
  |  ---------------------
  |
  |  Description:
  |  ------------
  |  This function builds and sends an ELA log.
  |  Note the usage of the resolvers and the format fields while building the log.
  |
  |  Parameters:
  |  -----------
  |  session - returned by a call to ela_new_session.
  |  user_id - used as an arbitrary data for the log.
  |
  |  Returned value:
  |  ---------------
  |  OPSEC_SESSION_OK if successful, OPSEC_SESSION_ERR otherwise.
   ----------------------------------------------------------------------------- */

int compose_and_send_log(OpsecSession *session, int user_id)
{
	Ela_LOG *log = NULL;
	int      rc  = OPSEC_SESSION_OK;

	if (!session) {
		fprintf(stderr, "compose_and_send_log: Received NULL session. Aborting log\n");
		return OPSEC_SESSION_ERR;
	}

	if (! (log = ela_log_create(SESSION_INFO(session)->ctx)) ){
		fprintf(stderr, "compose_and_send_log: Unable to create log. Aborting log\n");
		return OPSEC_SESSION_ERR;
	}

	fprintf(stdout,
		"compose_and_send_log: Adding fields product=%d, user_id=%d, info_url=%d, src=%s\n",
		PROD_ID, user_id, INFO_ID, SRC_IP);

	rc |= ela_log_add_field(log, FormatFields.product, Resolvers.comp, PROD_ID);
	rc |= ela_log_add_field(log, FormatFields.user, Resolvers.uid2name, user_id);
	rc |= ela_log_add_raw_field(log, "info_url", ELA_VT_INDEX, Resolvers.comp, INFO_ID);
	rc |= ela_log_add_raw_field(log, "src"  , ELA_VT_IP, NULL, inet_addr(SRC_IP));

	if(rc != OPSEC_SESSION_OK)
		fprintf(stderr, "compose_and_send_log: Error while adding fields to log. Aborting log\n");
	else {
		fprintf(stdout, "compose_and_send_log: Sending log\n");
		rc |= ela_send_log(session, log);	/* Actual log sending */
	}
	
	ela_log_destroy(log);
	
	return rc;
}

 /* -----------------------------------------------------------------------------
  |  activate_client:
  |  ---------------
  |
  |  Description:
  |  ------------
  |  Initializes a new opsec session.
  |
  |  Parameters:
  |  -----------
  |  info - Containing information which will be hanged on the session opaque.
  |
  |  Returned value:
  |  ---------------
  |  None.
   ----------------------------------------------------------------------------- */
void activate_client(void *info_)
{
	OpsecSession *session = NULL;
	Info         *info    = (Info *)info_;
	int           idx     = 0;

	/*
	 * Create log session
	 */
	if(!(session = ela_new_session(info->client, info->server, info->ctx)))
	{
		fprintf(stderr, "Unable to create session (%s)!\n", opsec_errno_str(-1));
		exit(1);
	}

	(SESSION_OPAQUE(session)) = info;

	/*
	   Once the session is established, the "session_established handler"
	   will be invoked, causing logs to be sent the server.
	 */

	return;
}

/*
    ---------------------
     ELA client handlers
    ---------------------
 */
 /* -----------------------------------------------------------------------------
  |  pong_handler:
  |  -------------
  |
  |  Description:
  |  ------------
  |  This handler function will be called when a reply arrives from a pinged entity
  |  and will close the ela session.
  |
  |  Parameters:
  |  -----------
  |  session       - returned by a call to ela_new_session.
  |  mask          - Reserved for future use. A bitmask to be used with info.
  |  info          - Reserved for future use. An OpsecInfo structure containing
  |                  additional parameters.
  |  interval_time - The round trip time in milliseconds.
  |  status        - Ok, Err or timeout.
  |  opaque        - User-supplied data to be passed to the callback function.
  |
  |  Returned value:
  |  ---------------
  |  None.
   ----------------------------------------------------------------------------- */
void pong_handler(OpsecSession *session,
                  unsigned int  bitmask,
                  OpsecInfo    *info,
                  long          interval_time,
                  int           status,
                  void         *opq)
{
	fprintf(stderr, "pong_handler: closing session\n");
	ela_end_session(session);
}

 /* -----------------------------------------------------------------------------
  |  session_established_handler:
  |  ----------------------------
  |
  |  Description:
  |  ------------
  |  Sends three logs and sends ping to the ELA server.
  |
  |  Parameters:
  |  -----------
  |  session - returned by a call to ela_new_session.
  |
  |  Returned value:
  |  ---------------
  |  OPSEC_SESSION_OK if successful, OPSEC_SESSION_ERR otherwise.
   ----------------------------------------------------------------------------- */
int session_established_handler(OpsecSession *session)
{
	int idx;
	
	fprintf(stdout, "session_established_handler: Session is active\n");

	for (idx = 1; idx <= 3; idx++)
		if (compose_and_send_log(session, idx) < 0){
			fprintf(stderr, "session_established_handler: Failed to send log %d\n", idx);
			break;
		}

	/*
	   We will not close the session untill all logs are saftly transfered.
	   Since pinging is done after the log sending the pong_handler will be
	   called after the log reaches the ELA server.
	 */
	opsec_ping_peer(session, 1000L, pong_handler, NULL);

	return OPSEC_SESSION_OK;
}

 /* -----------------------------------------------------------------------------
  |  init_ela_ctx:
  |  -------------
  |
  |  Description:
  |  ------------
  |  Defines logs FormatFields & Resolvers
  |
  |  Parameters:
  |  -----------
  |  None.
  |
  |  Returned value:
  |  ---------------
  |  Pointer to Ela_CONTEXT if successful, exits otherwise.
   ----------------------------------------------------------------------------- */

Ela_CONTEXT *init_ela_ctx()
{
	Ela_CONTEXT	*ctx = NULL;

	if(!(ctx = ela_context_create()))
	{
		fprintf(stderr, "Unable to create ela-context!\n");
		exit(1);
	}
	/*
	   Predefine the FormatFields
	 */
	FormatFields.product = ela_ff_create(ctx, "product", ELA_VT_INDEX);
	FormatFields.user    = ela_ff_create(ctx, "user"   , ELA_VT_INDEX);

	/*
	   Resolver used for compression
	 */
	Resolvers.comp = ela_resinfo_create(ctx, "expand", NULL, NULL, ELA_ASSOC_RES);

	ela_resentry_add(ctx, Resolvers.comp, ELA_VT_INDEX, PROD_ID, ELA_VT_STRING, "Ela sample client");
	ela_resentry_add(ctx, Resolvers.comp, ELA_VT_INDEX, INFO_ID, ELA_VT_STRING, "http://www.opsec.com");

	/*
	   Resolves user id to name
	 */
	Resolvers.uid2name = ela_resinfo_create(ctx, "User id to name", NULL, NULL, ELA_ASSOC_RES);

	ela_resentry_add(ctx, Resolvers.uid2name, ELA_VT_INDEX, 1, ELA_VT_STRING, "Keith Emerson");
	ela_resentry_add(ctx, Resolvers.uid2name, ELA_VT_INDEX, 2, ELA_VT_STRING, "Greg Lake");
	ela_resentry_add(ctx, Resolvers.uid2name, ELA_VT_INDEX, 3, ELA_VT_STRING, "Carl Palmer");
	
	return ctx;
}

 /* -----------------------------------------------------------------------------
  |  start_handler:
  |  --------------
  |
  |  Description:
  |  ------------
  |  The start handler is used for initializing global session parameters, etc.
  |
  |  Parameters:
  |  -----------
  |  session - returned by a call to ela_new_session.
  |
  |  Returned value:
  |  ---------------
  |  OPSEC_SESSION_OK if successful, OPSEC_SESSION_ERR otherwise.
   ----------------------------------------------------------------------------- */
int start_handler(OpsecSession *session)
{
	printf("\nELA Start_Handler was invoked\n");
	return OPSEC_SESSION_OK;
}

 /* -----------------------------------------------------------------------------
  |  end_handler:
  |  ------------
  |
  |  Description:
  |  ------------
  |  The end handler is used for clearing global session parameters, etc.
  |  Note that after exiting this function the session pointer is no longer valid.
  |
  |  Parameters:
  |  -----------
  |  session - returned by a call to ela_new_session.
  |
  |  Returned value:
  |  ---------------
  |  None.
   ----------------------------------------------------------------------------- */
void end_handler(OpsecSession *session)
{
	printf("\nELA End_Handler was invoked\n");
}

 /* -----------------------------------------------------------------------------
  |  FreeData:
  |  ---------
  |
  |  Description:
  |  ------------
  |  This function frees the OPSEC entities, environment, context and other
  |  memory allocations.
  |
  |  Parameters:
  |  -----------
  |  env    - returned by a call to opsec_init.
  |  server - returned by a call to opsec_init_entity.
  |  client - returned by a call to opsec_init_entity.
  |  ctx    - returned by a call to ela_context_create.
  |
  |  Returned value:
  |  ---------------
  |  None.
   ----------------------------------------------------------------------------- */
void FreeData(OpsecEnv *env, OpsecEntity *server, OpsecEntity *client, Ela_CONTEXT *ctx)
{
	/* context */
	if(ctx)	ela_context_destroy(ctx);

	/* opsec entities */
	if(server)	opsec_destroy_entity(server);
	if(client)	opsec_destroy_entity(client);

	/* opsec environment */
	if(env)	opsec_env_destroy(env);
}


 /* -----------------------------------------------------------------------------
   MAIN 
   ----------------------------------------------------------------------------- */
int main(int ac, char *av[])
{
	char          *prog_name = NULL;
	OpsecEnv      *env;
	OpsecEntity   *client, *server;
	Ela_CONTEXT   *ctx;
	
	Info info;
		
	prog_name = av[0];

	/*
	 * Create environment
	 */
	if (!(env = opsec_init(OPSEC_EOL)))
	{
		fprintf(stderr, "%s: opsec_init failed (%s)\n",
			    prog_name, opsec_errno_str(opsec_errno));
		exit(1);
	}

	/*
	 *  Initialize entities
	 */
	client = opsec_init_entity(env, ELA_CLIENT,
	                                OPSEC_SESSION_START_HANDLER, start_handler,
	                                OPSEC_SESSION_END_HANDLER, end_handler,
	                                OPSEC_SESSION_ESTABLISHED_HANDLER, session_established_handler,
	                                OPSEC_EOL);

	server = opsec_init_entity(env, ELA_SERVER,
	                                OPSEC_ENTITY_NAME, "ela_server",
	                                OPSEC_SERVER_IP,   inet_addr("127.0.0.1"),
	                                OPSEC_SERVER_PORT, htons(ELA_PORT),
	                                OPSEC_EOL);
	if (!(server) || !(client))
	{
		fprintf(stderr, "%s: opsec_init_entity failed (%s)\n",
			   prog_name, opsec_errno_str(opsec_errno));
		opsec_env_destroy(env);
		exit(1);
	}

	/*
	 * Initialize log context
	 */
	ctx = init_ela_ctx();

	info.server = server;
	info.client = client;
	info.ctx    = ctx;

	/*
	 * The following schedules the activate client function,
	 * which will initiate the opsec session.
	 * This is done in order for the session to be created once the mainloop starts.
	 */
	opsec_schedule(env, 100L, activate_client, (void *)&info);

	/*
	 * Mainloop
	 */
	opsec_mainloop(env);

	printf("\n%s: opsec_mainloop returned\n", prog_name);

	/*
	 *  Free the OPSEC entities, environment, context
	 *  and other memory allocations before exiting.
	 */
	FreeData(env, server, client, ctx);

	return 0;
}
