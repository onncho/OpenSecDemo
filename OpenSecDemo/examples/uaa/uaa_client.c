 /*************************************************************************\
 *                                                                         *
 * uaa_client.c : Sample OPSEC UAA client                                  *
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
 * This is a sample for a UAA client.                                      *
 *                                                                         *
 * The client operates as followes:                                        *
 *                                                                         *
 * 1. the session creation is scheduled before activating the mainloop     *
 *                                                                         *
 * 2. In the session established handler, a query is sent to the UAG       *
 *                                                                         *
 * 3. If the UAG doesn't send the user name back, we try to authenticate   *
 *    the user                                                             *
 *                                                                         *
 \*************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#ifdef WIN32
#include <winsock.h>
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "opsec/opsec.h"
#include "opsec/opsec_error.h"
#include <opsec/uaa.h>
#include <opsec/uaa_client.h>
#include <opsec/uaa_error.h>

/*
 * Global definitions
 */

typedef struct _Info{
	OpsecEntity     *server;
	OpsecEntity     *client;
}Info;

/*
 * Functions
 */

 /* -----------------------------------------------------------------------------
  |  Error:
  |  ------
  |
  |  Description:
  |  ------------
  |  handles errors by printing them to the standart error
  |
  |  Parameters:
  |  -----------
  |  error_str - a string describing the error
  |
  |  Returned value:
  |  ---------------
  |  None.
   ----------------------------------------------------------------------------- */
void Error(char *error_str)
{
	fprintf(stderr,"Error: %s\n",error_str);
}

 /* -----------------------------------------------------------------------------
  |  print_assert:
  |  -------------
  |
  |  Description:
  |  ------------
  |  prints a uaa_assert_t structure.
  |
  |  this is done by creating an iterator to the structure and going over all the
  |  assertions one by one
  |
  |  Parameters:
  |  -----------
  |  prefix     - The name of the assert printed
  |  asserts    - The assert to be printed
  |
  |  Returned value:
  |  ---------------
  |  None.
   ----------------------------------------------------------------------------- */
void print_assert(char *prefix, uaa_assert_t *asserts)
{
	uaa_assert_t_iter *iter;
	char              *value, *type;
	int               idx = 0;

	iter = uaa_assert_t_iter_create(asserts, NULL);

	if (!iter)
		return;

	fprintf(stderr, "%s\n", prefix);

	while(uaa_assert_t_iter_get_next(iter, &value, &type)!=-1) {

		idx++;
		fprintf(stderr, "Assertion number %2d: Type  = %s\n", idx, type);
		fprintf(stderr, "                     Value = %s\n", value);
	}

	uaa_assert_t_iter_destroy(iter);
	return;
}

 /* -----------------------------------------------------------------------------
  |  activate_client:
  |  ----------------
  |
  |  Description:
  |  ------------
  |  Initializes a new opsec session.
  |
  |  Parameters:
  |  -----------
  |  info_ - a structure holding the client and server entities
  |
  |  Returned value:
  |  ---------------
  |  None.
   ----------------------------------------------------------------------------- */
void activate_client(void *info_)
{
	OpsecSession *session = NULL;
	Info         *info    = (Info *)info_;

	/*
	 * Create uaa session
	 */

	if(!(session = uaa_new_session(info->client, info->server))) {

		fprintf(stderr, "Unable to create session (%s)!\n", opsec_errno_str(-1));
		exit(1);

	}

	/*
	 * Once the session is established, the "session_established handler"
	 * will be invoked, causing a query to be sent the server.
	 */

	return;
}

 /* -----------------------------------------------------------------------------
  |  queryUAG:
  |  ---------
  |
  |  Description:
  |  ------------
  |  create a uaa_assert_t structure (uaa_assert_t_create) fill it (uaa_assert_t_add),
  |  and send it as a query (uaa_send_query).
  |
  |  Parameters:
  |  -----------
  |  session - Pointer to an OpsecSession object
  |
  |  Returned value:
  |  ---------------
  | 0 if successful, -1 otherwise
   ----------------------------------------------------------------------------- */
int queryUAG(OpsecSession *session)
{
	uaa_assert_t *query = uaa_assert_t_create();

	if(!query)
		return -1;
	if(uaa_assert_t_add(query, "src", "1.1.1.1") == -1) {

		Error("queryUAG: uaa_assert_t_add failed");
		uaa_assert_t_destroy(query);
		return -1;
	}
	if(uaa_assert_t_add(query, "user", "?")==-1) {

		Error("queryUAG: uaa_assert_t_add failed");
		uaa_assert_t_destroy(query);
		return -1;
	}

	/*
	 * send the query to the server.
	 * we use timeout zero because we are willing to wait for the reply, no matter how
	 * long it takes.
	 */

	if(uaa_send_query(session, query, NULL, 0l)==-1) {

		Error("queryUAG: uaa_send_query failed");
		uaa_assert_t_destroy(query);
		return -1;
	}
	uaa_assert_t_destroy(query);

	return 0;
}

/* -----------------------------------------------------------------------------
  |  authenticateUAG:
  |  ----------------
  |
  |  Description:
  |  ------------
  |  create a uaa_assert_t structure (uaa_assert_t_create) fill it (uaa_assert_t_add),
  |  and send it as an authentication request (uaa_send_authenticate_request).
  |
  |  Parameters:
  |  -----------
  |  session - Pointer to an OpsecSession object
  |
  |  Returned value:
  |  ---------------
  |  0 if successful, -1 otherwise
   ----------------------------------------------------------------------------- */
int authenticateUAG(OpsecSession *session)
{
	uaa_assert_t *auth_req = uaa_assert_t_create();

	if(!auth_req)
                return -1;
	if(uaa_assert_t_add(auth_req, "uid", "OPSEC")==-1) {

		Error("authenticateUAG: uaa_assert_t_add failed");
		uaa_assert_t_destroy(auth_req);
		return -1;
	}
	if(uaa_assert_t_add(auth_req, "password", "123456")==-1) {

		Error("authenticateUAG: uaa_assert_t_add failed");
		uaa_assert_t_destroy(auth_req);
		return -1;
	}
	if(uaa_assert_t_add(auth_req, "action", "?")==-1) {

		Error("authenticateUAG: uaa_assert_t_add failed");
		uaa_assert_t_destroy(auth_req);
		return -1;
	}
	if(uaa_assert_t_add(auth_req, "user", "?")==-1) {

		Error("authenticateUAG: uaa_assert_t_add failed");
		uaa_assert_t_destroy(auth_req);
		return -1;
	}
	if(uaa_assert_t_add(auth_req, "message", "?")==-1) {

		Error("authenticateUAG: uaa_assert_t_add failed");
		uaa_assert_t_destroy(auth_req);
		return -1;
	}

	/*
	 * send the query to the server.
	 * we use timeout zero because we are willing to wait for the reply, no matter how
	 * long it takes.
	 */

	if(uaa_send_authenticate_request(session, auth_req, NULL, 0l)==-1) {

		Error("authenticateUAG: uaa_send_authenticate_request failed");
		uaa_assert_t_destroy(auth_req);
		return -1;
	}

	uaa_assert_t_destroy(auth_req);

	return 1;
}

/* -------------------------------------------------------------------------------------
                                 UAA   client   handlers
   ------------------------------------------------------------------------------------- */

 /* -----------------------------------------------------------------------------
  |  uaa_authenticate_reply_handler:
  |  -------------------------------
  |
  |  Description:
  |  ------------
  |  this handler is called whenever the server sends back a reply for an authentication
  |  request.
  |
  |  we have two ways of associating the reply with the query: either by the cmd_id,
  |  which is equal to the one returned by calling uaa_send_query, or by the opaque
  |  that is associated with the query.
  |
  |  Parameters:
  |  -----------
  |  session - Pointer to an OpsecSession object
  |  reply   - A pointer to a uaa_assert_t object, holding the servers reply
  |  opaque  - Data hanged on the query
  |  cmd_id  - the id returned by the uaa_send_authenticate_request
  |  status  - A uaa_reply_status object, holding the reply status
  |
  |  Returned value:
  |  ---------------
  |  OPSEC_SESSION_END
   ----------------------------------------------------------------------------- */
static int uaa_authenticate_reply_handler(OpsecSession *session,
                                          uaa_assert_t *reply,
                                          void *opaque,
                                          int cmd_id,
                                          uaa_reply_status status)

{
	fprintf(stderr,"\nuaa_authenticate_handler\n");

	fprintf(stderr, "uaa_authenticate_handler: status is %s\n",uaa_error_str(status));

	if ((status==UAA_REPLY_STAT_OK) && (reply))
		print_assert("authentication reply assert: ",reply);

	/*
	 * we are done processing the requests, by returning OPSEC_SESSION_END we tell
	 * the underlying OPSEC framework to terminate the session.
	 */

	return OPSEC_SESSION_END;
}

 /* -----------------------------------------------------------------------------
  |  uaa_query_reply_handler:
  |  ------------------
  |
  |  Description:
  |  ------------
  |  this handler is called whenever the server sends back a reply for a query
  |  that was previously sent.
  |
  |  we have two ways of associating the reply with the query: either by the cmd_id,
  |  which is equal to the one returned by calling uaa_send_query, or by the opaque
  |  that is associated with the query.
  | 
  |  Parameters:
  |  -----------
  |  session - Pointer to an OpsecSession object
  |  reply   - A pointer to a uaa_assert_t object, holding the servers reply
  |  opaque  - Data hanged on the query
  |  cmd_id  - The ID returned by uaa_send_query
  |  status  - A uaa_reply_status object, holding the reply status
  |  last    - This parameter always has a value of 1
  |
  |  Returned value:
  |  ---------------
  | OPSEC_SESSION_OK if we still need the session, OPSEC_SESSION_END otherwise
   ----------------------------------------------------------------------------- */
static int uaa_query_reply_handler(OpsecSession *session,
                                   uaa_assert_t *reply,
                                   void *opaque,
                                   int cmd_id,
                                   uaa_reply_status status,
                                   int last)
{
	char              *type, *value = NULL;
	uaa_assert_t_iter *iter = uaa_assert_t_iter_create(reply,"user");
	int               rc = 0;

	fprintf(stderr, "\nuaa_query_reply_handler\n");

	fprintf(stderr, "uaa_query_reply_handler: status is %s\n", uaa_error_str(status));

	if(status==UAA_REPLY_STAT_OK) {
		if(reply) {

			print_assert("query reply assert: ",reply);
			if(!iter) {

				Error("uaa_query_reply_handler: uaa_assert_t_iter_create failed");
				return OPSEC_SESSION_ERR;
			}
			rc = uaa_assert_t_iter_get_next(iter, &value, &type);
			uaa_assert_t_iter_destroy(iter);
		}
		if (!value) {

			/*
			 * The server didn't return the user name, try to authenticate.
			 */

			if (authenticateUAG(session) == 0)
				return OPSEC_SESSION_OK;
		}
	} 

	/*
	 * we are done processing the requests, by returning OPSEC_SESSION_END we tell
	 * the underlying OPSEC framework to terminate the session.
	 */

	return OPSEC_SESSION_END;
}
 /* -----------------------------------------------------------------------------
  |  start_handler:
  |  --------------
  |
  |  Description:
  |  ------------
  |
  |  Parameters:
  |  -----------
  |  session - Pointer to an OpsecSession object
  |
  |  Returned value:
  |  ---------------
   ----------------------------------------------------------------------------- */
static int start_handler(OpsecSession *session)
{
	fprintf(stderr, "uaa_client_start_handler\n");
	return OPSEC_SESSION_OK;
}

 /* -----------------------------------------------------------------------------
  |  session_established_handler:
  |  ----------------------------
  |
  |  Description:
  |  ------------
  |  Sends a query to the server
  |
  |  Parameters:
  |  -----------
  |  session - Pointer to an OpsecSession object
  |
  |  Returned value:
  |  ---------------
  |  OPSEC_SESSION_OK if successful, OPSEC_SESSION_END otherwise.
   ----------------------------------------------------------------------------- */
static int session_established_handler(OpsecSession *session)
{
	int rc;

	fprintf(stdout, "session_established_handler: Session is active\n");
	rc = queryUAG(session);
	if (rc == 0)
		return OPSEC_SESSION_OK;
	else
		return OPSEC_SESSION_END;
}

 /* -----------------------------------------------------------------------------
  |  end_handler:
  |  ------------
  |
  |  Description:
  |  ------------
  | 
  |
  |  Parameters:
  |  -----------
  |  session - Pointer to an OpsecSession object
  |
  |  Returned value:
  |  ---------------
  |  None.
   ----------------------------------------------------------------------------- */
static void end_handler(OpsecSession *session)
{
	fprintf(stderr, "uaa_client_end_handler\n");
	return;
}


/* -------------------------------------------------------------------------------------
                                        M A I N
   ------------------------------------------------------------------------------------- */
int main(int ac, char *av[])
{
	OpsecEnv    *env;
	OpsecEntity *client, *server;
	char        *ProgName;
	Info        info;
	
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
	 *  Initialize entities
	 */

	client = opsec_init_entity(env, UAA_CLIENT,
	                                OPSEC_SESSION_START_HANDLER, start_handler,
	                                OPSEC_SESSION_END_HANDLER, end_handler,
	                                OPSEC_SESSION_ESTABLISHED_HANDLER, session_established_handler,
	                                UAA_QUERY_REPLY_HANDLER,uaa_query_reply_handler,
	                                UAA_AUTHENTICATE_REPLY_HANDLER, uaa_authenticate_reply_handler,
	                                OPSEC_EOL);

	server = opsec_init_entity(env, UAA_SERVER,
	                                OPSEC_ENTITY_NAME, "UAG",
	                                OPSEC_SERVER_IP,   inet_addr("127.0.0.1"),
	                                OPSEC_SERVER_PORT, (int)htons(19191),
	                                OPSEC_EOL);

	if (!(server) || !(client))
	{
		fprintf(stderr, "%s: opsec_init_entity failed (%s)\n",
		                ProgName, opsec_errno_str(opsec_errno));
		opsec_env_destroy(env);
		exit(1);
	}

	info.server = server;
	info.client = client;

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

	printf("\n%s: opsec_mainloop returned\n", ProgName);

	/* free opsec entities */

	if(server)      opsec_destroy_entity(server);
	if(client)      opsec_destroy_entity(client);

	/* free opsec environment */

	if(env) opsec_env_destroy(env);

	return 0;
}
