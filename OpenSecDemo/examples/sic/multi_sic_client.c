
/*******************************************************************************
 *   This example demonstrates the use of the multiple SIC identities. 
 *   It initializes 2 SIC identities and then creates 2 sessions to 2 servers.
 *   Each one of the servers belongs to a different SIC domain
 * 
 *   Note: although it is an ELA client, it does not send logs to the ELA server, it         
 *   only sets up a connection (session) to each server, waits
 *   for the session to be established, and disconnects
 *******************************************************************************/
 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "opsec/opsec.h"
#include "opsec/ela_opsec.h"
#include "opsec/ela.h"
#ifdef WIN32
#include <winsock.h>
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#endif


#define ELA_PORT  18187


static int
session_established_handler(OpsecSession *session)
{
	char            *my_sic_name      = NULL;

	printf("\n\n--------------------------------------\n");
	printf("The OPSEC session has been established\n");
	printf("--------------------------------------\n\n");


	if(opsec_session_get_my_sic_name(session,&my_sic_name)){
		fprintf(stderr,"Failed to get session SIC name\n");
		return OPSEC_SESSION_ERR;
	}
	printf("Session SIC name is:   %s\n", my_sic_name ? my_sic_name : "NULL");

	opsec_end_session(session);

	return OPSEC_SESSION_OK;
}

static int
session_start_handler(OpsecSession *session)
{
	printf("\n-----------------------------\n");
	printf("The OPSEC session is starting\n");
	printf("-----------------------------\n\n");
	printf("Waiting for it to be established...\n");

	return OPSEC_SESSION_OK;
}

static void
session_end_handler(OpsecSession *session)
{
	int     end_reason        = 0;
	int     sic_errno         = 0;
	char    *sic_errmsg       = NULL;

	char    *end_reason_str[] = { "SESSION_NOT_ENDED", "END_BY_APPLICATION",
                                      "UNABLE_TO_ATTACH_COMM", "ENTITY_TYPE_SESSION_INIT_FAIL",
                                      "ENTITY_SESSION_INIT_FAIL", "COMM_FAILURE", "BAD_VERSION",
                                      "PEER_SEND_DROP", "PEER_ENDED", "PEER_SEND_RESET",
                                      "COMM_IS_DEAD", "SIC_FAILURE", "SESSION_TIMEOUT" };

	printf("\n\n---------------------------\n");
	printf("The OPSEC session is ending\n");
	printf("---------------------------\n\n");

	end_reason = opsec_session_end_reason(session);

	printf("\nSession end reason is:    %s\n", end_reason_str[end_reason]);

	if (SIC_FAILURE == end_reason) {
		if (!opsec_get_sic_error(session, &sic_errno, &sic_errmsg)) {
			printf("SIC Error Number          : %d\n", sic_errno);
			printf("SIC Error Message         : %s\n\n", sic_errmsg);
		}
	}
}

static void
clean_env(OpsecEnv *env, OpsecEntity *client, OpsecEntity *server1, OpsecEntity *server2)
{
	if (client) opsec_destroy_entity(client);
	if (server1) opsec_destroy_entity(server1);
	if (server2) opsec_destroy_entity(server2);
	if (env) opsec_env_destroy(env);
}

int 
main(int argc, char *argv[])
{
	OpsecEnv          *env      = NULL;
	OpsecEntity       *client   = NULL;
	OpsecEntity       *server1   = NULL;
	OpsecEntity       *server2  = NULL;
	OpsecSession      *session1  = NULL;
	OpsecSession      *session2  = NULL;

	/*
	 * OPSEC initialization: 
	 */

	env = opsec_init(OPSEC_CONF_FILE,  "multi_sic.conf",OPSEC_EOL);

	if (!env) { 
		fprintf(stderr,"Failed to initialize the OPSEC environment\n");
		clean_env(env, client, server1,server2);
		exit(1);
	}

	/*
	 * SIC identities initialization:
	 * Each SIC idenity is identified in the configuration by a SIC identity name
	 */

	if (opsec_init_sic_id(env,OPSEC_SIC_ID_NAME,"jerusalem", OPSEC_EOL)) {
		printf("Failed to create SIC identity for jerusalem\n");
		clean_env(env, client, server1,server2);
		exit(1);
	}
	if (opsec_init_sic_id(env,OPSEC_SIC_ID_NAME,"london",OPSEC_EOL)) {
		printf("Failed to create SIC identity for london\n");
		clean_env(env, client, server1,server2);
		exit(1);
	}

	/*
	 * OPSEC entities initialization: 
	 * Must be performed after SIC identity initialization
	 */

	/*
	 * Client entity initialization:
	 */

	client = opsec_init_entity(env, ELA_CLIENT,
	                           OPSEC_GENERIC_SESSION_START_HANDLER, session_start_handler,
	                           OPSEC_SESSION_ESTABLISHED_HANDLER, session_established_handler,
	                           OPSEC_GENERIC_SESSION_END_HANDLER, session_end_handler,
	                           OPSEC_EOL);
 
	if (!client){
		fprintf(stderr,"Failed to initialize the client entity\n");
		clean_env(env, client, server1,server2);
		exit(1);
	}


	/*
	 * First server entity initialization:
	 */
	server1 = opsec_init_entity(env, ELA_SERVER,
	                           OPSEC_ENTITY_NAME, "server_jerusalem",
	                           OPSEC_EOL);

	if (!server1){
		fprintf(stderr,"Failed to initialize the server entity\n");
		clean_env(env, client, server1,server2);
		exit(1);
	}
    
	/*
	 * Session creation for first server:
	 */

	session1 = opsec_new_generic_session(client, server1);

	if(!session1) {
		fprintf(stderr, "Failed to create the OPSEC session 1\n");
		clean_env(env, client, server1,server2);
		exit(1);
	}

	/*
	 * Second server entity initialization:
	 */

	server2 = opsec_init_entity(env, ELA_SERVER,
	                                OPSEC_ENTITY_NAME, "server_london",
	                                OPSEC_EOL);


	/*
	 * Session creation for second server:
	 */

	session2 = opsec_new_generic_session(client, server2);

	if(!session2) {
		fprintf(stderr, "Failed to create the OPSEC session 2\n");
		clean_env(env, client, server1,server2);
		exit(1);
	}

	opsec_mainloop(env);

	clean_env(env, client, server1,server2);

	return 0;
}
