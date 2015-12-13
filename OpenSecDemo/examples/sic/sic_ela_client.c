/******************************************************************************
 *                                                                            *
 *   This client demonstartes the use of the SIC infrastructure. Although     *
 *   it is an ELA client, it does not send logs to the ELA server, it         *
 *   only sets up a connection (session) to the server using SIC, waits       *
 *   for the session to be esblished, and disconnects.                        *
 *                                                                            *
 *   The session_established_handler() function, queries the session for:     *
 *                                                                            *
 *   1) The Peer SIC Name.                                                    *
 *   2) The chosen SIC method.                                                *
 *   2) The SIC service name and number.                                      *
 *                                                                            *
 *   If one of the SSLCA authentication method flavors is used, the session   *
 *   is also queried for:                                                     *
 *                                                                            *
 *   1) The Peer certificate hash.                                            *
 *   2) The Peer certificate fingerprint.                                     *
 *                                                                            *
 *                                                                            *
 *   Once all of this information is printed, the session_established_handler *
 *   ends the newly opened session using opsec_end_session().                 *
 *                                                                            *
 *   The session_end_handler() finds out what the session end reason is       *
 *   and if the session is closed due to a problem with the SIC connection    *
 *   set up, the SIC error is also printed.                                   *
 *                                                                            *
 ******************************************************************************/

/*
 * The following lines are the printout of a successful session:
 * -------------------------------------------------------------

-----------------------------
The OPSEC session is starting
-----------------------------

Waiting for it to be established...


--------------------------------------
The OPSEC session has been established
--------------------------------------

Peer SIC name is:   cn=cp_mgmt,o=myname.mydomain.com.n79vjo
SIC method is:      sslca
SIC service is:     ela
SIC service number: 68
Hash is:            9b:b4:97:ec:0b:c9:d4:4d:82:6c:27:bf:dc:cc:cd:bc:b1:77:79:07
Hash length is:     20
Hash str is:        HOYT JUTE WHET GUM HURT MAD FLED BURY TROD MEEK RATE SLAT


---------------------------
The OPSEC session is ending
---------------------------


Session end reason is:    END_BY_APPLICATION

* End of printout.
*/

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


static int
sic_mehtod_used_is_sslca(char *method)
{
	if (!method) return 0;

	if ( !strcmp(method, "sslca"              ) ||
	     !strcmp(method, "sslca_comp"         ) ||
	     !strcmp(method, "asym_sslca"         ) ||
	     !strcmp(method, "asym_sslca_comp"    ) ||
	     !strcmp(method, "sslca_rc4"          ) ||
	     !strcmp(method, "sslca_rc4_comp"     ) ||
	     !strcmp(method, "asym_sslca_rc4"     ) ||
	     !strcmp(method, "asym_sslca_rc4_comp")    )    return 1;

	return 0;
}


static int
session_established_handler(OpsecSession *session)
{
	int             rc                  = 0;
	unsigned int    i;
	char            *peer_sic_name      = NULL;
	char            *chosen_sic_method  = NULL;
	char            *sic_svc_string     = NULL;
	short           sic_svc_number      = 0;
	unsigned char   cert_hash[100];
	unsigned int    cert_hash_len       = 100;
	char            cert_string[100];

	printf("\n\n--------------------------------------\n");
	printf("The OPSEC session has been established\n");
	printf("--------------------------------------\n\n");

	peer_sic_name = opsec_sic_get_peer_sic_name(session);
	printf("Peer SIC name is:   %s\n", peer_sic_name ? peer_sic_name : "NULL");

	chosen_sic_method = opsec_sic_get_sic_method(session);
	printf("SIC method is:      %s\n", chosen_sic_method ? chosen_sic_method : "NULL");

	sic_svc_string = opsec_sic_get_sic_service(session, &sic_svc_number);
	printf("SIC service is:     %s\n", sic_svc_string ? sic_svc_string : "NULL");
	printf("SIC service number: %d\n", sic_svc_number);

	if (sic_mehtod_used_is_sslca(chosen_sic_method)) {
		
		rc = opsec_sic_get_peer_cert_hash(session, cert_hash, &cert_hash_len, cert_string, 100);

		if (!rc) {
			int		hashon;

			printf("Hash is:            ");

			for (i=0; i < cert_hash_len; i++) {
				hashon = cert_hash[i];
				hashon &= 0x0ff;
				printf("%02x", hashon);
				if (i < cert_hash_len - 1) printf(":");
			}

			printf("\n");
			printf("Hash length is:     %d\n", cert_hash_len);
		
			printf("Hash str is:        %s\n", cert_string[0] ? cert_string : "NULL");
		}

	}

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
clean_env(OpsecEnv *env, OpsecEntity *client, OpsecEntity *server)
{
	if (client) opsec_destroy_entity(client);
	if (server) opsec_destroy_entity(server);
	if (env) opsec_env_destroy(env);
}

int 
main(int argc, char *argv[])
{
	OpsecSession      *session  = NULL;
	OpsecEntity       *client   = NULL;
	OpsecEntity       *server   = NULL;
	OpsecEnv          *env      = NULL;


	/*
	 * The OPSEC environment is created with the following parameters:
	 *
	 * 1) Configuration file (ela.conf). Since the configuration file 
	 *    option is used here, it must exist or opsec_init() will fail.
	 * 2) Certificate file (opsec.p12). This is the defualt name for
	 *    the opsec application certificate file. This file is created
	 *    by using the opsec_pull_cert tool. If the file is not present
	 *    opsec_init() will not fail, but the SSLCA methods will not be
	 *    available.
	 * 3) opsec_sic_name - This is the DN created for the OPSEC 
	 *    application when it is defined using the VPN-1/FireWall-1 Policy
	 *    editor. This name must be supplied in order to enable 
	 *    VPN-1/FireWall-1 to recognize the application.
	 *
	 */

	env = opsec_init(OPSEC_CONF_FILE,  "ela.conf",
	                 OPSEC_SIC_NAME,   "CN=sic_ela_client,O=myname.mydomain.com.n79vjo",
	                 OPSEC_SSLCA_FILE, "opsec.p12", 
	                 OPSEC_EOL);

	if (!env) { 
		fprintf(stderr,"Failed to initialize the OPSEC environment\n");
		clean_env(env, client, server);
		exit(1);
	}


	/*
	 * The client entity is registered only with the handlers, common to all 
	 * OPSEC sessions:
	 *
	 * 1) The start handler.
	 * 2) The 'established' handler - in which we will find out some
	 *    details about the SIC characteristics of the session.
	 * 3) The end handler, in which we will find out what the SIC
	 *    error is, in case the SIC connection set-up failed.
	 */

	client = opsec_init_entity(env, ELA_CLIENT,
	                           OPSEC_GENERIC_SESSION_START_HANDLER, session_start_handler,
	                           OPSEC_SESSION_ESTABLISHED_HANDLER, session_established_handler,
	                           OPSEC_GENERIC_SESSION_END_HANDLER, session_end_handler,
	                           OPSEC_EOL);
 
	if (!client){
		fprintf(stderr,"Failed to initialize the client entity\n");
		clean_env(env, client, server);
		exit(1);
	}
 
	/*
	 * The server entity is created with all the parameters needed for
	 * SIC:
	 *
	 * 1) auth_port - is used to make OPSEC use SIC for sessions 
	 *                associated with this server.
	 * 2) auth_type - defining use of sslca for sessions opened
	 *                against this server.
	 * 3) opsec_entity_sic_name - used to complete the server 
	 *                            identification using SIC.
	 * 4) The server IP address.
	 *
	 * All of the above can be overriden by settings in ela.conf
	 */

	server = opsec_init_entity(env, ELA_SERVER,
	                           OPSEC_ENTITY_NAME, "ela_server",
	                           OPSEC_SERVER_IP,   inet_addr("127.0.0.1"),
	                           OPSEC_SERVER_AUTH_PORT, (int)htons(18187),
	                           OPSEC_ENTITY_SIC_NAME, "CN=cp_mgmt,O=myname.mydomain.com.n79vjo",
	                           OPSEC_SERVER_AUTH_TYPE, OPSEC_SSLCA,
	                           OPSEC_EOL);

	if (!server){
		fprintf(stderr,"Failed to initialize the server entity\n");
		clean_env(env, client, server);
		exit(1);
	}
    
	session = opsec_new_generic_session(client, server);

	if(!session) {
		fprintf(stderr, "Failed to create the OPSEC session\n");
		clean_env(env, client, server);
		exit(1);
	}

	opsec_mainloop(env);

	clean_env(env, client, server);

	return 0;
}
