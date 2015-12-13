/***************************************************************************
 *                                                                         *
 * ufp_server.c : Sample OPSEC UFP Server                                  *
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
 ***************************************************************************

/***************************************************************************
 *                                                                         *
 * The server handles the 3 types of events (UFP_DESC, UFP_DICT, UFP_CAT)  *
 * with the corresponding desc_handler, dict_handler and cat_handler       *
 * functions.                                                              *
 *                                                                         *
 * The UFP server can categorize URLs in two different modes:              *
 *    BC_MODE = 1: Send categorization reply without cache information.    *
 *	  BC_MODE = 0: Send categorization reply with cache information    *
 *                 including ABSOLUTE masks only.                          *
 * The mode is determined according to the value of the BC_MODE parameter  *
 * which is used only for convenience in this sample.                      *
 *                                                                         *
 * ufp.conf contains configuration information for the connection between  *
 * the UFP Client and Server (e.g. port number, authentication type etc.). *
 *                                                                         *
 * Note that most definitions and values in this application are  chosen   *
 * for the sake of this sample and will be replaced in real life           *
 * applications.                                                           *
 *                                                                         *
 ***************************************************************************/

#include "opsec/opsec_error.h"
#include "opsec/ufp_server.h"
#include "opsec/ufp_opsec.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef WIN32
#include <winsock.h>
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

/*
   Global definitions (arbitrarily chosen)
 */
#define BC_MODE    0
#define TTL        500 /* [ms] */
#define HTTP_PORT  80

char *description     = "OPSEC_UFP_Demo_Server";
char *redirection_url = "www.checkpoint.com";


/*
   Dictionary definitions
 */
/* number of categories */
#define DICT_LEN   9

#define MATCH_LEN  128

int server_dict_ver = 1;
int dict_elems      = DICT_LEN;
int ufp_mask_len    = ((DICT_LEN+7)/8)*8;

typedef struct match_st {
	char *match_str;
	int   match_cat;
} match_st;

/* dictionary categories */
char *dict[DICT_LEN] = { "Alcohol",      /* 0 */
                         "Drugs",        /* 1 */
                         "Games",        /* 2 */
                         "Sex",          /* 3 */
                         "Pornography",  /* 4 */
                         "Sports",       /* 5 */
                         "CheckPoint",   /* 6 */
                         "MegaSports",   /* 7 */
                         "8CAT" };       /* 8 */

/*
   These are the 'match strings', used for categorizing URL's, sent by the client.
 */
match_st match_data[MATCH_LEN] = { {"wine"      , 0},
                                   {"alcohol"   , 0},
                                   {"lsd"       , 1},
                                   {"crack"     , 1},
                                   {"opium"     , 1},
                                   {"bridge"    , 2},
                                   {"poker"     , 2},
                                   {"chess"     , 2},
                                   {"soccer"    , 2},
                                   {"tennis"    , 2},
                                   {"sex"       , 3},
                                   {"playboy"   , 4},
                                   {"penthouse" , 4},
                                   {"soccer"    , 5},
                                   {"tennis"    , 5},
                                   {"checkpoint", 6},
                                   {"firewall-1", 6},
                                   {"opsec"     , 6},
                                   {"nba"       , 7},
                                   {"basketball", 7},
                                   {"football"  , 7},
                                   {"soccer"    , 7},
                                   {"8"         , 8},
                                   { NULL       ,-1} };


 /* -----------------------------------------------------------------------------
  |  free_all:
  |  ---------
  |
  |  Description:
  |  ------------
  |  This function frees the OPSEC server entity & environment.
  |
  |  Parameters:
  |  -----------
  |  env    - returned by a call to opsec_init.
  |  server - returned by a call to opsec_init_entity.
  |
  |  Returned value:
  |  ---------------
  |  None.
   ----------------------------------------------------------------------------- */
static void free_all(OpsecEnv *env, OpsecEntity *server)
{
	if(server) opsec_destroy_entity(server);

	if(env) opsec_env_destroy(env);

	return;
}

 /* -----------------------------------------------------------------------------
  |  print_dictionary:
  |  -----------------
  |
  |  Description:
  |  ------------
  |  This function prints the UFP server dictionary parameters.
  |
  |  Parameters:
  |  -----------
  |  None.
  |
  |  Returned value:
  |  ---------------
  |  None.
   ----------------------------------------------------------------------------- */
static void print_dictionary()
{
	int idx = 0;

	fprintf(stderr, "\nServer dictionary: \
	               \n------------------ \
	               \nDict ver:   %d \
	               \ndict_elems: %d \
	               \nnmask_len:  %d \
	             \n\nCategories:", server_dict_ver, dict_elems, ufp_mask_len);

	for (idx = 0; idx < DICT_LEN; idx++)
		fprintf(stderr, "\nCat %d: %s", idx, dict[idx]);
	
	fprintf(stderr, "\n\nURL for redirection: %s\n", redirection_url);
}

 /* -----------------------------------------------------------------------------
  |  send_bc_reply:
  |  --------------
  |
  |  Description:
  |  ------------
  |  This function sends reply to the client without cache info. or redirection URL.
  |
  |  Parameters:
  |  -----------
  |  session      - Pointer so an OpsecSession object.
  |  cat_mask     - the UFP server categorization mask.
  |  cat_mask_len - categorization mask length.
  |  status       - of the UFP server reply.
  |
  |  Returned value:
  |  ---------------
  |  OPSEC_SESSION_OK if successful, OPSEC_SESSION_ERR otherwise.
   ----------------------------------------------------------------------------- */
static int send_bc_reply(OpsecSession *session, ufp_mask cat_mask, int cat_mask_len, int status)
{
	return ufp_send_cat_reply(session, cat_mask, cat_mask_len, status);
}

 /* -----------------------------------------------------------------------------
  |  send_reply:
  |  -----------
  |
  |  Description:
  |  ------------
  |  This function sends a full reply to the client, including cache info. & redirection URL.
  |  The cache info contains only one entry with an ABSOLUTE mask.
  |  Note that additional entries can be added. The server can choose to send entries,
  |  with data relating to the client request mask (see documentation for more details).
  |
  |  In this sample we ignored the client request mask for simplicity.
  |
  |  Parameters:
  |  -----------
  |  session      - Pointer so an OpsecSession object.
  |  cat_mask     - the UFP server categorization mask.
  |  cat_mask_len - categorization mask length.
  |  dst_ip       - used as the cached IP in the UfpCacheInfo.
  |  status       - of the UFP server reply.
  |
  |  Returned value:
  |  ---------------
  |  OPSEC_SESSION_OK if successful, OPSEC_SESSION_ERR otherwise.
   ----------------------------------------------------------------------------- */
static int send_reply(OpsecSession *session,
                      ufp_mask      cat_mask,
                      int           cat_mask_len,
                      char         *dst_ip,
                      int           status)
{
	UfpCacheInfo *cache_info = NULL;
	int returned_val = OPSEC_SESSION_OK;
	
	/*
	   Add the categorization reply to UfpCacheInfo:
	 */
	if (! (cache_info = ufp_create_cache_info(TTL)) ) {
		fprintf(stderr, "send_reply: Error while creating cache info");
		return OPSEC_SESSION_ERR;
	}

	returned_val = ufp_add_to_cache_info(cache_info,
	                                     NULL,
	                                     dst_ip,
	                                     HTTP_PORT,
	                                     cat_mask,
	                                     cat_mask_len,
	                                     ABSOLUTE_MASK);
	if (returned_val != OPSEC_SESSION_OK) {
		fprintf(stderr, "send_reply: Problem occurred while adding cache information\n");
		ufp_destroy_cache_info(cache_info);
		return OPSEC_SESSION_ERR;
	}

	/*
	   Send reply to client
	 */
	returned_val = ufp_send_cat_reply_with_cache_info(session,
	                                                  cat_mask,
	                                                  ufp_mask_len,
	                                                  status,
	                                                  cache_info,
	                                                  redirection_url);
	ufp_destroy_cache_info(cache_info);

	return returned_val;
}

 /* -----------------------------------------------------------------------------
  |  do_cat:
  |  -------
  |
  |  Description:
  |  ------------
  |  This function does the URL categorization. It simply looks for the given
  |  URL string in the 'match strings' defined for each category.
  |  If found it sets the relating bit in the cat. mask 'on'.
  |  This is a naive implementation of categorization just for this example.
  |
  |  Parameters:
  |  -----------
  |  url      - sent by the client.
  |  cat_mask - the UFP server categorization mask.
  |
  |  Returned value:
  |  ---------------
  |  OPSEC_SESSION_OK.
   ----------------------------------------------------------------------------- */
static int do_cat(char *url, ufp_mask *cat_mask)
{
	int idx = 0;

	for (idx = 0; (match_data[idx].match_str) ; idx++)
		if (strstr(url, match_data[idx].match_str)) {
			ufp_mask_set(*cat_mask, ufp_mask_len, match_data[idx].match_cat);
			fprintf(stderr, "do_cat: Found match: %s\n", dict[match_data[idx].match_cat]);
		}

	return OPSEC_SESSION_OK;
}


/*
   ---------------------
     Server's handlers
   ---------------------
 */
 
 /* -----------------------------------------------------------------------------
  |  desc_handler:
  |  -------------
  |
  |  Description:
  |  ------------
  |  This is the UFP server description handler.
  |
  |  Parameters:
  |  -----------
  |  session - Pointer so an OpsecSession object.
  |
  |  Returned value:
  |  ---------------
  |  OPSEC_SESSION_OK if successful, OPSEC_SESSION_ERR otherwise.
   ----------------------------------------------------------------------------- */
static int desc_handler(OpsecSession *session)
{
	if (ufp_send_desc_reply(session, description, UFP_OK) != OPSEC_SESSION_OK) {
		fprintf(stderr, "desc_handler: cannot send description reply (%s)\n",
				opsec_errno_str(opsec_errno));
		return OPSEC_SESSION_ERR;
	}
	fprintf(stderr, "desc_handler: Sent description (%s)\n", description);

	return OPSEC_SESSION_OK;
}

 /* -----------------------------------------------------------------------------
  |  dict_handler:
  |  -------------
  |
  |  Description:
  |  ------------
  |  This is the UFP server dictionary handler.
  |
  |  Parameters:
  |  -----------
  |  session - Pointer so an OpsecSession object.
  |
  |  Returned value:
  |  ---------------
  |  OPSEC_SESSION_OK if successful, OPSEC_SESSION_ERR otherwise.
   ----------------------------------------------------------------------------- */
static int dict_handler(OpsecSession *session)
{
	if (ufp_send_dict_reply( session,
	                         dict,
	                         server_dict_ver,
	                         dict_elems,
	                         ufp_mask_len,
	                         UFP_OK ) != OPSEC_SESSION_OK) {
		fprintf(stderr, "dict_handler: can't send dictionary reply (%s)\n",
				opsec_errno_str(opsec_errno));
		return OPSEC_SESSION_ERR;
	}
	fprintf(stderr, "dict_handler: Sent dictionary\n");

	return OPSEC_SESSION_OK;
}

 /* -----------------------------------------------------------------------------
  |  cat_handler:
  |  ------------
  |
  |  Description:
  |  ------------
  |  This is the UFP server categorization handler.
  |
  |  Parameters:
  |  -----------
  |  session  - Pointer so an OpsecSession object.
  |  url      - sent by the client.
  |  dict_ver - the dictionary version with which the client works.
  |  info     - request parameters, sent from the client.
  |
  |  Returned value:
  |  ---------------
  |  OPSEC_SESSION_OK if successful, OPSEC_SESSION_ERR otherwise.
   ----------------------------------------------------------------------------- */
static int cat_handler( OpsecSession *session,
                       	char         *url,
                       	int           dict_ver,
                       	OpsecInfo    *info )
{
	/* OpsecInfo data */
	char *dst_ip   = NULL;
	char *src_ip   = NULL;
	char *dst_port = NULL;
	char *src_port = NULL;

	char *client_mask_s     = NULL;
	char *client_mask_len_s = NULL;

	/* mask length, received from the client */
	int client_mask_len = 0;

	/* Categorization mask, sent to the client */
	ufp_mask  cat_mask;
	char     *cat_mask_s = NULL;
    char     *user_name = NULL;

	int status       = UFP_OK,
	    returned_val = OPSEC_SESSION_OK;
	static int cnt   = 1;

	fprintf(stderr, "\ncat_handler: Received categorization request(#%d). url: %s\n", cnt++, url);
	/*
	   Check if Dictionary versions match.
	   (Different versions will probably result in wrong categorization)
	 */
	if (dict_ver != server_dict_ver) {
		fprintf(stderr, "Received bad dictionary version (%d)\n", dict_ver);
		status = UFP_DICT_VER_ERR;
	}
	else
		status = UFP_OK;

	/*
	   Retrieve data from the OpsecInfo structure:
	 */
	dst_ip            = opsec_info_get(info, "destination", "ip"  , NULL);
	src_ip            = opsec_info_get(info, "source"     , "ip"  , NULL);
	dst_port          = opsec_info_get(info, "destination", "port", NULL);
	src_port          = opsec_info_get(info, "source"     , "port", NULL);
	client_mask_s     = opsec_info_get(info, "mask", NULL);
	client_mask_len_s = opsec_info_get(info, "mask_len", NULL);
    user_name         = opsec_info_get(info, "user_name", NULL);

	fprintf(stderr, "OpsecInfo data: \
	             \n  destination ip:   %s  \n  source ip:        %s \
	             \n  destination port: %s  \n  source port:      %s \
	             \n  user name:        %s  \n",
	             dst_ip   ? dst_ip   : "none", src_ip   ? src_ip   : "none",
	             dst_port ? dst_port : "none", src_port ? src_port : "none",
	             user_name ? user_name : "none");
	                                               
	if (!client_mask_s || !client_mask_len_s)
		fprintf(stderr, "cat_handler: No client mask found in OpsecInfo\n");
	else
	{
		client_mask_len = atoi(client_mask_len_s);
		fprintf(stderr, "cat_handler: Client mask: %s (len = %d)\n", client_mask_s, client_mask_len);
		if (client_mask_len != ufp_mask_len)
		{
			fprintf(stderr, "cat_handler: Mask length is illegal");
			return OPSEC_SESSION_ERR;
		}
	}

	/*
	   Categorize the URL
	 */
	if (!(cat_mask = ufp_mask_init(ufp_mask_len))) {
		fprintf(stderr,"cat_handler: Unable to create mask (url = %s)\n", url);
		return OPSEC_SESSION_ERR;
	}
	

	if(do_cat( url, &cat_mask ) != OPSEC_SESSION_OK){
		fprintf(stderr, "cat_handler: Error while categorizing URL\n");
		return OPSEC_SESSION_ERR;
	}

	/*
	   Send reply to client
	 */
	if (BC_MODE)
		returned_val = send_bc_reply(session, cat_mask, ufp_mask_len, status);
	else
		returned_val = send_reply(session, cat_mask, ufp_mask_len, dst_ip, status);
	
	if(returned_val != OPSEC_SESSION_OK)
		fprintf(stderr, "cat_handler: can't send cat reply (%s)\n",	opsec_errno_str(opsec_errno));
	else
		fprintf(stderr, "cat_handler: Sent reply (status = %s)\n", (status == UFP_OK) ? "ok" : "error");

	/*
	   Free allocated memory
	 */
	ufp_mask_destroy(cat_mask);

	return returned_val;
}

/*
 * MAIN
 */
int main(int argc, char **argv)
{
	OpsecEnv    *opsec_env = NULL;
	OpsecEntity *server    = NULL;

	/*
	 * Create environment
	 */
	opsec_env = opsec_init(OPSEC_EOL);
	if(!opsec_env){
		fprintf(stderr,"Unable to init environment. (%s)",
				opsec_errno_str(opsec_errno));
		exit(1);
	}
	
	/*
	 *  Initialize entity
	 */
	server = opsec_init_entity(opsec_env, UFP_SERVER,
	                                      OPSEC_ENTITY_NAME, "ufp_server",
	                                      UFP_DESC_HANDLER, desc_handler,
	                                      UFP_DICT_HANDLER, dict_handler,
	                                      UFP_CAT_HANDLER, cat_handler,
	                                      OPSEC_SERVER_PORT, (int)htons(18182),
	                                      OPSEC_EOL);
	
	if(!server || opsec_start_server( server ) ) {
		fprintf(stderr,"Unable to start server! (%s)",
				opsec_errno_str(opsec_errno));
		exit(1);
	}

	/*
	   Print the dictionary server parameters
	 */
	print_dictionary();

	fprintf(stderr, "\nServer is running\n\n");

	opsec_mainloop( opsec_env );

	fprintf(stderr,"UFP server sample program: mainloop returned.\n");

	/*
	 * Free the server entity & environment before exiting.
	 */
	free_all(opsec_env, server);
	
	return 0;
}
