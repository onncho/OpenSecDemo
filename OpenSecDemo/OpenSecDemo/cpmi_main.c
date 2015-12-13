/***************************************************************************
 *                                                                         *
 * cpmi_client.c : Sample OPSEC CPMI client.                               *
 *                                                                         *
 * This is a part of the Check Point OPSEC SDK                             *
 * Copyright (c) 1994-1999 Check Point Software Technologies, Ltd.         *
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
 * This is an example of a simple use of the CPMI API.                     *
 * This client contains a few files, each one demonstrates different use   *
 * and different functionaly of CPMI.                                      * 
 *                                                                         * 
 * Files:                                                                  * 
 *  cpmi_main.c - contains the OPSEC initializaion and some utilities for  *
 *                this program.                                            * 
 *  cpmi_print_obj.c - prints objects. Demonstrates how to parse objects.  *
 *  cpmi_read_obj.c - parse all tables, prints their names and demonstrate *
 *                    how to get objects from a table.                     *
 *  cpmi_get_status.c - demonstrate how to retrieve status of application. *
 *  cpmi_get_notification.c - demostrates how to register and handle       *
 *                            notifications on changes in the database     * 
 *  cpmi_create_obj.c - demonstrate how to create and delete a simple      *
 *                      object.                                            *
 *  cpmi_client.h - header files for this program.                         *
 *  cpmi.conf - configuration file for this program.                       * 
 *************************************************************************** 

Usage: Cpmi_main.exe <options>
options:
  -s - print status of application

  -t [-v table <table name> ] - print list of tables.
     if -v is used print also all objects in table 'table name'

  -n - get notification on changes in database

  -c [-v host <host name> -v ip <a.b.c.d>] - create plain host in database
     if -v is used, it creates the host with 'host name' and 'ip'
     otherwise this client uses defaults.

  -d [-v host <host name>] - delete plain host from database
     if -v is used, delete the host with 'host name' (if exists) 
     otherwise this client uses defaults.
  
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

#include "../include/opsec/opsec.h"
#include "../include/opsec/cpmiapi_opsec.h"
#include "../include/opsec/cpmiapi_opsec.h"
#include "../include/opsec/opsec_error.h"
#include "../include/cpmi/CPMIClient/CPMIClientAPIs.h"

#include "cpmi_client.h"

/*
    --------------------
     Global definitions
    --------------------
 */
#define DEFAULT_IP      "127.0.0.1"
#define DEFAULT_PORT    18190
#define USER_NAME       "aa"
#define USER_PASSWORD  "aaaa"

typedef enum { ActionNone, 
                ActionPrintTbl, 
                ActionGetStatus,
                ActionGetNotification,
                ActionCreatePlainHost,
                ActionDeletePlainHost
} eCpmiAction;

eCpmiAction action = ActionNone;

static int parse_command_line(int ac, char *argv[]);
static void Usage();

/*******************************************
 *
 * CPMI Client Session Handlers
 *
 *******************************************/
static eOpsecHandlerRC
cpmi_start_handler(OpsecSession *session);

static void
cpmi_end_handler(OpsecSession *session);

static eOpsecHandlerRC 
cpmi_session_established(OpsecSession *session);

static eOpsecHandlerRC 
bind_server_CB(OpsecSession *session,cpresult stat,void *info);
/*********************************
 *
 * Main
 *
 *********************************/
int main (int ac, char *av[])
{

    static OpsecEntity  *client;
    static OpsecEntity  *server;
    OpsecEnv            *env;
    OpsecSession        *session;

    /* parse command line */
    parse_command_line(ac, av);

    env = opsec_init(OPSEC_CONF_ARGV, &ac, av,
                      OPSEC_CONF_FILE, "cpmi.conf", 
                      OPSEC_EOL);

    if (!env)    {
        fprintf(stderr, "Cannot init OpsecEnv\n");
	exit(-1);
    }

    client = opsec_init_entity(env,
                               CPMI_CLIENT,
                               OPSEC_ENTITY_NAME,"cpmi_client",
                               OPSEC_SESSION_START_HANDLER,cpmi_start_handler,
                               OPSEC_SESSION_ESTABLISHED_HANDLER,
                               cpmi_session_established,
                               OPSEC_SESSION_END_HANDLER,cpmi_end_handler,
                               OPSEC_EOL);

    server = opsec_init_entity(env,
                               CPMI_SERVER,
                               OPSEC_ENTITY_NAME, "cpmi_server",
                               OPSEC_SERVER_IP, inet_addr(DEFAULT_IP),
                               OPSEC_SERVER_AUTH_PORT, (int)htons(DEFAULT_PORT),
                               OPSEC_EOL);	

    if (!client || !server) {
        fprintf(stderr,"failed to initialize client(%x) or server(%x) entities.\n", client, server);
        exit(-1);
    }

    /* 
     * Start the session
     */
    CPMISessionNew(client,server,0,&session);
    if(!session) {
        fprintf(stderr, "CPMISessionNew failed.\n");
        fprintf(stderr, "Opsec error: %s\n", opsec_errno_str(opsec_errno));
        exit(-1);
    }
  
    /*
     * Start Main Loop
     */
    opsec_mainloop(env);

    /* Cleanup */
    opsec_destroy_entity(server);
    opsec_destroy_entity(client);
    opsec_env_destroy(env);
    return 0;
}


/***************************************************
 *
 * Handlers Implementation
 *
 ***************************************************/
/* 
 * Initialize
 */
static eOpsecHandlerRC
cpmi_start_handler(OpsecSession *session)
{	
    fprintf(stderr, "cpmi_start_handler: %x\n", session);

    /*
     * Initialization of the session
     */
     
    return OPSEC_SESSION_OK;
}


/* 
 * Session Established Handler
 */
static eOpsecHandlerRC 
cpmi_session_established(OpsecSession *session)
{
    /* client starts by binding the server */
    cpmiopid id;
    cpresult res;

    fprintf(stderr, "cpmi_session_established: %x \n", session);

    res = CPMISessionBind(session, bind_server_CB, NULL, &id);

    /* this is how to use user bind
     *
    res = CPMISessionBindUser(session, USER_NAME, USER_PASSWORD,
                              bind_server_CB, NULL, &id);
     */
     
    if(res != CP_S_OK) {
        printf("Cannot bind Server: %s\n", CPGetErrorMessage(res));
        CPMISessionEnd(session);
    }

    return OPSEC_SESSION_OK;
}


/* 
 * Clean-Up
 */
static void
cpmi_end_handler(OpsecSession *session)
{

    fprintf(stderr, "cpmi_end_handler: %x\n", session);
    
    /*
     *  Destruction of the session
     */
    
}

/*
 * Handle Bind reply  
 */
static eOpsecHandlerRC 
bind_server_CB(OpsecSession *session,cpresult stat,void *info)
{
    fprintf(stderr, "bind_server_CB: session %x, status %d, info %x\n", session, stat, info);

    /*
     * check the Call Back status.
     */
    if (CP_FAILED(stat)) {
        fprintf(stderr, "bind_server_CB: client failed to bind - %s\n",CPGetErrorMessage(stat));
        return OPSEC_SESSION_END;
    }
	
    /*
     * open DataBase.
     */
    switch (action) {
    case ActionPrintTbl: 
        return print_table(session);
    
    case ActionGetStatus:
        return get_status(session);
        
    case ActionGetNotification:
        return get_notification(session);

    case ActionCreatePlainHost:
        return create_plain_host(session);
        
    case ActionDeletePlainHost:
        return delete_plain_host(session);
        
    default:
        return OPSEC_SESSION_END;
        break;
    }
}



/***************************************************
 *
 * Internal Functions Implementation
 *
 ***************************************************/
static void Usage(char *ProgName)
{
    fprintf(stderr,	"\nUsage: %s <options>\n", ProgName);
    fprintf(stderr,	"options:\n");
    fprintf(stderr, "  -s - print status of application\n\n");
    fprintf(stderr, "  -t [-v table <table name> ] - prints list of tables.\n");
    fprintf(stderr, "     if -v is used prints also all objects in table 'table name'\n\n");
    fprintf(stderr, "  -n - get notification on changes in database\n\n");
    fprintf(stderr, "  -c [-v host <host name> -v ip <a.b.c.d>] - create plain host in database\n");
    fprintf(stderr, "     if -v is used, it creates the host with 'host name' and 'ip' \n");
    fprintf(stderr, "     otherwise this client uses defaults. \n\n");
    fprintf(stderr, "  -d [-v host <host name>] - delete plain host from database\n");
    fprintf(stderr, "     if -v is used, delete the host with 'host name' (if exists)\n");
    fprintf(stderr, "     otherwise this client uses defaults. \n\n");
    
    exit(1);
}

static int parse_command_line(int ac, char *av[])
{
    int i, not_end;
    
    for (i = 1, not_end = 1; i < ac && not_end; i++) {
        if (av[i][0] != '-')
            Usage(av[0]);
        switch (av[i][1]) {
            case 't':
                action = ActionPrintTbl;
                not_end = 0;
                break;

            case 's':
                action = ActionGetStatus;
                not_end = 0;
                break;

            case 'n':
                action = ActionGetNotification;
                not_end = 0;
                break;

            case 'c':
                action = ActionCreatePlainHost;
                not_end = 0;
                break;

            case 'd':
                action = ActionDeletePlainHost;
                not_end = 0;
                break;
                
            default:
                Usage(av[0]);
        }
    }

    if (action == ActionNone) 
       Usage(av[0]);
       
    return 0;
}

