/***************************************************************************
 *                                                                         *
 * amon_server.c : Sample OPSEC AMON Server                                *
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
 *                                                                         *
 ***************************************************************************/

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#ifdef WIN32
#include <winsock.h>
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "opsec/opsec.h"
#include "opsec/opsec_error.h"

#include "opsec/amon_oid.h"
#include "opsec/amon_api.h"
#include "opsec/amon_reply_server_api.h"
#include "opsec/amon_server.h"

/*******************************************
 *
 * Global Definitions
 *
 *******************************************/
#define AMON_DEFAULT_PORT 18193

static time_t application_start_time = 0;
static int    sdk_build_number = 0;
static char  *sdk_version = NULL;

/*******************************************
 *
 * Amon Server Handlers
 *
 *******************************************/
static eOpsecHandlerRC 
amon_start_handler(OpsecSession *session);

static eOpsecHandlerRC 
amon_end_handler(OpsecSession *session);

static eOpsecHandlerRC 
amon_request_handler(OpsecSession *session, AmonRequest *req, AmonReqId id);

static eOpsecHandlerRC 
amon_cancel_handler(OpsecSession *session, AmonReqId id);

/*******************************************
 *
 * Amon Server Interanl Functions
 *
 *******************************************/
static int  process_request(OpsecSession *session, AmonRequest *req, AmonReqId id);
static int  db_init(); 
static void db_destroy();
/*******************************************
 *
 * Main
 *
 *******************************************/
int main(int argc, char **argv)
{
    OpsecEnv    *env    = NULL;
    OpsecEntity *server = NULL;

    /* save application Up-Time */
    application_start_time = time(NULL);

    /* get sdk build number */
    opsec_get_sdk_version(NULL, NULL, &sdk_build_number, &sdk_version, NULL);

    /*
     * Initialize the MIB database
     */
    if ( db_init() ) {
        fprintf(stderr, "%s: db_init_failed", argv[0]);
        exit(1);
    }

    /*
     * Initialize OPSEC Environment
     * For more options of initialization see opsec.pdf
     */
    env = 
        opsec_init(OPSEC_CONF_ARGV, &argc, argv,
                   OPSEC_EOL);

	if (env == NULL) {
        fprintf(stderr, "%s: opsec_init failed\n", argv[0]);
        exit(1);
    }

    /* 
     * Initialize AMON Server Entity 
     * For more options of initialization see opsec.pdf
     */
	server =
	    opsec_init_entity(env, 
                          AMON_SERVER,
                          OPSEC_ENTITY_NAME, "amon_server",
                          OPSEC_SERVER_PORT, (int)htons(AMON_DEFAULT_PORT),
                          OPSEC_SESSION_START_HANDLER, amon_start_handler,
                          OPSEC_SESSION_END_HANDLER,   amon_end_handler,
                          AMON_REQUEST_HANDLER,        amon_request_handler,
                          AMON_CANCEL_HANDLER,         amon_cancel_handler,
                          OPSEC_EOL);

	if (server == NULL) {
        fprintf(stderr, "%s: opsec_init_entity failed\n", argv[0]);
        exit(1);
    }

    /*
     * start the server: bind and listen
     */
	if (opsec_start_server(server) < 0) {
        fprintf(stderr, "%s: opsec_start_server failed\n", argv[0]);
        exit(1);
    }
    
    opsec_mainloop(env);

    fprintf(stderr, "%s: opsec_mainloop returned\n", argv[0]);

	/*********************************
	 * Clean-up
	 *********************************/
    opsec_destroy_entity(server);
	opsec_env_destroy(env);
    db_destroy();    

	return 0;
}


/*******************************************
 *
 * Handlers Implementation
 *
 *******************************************/
/*
 * Initialize
 */ 
static eOpsecHandlerRC 
amon_start_handler(OpsecSession *session)
{
    fprintf(stderr, "amon_start_handler: session(%x)\n", session);

    /*
     * initialization of the session
     */
    
    return OPSEC_SESSION_OK;
}

/*
 * Clean-up
 */ 
static eOpsecHandlerRC 
amon_end_handler(OpsecSession *session)
{
    fprintf(stderr, "amon_end_handler: session(%x)\n", session);

    /*
     * Destruction of the session 
     */

    return OPSEC_SESSION_OK;
}

/*
 * Handle the request
 */ 
static eOpsecHandlerRC 
amon_request_handler(OpsecSession *session, 
                     AmonRequest *req,
                     AmonReqId id)
{
    int rc;
    
    fprintf(stderr, "amon_request_handler: session(%x) ; request(%x) ; id (%d)\n",
            session, req, id);

    /* 
     * process the request, and send back the reply for this request
     */
    rc = process_request(session, req, id);
    
    return (rc == 0 ? OPSEC_SESSION_OK : OPSEC_SESSION_ERR);
}


/*
 * Hadle Cancel Request
 */ 
static eOpsecHandlerRC 
amon_cancel_handler(OpsecSession *session, 
                    AmonReqId id)
{
    fprintf(stderr, "amon_cancel_handler: session(%x) - request # %d canceled\n", session, id);

    /* 
     * handle the cancel of a request
     */
     
    return OPSEC_SESSION_OK;
}
 

/**************************************************
 *
 * Internal functions - DB implementation
 * Note that this is a very simple way to implement
 * status DB
 **************************************************/

typedef enum {
    GetStatusOK, 
    GetStatusDescription, 
    GetVendor, 
    GetProduct, 
    GetProductVersion,
    GetSdkVersion, 
    GetSdkBuild, 
    GetAppTime,
    GetMyName,
    GetMyNumber,
    GetNone
} DataType;

/* the Database is ordered */
struct AmonDb {
    char *oid_str;
    Oid *oid;
    char *name;
    DataType data_type;
} DB [] = {
    /* start of opsec generic (mandatory) oid set */
    {"1.3.6.1.4.1.2620.2.1.1.1", 0, "StatusOK",            GetStatusOK}, 
    {"1.3.6.1.4.1.2620.2.1.1.2", 0, "StatusDescription",   GetStatusDescription}, 
    {"1.3.6.1.4.1.2620.2.1.1.3", 0, "opsecVendor",         GetVendor},          
    {"1.3.6.1.4.1.2620.2.1.1.4", 0, "opsecProduct",        GetProduct},
    {"1.3.6.1.4.1.2620.2.1.1.5", 0, "opsecProductVersion", GetProductVersion},
    {"1.3.6.1.4.1.2620.2.1.1.6", 0, "opsecSdkVersion",     GetSdkVersion},
    {"1.3.6.1.4.1.2620.2.1.1.7", 0, "opsecSdkBuild",       GetSdkBuild},
    {"1.3.6.1.4.1.2620.2.1.1.8", 0, "opsecAppUpTime",      GetAppTime},
    /* end-of opsec generic (mandatory) oid set */
    /* start of private oid set */
    {"1.7.1",                    0, "myName",              GetMyName},
    {"1.7.2",                    0, "myNumber",            GetMyNumber},
    /* end of private oid set */
    {NULL,                       0, NULL,                  GetNone}
};


static int  db_process_oid(const Oid *oid, AmonReply *rep, eAmonScope scope);
static int  get_value(opsec_value_t *value, struct AmonDb *pDB);
static int  add_oid_to_reply(AmonReply *rep, struct AmonDb *pDB, const Oid *oid);
static struct AmonDb *find_oid(const Oid *oid, eOidContain *contain);

/*
 * Initialize DataBase.   
 * return 0 on success, else > 0
 */
static int db_init() 
{   
    struct AmonDb *pDB = NULL;
    int err = 0;

    for (pDB = DB; pDB->oid_str != NULL; pDB++) {
        if (oid_create_from_string(&(pDB->oid), pDB->oid_str) != EO_OK) {
            fprintf(stderr, "db_init: fail to create oid (%s)\n", pDB->oid_str);
            err++;
            break;
       } 
    }

    if (err)
        db_destroy();

    return err;    
}


/*
 * Destroy DataBase
 */
static void db_destroy()
{
    struct AmonDb *pDB = NULL;

    for (pDB = DB; pDB->oid_str != NULL; pDB++) 
        oid_destroy(pDB->oid); 
}


static int get_value(opsec_value_t *value, struct AmonDb *pDB)
{
    int rc = 0;
    char *msg = NULL;
    
    if (pDB == NULL || value == NULL) {
        fprintf(stderr, "get_value: Invalid Parameters - opsec_value_t (%x) ; AmonDb (%x)\n",
                value, pDB);
        return -1;        
    }
    
    switch (pDB->data_type) {
    case GetStatusOK:
        if (opsec_value_set(value, OPSEC_VT_I32BIT, 0) != EO_OK) {
            msg = "get_value: failed to set Status OK code.\n";
            rc = -1;
        }
        break;
    
    case GetStatusDescription:
        if (opsec_value_set(value, OPSEC_VT_STRING, "no problems") != EO_OK) {
            msg = "get_value: failed to set status description.\n";
            rc = -1;
        }
        break;
        
    case GetVendor:
        if (opsec_value_set(value, OPSEC_VT_STRING, "Check Point Software Technologies, Ltd.") != EO_OK) {
            msg = "get_value: failed to set Vendor\n";
            rc = -1;
        }
        break;
        
    case GetProduct:
        if (opsec_value_set(value, OPSEC_VT_STRING, "OPSEC SDK AMON Sample Server") != EO_OK) {
            msg = "get_value: failed to set Product\n";
            rc = -1;
        }
        break;
     
    case GetProductVersion:
        if (opsec_value_set(value, OPSEC_VT_STRING, "1.0") != EO_OK) {
            msg = "get_value: failed to set Product Version\n";
            rc = -1;
        }
        break;
    
    case GetSdkVersion:
        if (opsec_value_set(value, OPSEC_VT_STRING, sdk_version) != EO_OK) {
            msg = "get_value: failed to set SDK Version\n";
            rc = -1;
        }
        break;
     
    case GetSdkBuild:
        if (opsec_value_set(value, OPSEC_VT_UI32BIT, sdk_build_number) != EO_OK) {
            msg = "get_value: failed to set SDK Build\n";
            rc = -1;
        }
        break;
        
    case GetAppTime:
    {   
        time_t now = time(NULL);
        now -= application_start_time;
        
        if (opsec_value_set(value, OPSEC_VT_UI32BIT, now) != EO_OK) {
            msg = "get_value: failed to set App Time\n";
            rc = -1;
        }
        break;
    }
    case GetMyName:
        if (opsec_value_set(value, OPSEC_VT_STRING, "Amon Server Jr.") != EO_OK) {
            msg = "get_value: failed to set My Name\n";
            rc = -1;
        }
        break;
    
    case GetMyNumber:
        if (opsec_value_set(value, OPSEC_VT_UI32BIT, 876543210) != EO_OK) {
            msg = "get_value: failed to set My Number\n";
            rc = -1;
        }
        break;

    case GetNone:
    default:
        msg = "get_value: Unsupported data type\n";
        rc = -1;
        break;
    }

    if (rc)
        fprintf(stderr, msg);

    return rc;   
}


static int
add_oid_to_reply(AmonReply *rep, struct AmonDb *pDB, const Oid *oid)
{
    opsec_value_t *value = NULL;
    OidRep *oid_rep = NULL;
    int rc = 0;
    eOidError oid_err = OidErr_Ok;
    const Oid *l_oid = NULL;
    
    if ( (value = opsec_value_create()) == NULL) {
        fprintf(stderr, "add_oid_to_reply: failed to create opsec_value\n");
        return -1; 
    }

    if (pDB == NULL) {
        /* the oid was not found in the DB */
        oid_err = OidErr_NotFound;
        if ( (l_oid = oid) == NULL) {
            fprintf(stderr, "add_oid_to_reply: there is no oid to set\n");
            opsec_value_dest(value);
            return -1;
        }
    } else {
        if ( get_value(value, pDB) != 0 ) {
            fprintf(stderr, "add_oid_to_reply: failed to get value\n");
            opsec_value_dest(value);
            return -1;
        }
        l_oid = pDB->oid;
    }
    
    if ( oid_reply_create_with_all(&oid_rep, l_oid, value, oid_err) != EO_OK) {
        fprintf(stderr, "add_oid_to_reply: failed to create OidReply\n");
        opsec_value_dest(value);
        return -1;
    }
    
    if (amon_reply_add_oid(rep, oid_rep) != EO_OK) {
        fprintf(stderr, "add_oid_to_reply: failed to add OidRep to AmonReply\n");
        rc = -1;
    }

    opsec_value_dest(value);
    oid_reply_destroy(oid_rep);
    
    return rc;
}


/*
 * search for the given oid in the database or one that contains it
 *
 * returns pointer to the first entry in the database, else NULL
 */
static struct AmonDb *find_oid(const Oid *oid, eOidContain *contain)
{
    struct AmonDb *pDB = NULL;
    
    /* find the first oid that contain or identical to the given oid */
    for (pDB = DB; pDB->oid_str != NULL; pDB++) {

        *contain = oid_contain(pDB->oid, oid);

        if ( *contain == OidContain_LeftContainRight || 
             *contain == OidContain_Identical) 
            return pDB;
    }

    return NULL;
}


/*
 * process each oid in the request
 *
 * return codes: 0 for success, else -1
 */
static int
db_process_oid(const Oid *oid, AmonReply *rep, eAmonScope scope)
{
    struct AmonDb *pDB = NULL;
    eOidContain contained;

    /* find the next oid in the DB */
    pDB = find_oid(oid, &contained);    /* assume that oid is the right operand of the oid_contain */
    
    switch (scope) {
    case AmonScope_GetNext:
        if (pDB == NULL)   /* oid not found */
            return add_oid_to_reply(rep, pDB, oid);

        if (contained == OidContain_LeftContainRight)    /* the next oid is this entry in the Database */ 
            return add_oid_to_reply(rep, pDB, oid);

        /* check if the next entry in the Database is valid */
        pDB++;
        return add_oid_to_reply(rep, ( (pDB->oid_str != NULL) ? pDB : NULL ), oid);

        break;
    
    case AmonScope_GetOne:

        if (pDB != NULL && contained == OidContain_Identical)   /* oid found */
            return add_oid_to_reply(rep, pDB, oid);

        return add_oid_to_reply(rep, NULL, oid);              /* oid not found */
        break;

    case AmonScope_GetAll:

        if (pDB == NULL)   /* oid not found */
            return add_oid_to_reply(rep, NULL, oid);

        if (pDB != NULL && contained == OidContain_Identical) /* there is only one oid in this sub-tree */
            return add_oid_to_reply(rep, pDB, oid); 

        /* all oid's in the DB that are in the subtree of the given oid */
        for ( ; pDB->oid_str != NULL; pDB++) {
            if ( (contained = oid_contain(pDB->oid, oid)) != OidContain_LeftContainRight ) 
                /* oid is not part of the sub-tree */
                /* it is possible to break here since the DB is ordered */
                continue;
            
            if ( add_oid_to_reply(rep, pDB, oid) != 0 ) {
                fprintf(stderr, "db_process_oid: failed to add oid (%s) to reply\n", pDB->oid_str);
                return -1;
            }
        }

        return 0;
        break;
        
    default:
        fprintf(stderr, "db_process_oid: Unknown scope %d\n", scope);
        return -1;
        break;
    }
}


/*
 * Process a request, build the reply and send it back to the client
 *
 * return 0 on success, else -1
 */
static int process_request(OpsecSession *session, AmonRequest *req, AmonReqId id)
{
    AmonReply       *amon_rep   = NULL;
    unsigned int    num_of_oids = 0;
    int             err_flag    = 0;
    AmonRequestIter *iter       = NULL;
    const Oid       *oid        = NULL;
    eAmonScope      scope; 
                          
    fprintf(stderr, "process_request: session(%x) ; request(%x) ; id (%d)\n",
            session, req, id);
           
    /* get the number of oids in the request, and the scope of the request */
    num_of_oids = amon_request_get_num_of_oids(req);
    scope = amon_request_get_scope(req);
    
    /* create reply object */
    if (amon_reply_create(&amon_rep) != EO_OK) {
        fprintf(stderr, "process_request: fail to create AmonReply\n");
        return -1;
    }

    /* create an iterator for the reqeust */
    if (amon_request_iter_create(req, &iter) != EO_OK) {
        fprintf(stderr, "process_request: fail to create Request Iterator\n");
        amon_reply_destroy(amon_rep);
        return -1;
    }

    /*
     * iterate on the request, 
     * for each oid in the request find the valid value/s for this oid,
     */
    while ((oid = amon_request_iter_next(iter)) != NULL) {
        if ( (err_flag = db_process_oid(oid, amon_rep, scope)) == -1 ) 
            break;
    }

    /* destroy the iterator */
    amon_request_iter_destroy(iter);
    
    /* if there are no errors we should send the reply back */
    if (err_flag == 0) {
        amon_reply_set_error(amon_rep, AmonError_OK);

        /* set last reply marker */
        amon_reply_set_last_reply_mark(amon_rep, LastReply_True);

        /* send the reply */
        if (amon_reply_send(session, amon_rep, id) != EO_OK) {
            fprintf(stderr, "process_request: Fail to send reply\n");
            err_flag = -1;
        }
    }    

    /* clean-up */
    amon_reply_destroy(amon_rep);
    
    return err_flag;
}

