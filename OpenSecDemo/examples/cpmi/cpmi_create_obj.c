
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "opsec/opsec.h"
#include "cpmi/CPMIClient/CPMIClientAPIs.h"

#include "cpmi_client.h"

/********************************
 *
 * Global definitions
 *
 ********************************/
#define DefaultHostName "MyHostdummyName"
#define DefaultIP        "10.1.1.1"

/*******************************************
 *
 * CPMI Client Call-Back Functions
 *
 *******************************************/
static eOpsecHandlerRC
create_object_CB(HCPMIDB db, HCPMIOBJ obj, cpresult stat, cpmiopid opid, void *info);

static eOpsecHandlerRC 
update_obj_CB(HCPMIDB db,cpresult stat,cpmiopid id,void *info);

static eOpsecHandlerRC 
open_db_CB_create(HCPMIDB db, cpresult stat, cpmiopid opid, void *info);

static eOpsecHandlerRC 
open_db_CB_delete(HCPMIDB db, cpresult stat, cpmiopid opid, void *info);

static eOpsecHandlerRC 
delete_obj_CB (HCPMIDB db, cpresult stat, cpmiopid opid, void *info);

static int 
get_host_and_ip(HCPMIDB db, const char **my_host, const char **my_ip);

/******************************************************************************/
eOpsecHandlerRC create_plain_host(OpsecSession *session)
{
    cpresult res;
    cpmiopid id;

    res = CPMIDbOpen(session, "", eCPMI_DB_OM_WRITE, open_db_CB_create, NULL, &id);

    if(res != CP_S_OK) {
        fprintf(stderr, "create_plain_host: failed to open database. Exiting ...\n");
        return OPSEC_SESSION_END;
    }

    return OPSEC_SESSION_OK;
}


eOpsecHandlerRC delete_plain_host(OpsecSession *session)
{
    cpresult res;
    cpmiopid id;

    res = CPMIDbOpen(session, "", eCPMI_DB_OM_WRITE, open_db_CB_delete, NULL, &id);

    if(res != CP_S_OK) {
        fprintf(stderr, "delete_plain_host: failed to open database. Exiting ...\n");
        return OPSEC_SESSION_END;
    }

    return OPSEC_SESSION_OK;
}


/* 
 * Open DB CB
 */
static eOpsecHandlerRC 
open_db_CB_create(HCPMIDB db, cpresult stat, cpmiopid opid, void *info)
{
    cpmiopid id;
    const char *obj_type = "host_plain";
    
    fprintf(stderr, "open_db_CB_create: db %x, status %d, opid %d, info %x\n", db, stat, opid, info);

    /*
     * check the Call Back status.
     */
    if (CP_FAILED(stat)) {
        fprintf(stderr, "open_db_CB_create: failed to open DataBase - %s.\n", CPGetErrorMessage(stat));
        return OPSEC_SESSION_END;
    }

    /* create new host object - use "host_plain" schema class */
    if (CPMIDbCreateObject(db, obj_type, create_object_CB, info, &id) != CP_S_OK) {
        fprintf(stderr, "open_db_CB_create: failed to create object - %s.\n", CPGetErrorMessage(stat));
        return OPSEC_SESSION_END;
    }

    return OPSEC_SESSION_OK;
}


/* 
 * create Object CB
 */
static eOpsecHandlerRC
create_object_CB(HCPMIDB db, HCPMIOBJ obj, cpresult stat, cpmiopid opid, void *info)
{
    tCPMI_FIELD_VALUE Val;
    cpmiopid          id;
    const char *host = NULL;
    const char *ip = NULL;
	
    /*
     * check the Call Back status.
     */
    if (CP_FAILED(stat)) {
        fprintf(stderr, "create_object_CB: failed to create object - %s.\n", CPGetErrorMessage(stat));
        return OPSEC_SESSION_END;
    }

    get_host_and_ip(db, &host, &ip);

    if (!host)
        host = DefaultHostName;
    if(!ip)
        ip = DefaultIP;
    
    /* set the new object name */
    if (CPMIObjSetName(obj, host) != CP_S_OK) {
        fprintf(stderr, "create_object_CB: Cannot set name object\n");
        return OPSEC_SESSION_END;
    }
	
    /* casting the (field) Val type as string */
    Val.fvt = eCPMI_FVT_CTSTR;

    /* assigning the host IP */
    Val.ctstrFv = ip;

    /* setting the new field Val */
    if (CPMIObjSetFieldValueByName (obj,"ipaddr",&Val)) {
        fprintf(stderr, "create_object_CB: Cannot set field \"ipaddr\".\n");
        return OPSEC_SESSION_END;
    }

    /* releasing field value */
    CPMIReleaseFieldValue(&Val);

    if (CPMIObjUpdate(obj,update_obj_CB, NULL, &id) != CP_S_OK) {
        fprintf(stderr, "create_object_CB: update failed.\n");
        return OPSEC_SESSION_END;
    }

    return OPSEC_SESSION_OK;
}


/*
 * Update Object CB
 */
static eOpsecHandlerRC 
update_obj_CB(HCPMIDB db,cpresult stat,cpmiopid id,void *info)
{
	
    if (stat != CP_S_OK) 
        fprintf(stderr, "update_obj_CB: failed to update object - %s.\n", CPGetErrorMessage(stat));
        
    return OPSEC_SESSION_END;
}


/*
 * Open DB CB - for delete.
 */
static eOpsecHandlerRC 
open_db_CB_delete(HCPMIDB db, cpresult stat, cpmiopid opid, void *info)
{
    HCPMITBL    tbl = NULL;
    const char *host = NULL;
    cpmiopid    id;
    cpresult    res;

    fprintf(stderr, "open_db_CB_delete: db %x, status %d, opid %d, info %x\n", db, stat, opid, info);

    /*
     * check the Call Back status.
     */
    if (CP_FAILED(stat)) {
        fprintf(stderr, "open_db_CB_delete: failed to open DataBase - %s.\n", CPGetErrorMessage(stat));
        return OPSEC_SESSION_END;
    }
    
    if (CPMIDbGetTable (db, "network_objects", &tbl) != CP_S_OK) {
        fprintf(stderr, "open_db_CB_delete: failed to get network_objects table - %s\n", 
                CPGetErrorMessage(stat));
        return OPSEC_SESSION_END;
    }

    get_host_and_ip(db, &host, NULL);
    if (!host)
        host = DefaultHostName;
    
    if ((res = CPMITblDeleteObj (tbl, host, delete_obj_CB, (void *)strdup(host), &id)) != CP_S_OK) 
        fprintf(stderr, "open_db_CB_delete: failed to get network_objects table - %s\n", 
                CPGetErrorMessage(stat));

    CPMIHandleRelease(tbl);
    
    return (res == CP_S_OK ? OPSEC_SESSION_OK : OPSEC_SESSION_END);
}


static eOpsecHandlerRC 
delete_obj_CB (HCPMIDB db, cpresult stat, cpmiopid opid, void *info)
{
    if (CP_FAILED(stat)) 
        fprintf(stderr, "delete_obj_CB: failed to delete object - %s.\n", CPGetErrorMessage(stat));
    else 
        fprintf(stderr, "delete_obj_CB: object %s was deleted.\n", info ? (char *)info : "No Name");

    if (info)
        free(info);
    
    return OPSEC_SESSION_END;
}

/*
 * return 0 on success, else -1.
 */
static int get_host_and_ip(HCPMIDB db, const char **my_host, const char **my_ip)
{
    OpsecSession *session = NULL;
    OpsecEnv     *env     = NULL;
    const char *conf_var = NULL;

    if (CPMIDbGetSession(db, &session) != CP_S_OK) {
        fprintf(stderr, "get_host_and_ip: failed to get session from DB\n");
        return -1;
    }

    if ( (env = opsec_get_session_env(session)) == NULL) {
        fprintf(stderr, "get_host_and_ip: failed to get env from session\n");
        return -1;
    }

    if (my_host)
        *my_host = opsec_get_conf(env, "host", NULL);

    if (my_ip)
        *my_ip   = opsec_get_conf(env, "ip", NULL); 

    return 0;
}    
