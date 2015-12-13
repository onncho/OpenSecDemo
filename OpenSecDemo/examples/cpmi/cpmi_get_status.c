
#include <stdio.h>
#include <string.h>

#include "opsec/opsec.h"
#include "cpmi/CPMIClient/CPMIClientAPIs.h"

#include "cpmi_client.h"

/*******************************************
 *
 * CPMI Client Call-Back Functions
 *
 *******************************************/
static eOpsecHandlerRC
query_object_CB(HCPMIDB db, HCPMIRSLT ResIr, cpresult stat, cpmiopid id, void *info);

static eOpsecHandlerRC
query_applications_CB(HCPMIDB db, HCPMIRSLT ResIr, cpresult stat, cpmiopid _id, void *info);

static eOpsecHandlerRC 
open_db_CB_status(HCPMIDB db, cpresult stat, cpmiopid opid, void *info);

/***************************************************************/
eOpsecHandlerRC get_status(OpsecSession *session)
{
    cpresult res;
    cpmiopid id;

    res = CPMIDbOpen(session, "", eCPMI_DB_OM_READ, open_db_CB_status, NULL, &id);

    if(res != CP_S_OK) {
        fprintf(stderr, "get_status: failed to open database. Exiting ...\n");
        return OPSEC_SESSION_END;
    }

    return OPSEC_SESSION_OK;
}


/* 
 * Open DB CB
 */
static eOpsecHandlerRC 
open_db_CB_status(HCPMIDB db, cpresult stat, cpmiopid opid, void *info)
{
    HCPMITBL        Tbl=NULL;
    cpmiopid        id;
    cpresult rc = CP_S_OK;
	
    fprintf(stderr, "open_db_CB_status: db %x, status %d, opid %d, info %x\n", db, stat, opid, info);

    /*
     * check the Call Back status.
     */
    if (CP_FAILED(stat)) {
        fprintf(stderr, "open_db_CB_status: failed to open DataBase - %s.\n", CPGetErrorMessage(stat));
        return OPSEC_SESSION_END;
    }

    if (CPMIDbGetTable(db, "applications", &Tbl) != CP_S_OK) {
        fprintf(stderr, "open_db_CB_status: failed to get application table\n");
        return OPSEC_SESSION_END;
    }
    
    rc = CPMITblQueryObjects (Tbl, NULL, query_object_CB, NULL, &id);
    CPMIHandleRelease(Tbl);
        
    return (rc == CP_S_OK ? OPSEC_SESSION_OK : OPSEC_SESSION_END);
}


/* 
 * Query Object CB
 */
static eOpsecHandlerRC
query_object_CB(HCPMIDB db, HCPMIRSLT ResIr, cpresult stat, cpmiopid _id, void *info)
{
    HCPMIITEROBJ ObjIter;
    HCPMIOBJ     Obj;
    HCPMIAPP     AppBuf[1024], App;
    unsigned int  AppBuf_count = 0;
    const char  *table_name = NULL;
    cpmiopid     id;
    int          end_session = 1;
    int          err = 0;
    unsigned int i = 0;
    
    /*
     * check the Call Back status.
     */
    if (CP_FAILED(stat)) {
        fprintf(stderr, "query_object_CB: failed to query - %s.\n", CPGetErrorMessage(stat));
        return OPSEC_SESSION_END;
    }

    if ( (stat = CPMIResultIterObj(ResIr, &ObjIter)) != CP_S_OK)	{
        fprintf(stderr, "query_object_CB: Cannot get Object iteration handle - %s\n", 
                CPGetErrorMessage(stat));
        return OPSEC_SESSION_END;
    }

    if (CPMIIterObjIsEmpty(ObjIter) == CP_S_OK) 	{
        fprintf(stderr, "query_object_CB: No Objects were found\n");
        CPMIHandleRelease(ObjIter);
        return OPSEC_SESSION_END;
    }

	/* print each object and query its status */
    while ( (CPMIIterObjIsDone(ObjIter)) != CP_S_OK ) {
        CPMIIterObjGetNext (ObjIter, &Obj);
        if (!Obj) {
            err++; 
            fprintf(stderr, "query_object_CB: Cannot Get Object\n");
            break;
        }

        if (CPMIObjGetAppHandle (Obj, &App) != CP_S_OK) {
            fprintf(stderr, "query_object_CB: failed to get Application Handle\n");
            break;
        }

        AppBuf[AppBuf_count++] = App;
        
        CPMIHandleRelease(Obj);
    }

	CPMIHandleRelease(ObjIter);

    if (!err)
        err = CPMIDbGetAppsStatus(db, AppBuf, AppBuf_count, 
                                    query_applications_CB, NULL, &id);  

    for (i = 0; i < AppBuf_count; i++)
        CPMIHandleRelease(AppBuf[i]);
    
    return (err != CP_S_OK ? OPSEC_SESSION_END : OPSEC_SESSION_OK);
}


static eOpsecHandlerRC
query_applications_CB(HCPMIDB db, HCPMIRSLT ResIr, cpresult stat, cpmiopid _id, void *info)
{
    HCPMIITEROBJ ObjIter;
    HCPMIOBJ     Obj;
    HCPMITBL     Tbl;
    const char *table_name = NULL;
    
    /*
     * check the Call Back status.
     */
    if (CP_FAILED(stat)) {
        fprintf(stderr, "query_applications_CB: failed to query - %s.\n", CPGetErrorMessage(stat));
        return OPSEC_SESSION_END;
    }

    /* geting object Iteration handle */
    if ( (stat = CPMIResultIterObj(ResIr,&ObjIter)) != CP_S_OK)	{
        fprintf(stderr, "query_applications_CB: Cannot get Object iteration handle - %s\n", 
                CPGetErrorMessage(stat));
        return OPSEC_SESSION_END;
    }

    /* Is this table empty ? (meaning with no objects) */
    if (CPMIIterObjIsEmpty(ObjIter) == CP_S_OK) 	{
        fprintf(stderr, "query_applications_CB: No Objects were found\n");
        CPMIHandleRelease(ObjIter);
        return OPSEC_SESSION_END;
    }
	
    while ( (CPMIIterObjIsDone(ObjIter)) != CP_S_OK ) {
        CPMIIterObjGetNext (ObjIter,&Obj);
        if (!Obj) {
            fprintf(stderr, "query_applications_CB: Cannot Get Object\n");
            break;
        }

        CPMIObjGetTbl(Obj, &Tbl);
        CPMITblGetName (Tbl, &table_name);
        fprintf(stdout, "\nPrinting Objects From Table %s\n", table_name);
        CPMIHandleRelease(Tbl);
        
        print_obj(Obj, 2);

        CPMIHandleRelease(Obj);
    }

	CPMIHandleRelease(ObjIter);
	
    return OPSEC_SESSION_END;
}


