
#include <stdio.h>
#include <string.h>

#include "opsec/opsec.h"
#include "cpmi/CPMIClient/CPMIClientAPIs.h"

#include "cpmi_client.h"

/********************************
 *
 * Global definitions
 *
 ********************************/
typedef enum { TblNo, TblAll, TblSpecific } eTblTag; 

/*******************************************
 *
 * Prototypes
 *
 *******************************************/
static eOpsecHandlerRC
query_object_CB(HCPMIDB db, HCPMIRSLT ResIr, cpresult stat, cpmiopid id, void *info);

static eOpsecHandlerRC 
open_db_CB_read(HCPMIDB db, cpresult stat, cpmiopid opid, void *info);

static eTblTag 
get_my_table(HCPMIDB db, const char **my_table, const **my_query);

/*****************************************************************/
eOpsecHandlerRC print_table(OpsecSession *session)
{   
    cpresult res;
    cpmiopid id;

    res = CPMIDbOpen(session, "", eCPMI_DB_OM_READ, open_db_CB_read, NULL, &id);

    if(res != CP_S_OK) {
        fprintf(stderr, "print_table: failed to open database. Exiting ...\n");
        return OPSEC_SESSION_END;
    }

    return OPSEC_SESSION_OK;
}


/* 
 * Open DB CB
 */
static eOpsecHandlerRC 
open_db_CB_read(HCPMIDB db, cpresult stat, cpmiopid opid, void *info)
{
    HCPMITBL        Tbl=NULL;
    HCPMIITERTBL    TblIter = NULL;
    cpmiopid        id;
    cpresult rc = CP_S_OK;
    const char *my_table = NULL;
    eTblTag my_table_tag = TblNo;
    int     end_session = 1;
	
    fprintf(stderr, "open_db_CB_read: db %x, status %d, opid %d, info %x\n", db, stat, opid, info);

    /*
     * check the Call Back status.
     */
    if (CP_FAILED(stat)) {
        fprintf(stderr, "open_db_CB_read: failed to open DataBase - %s.\n", CPGetErrorMessage(stat));
        return OPSEC_SESSION_END;
    }

    /*
     * create Iterator on DB
     */
    if (CPMIDbIterTables (db, &TblIter) != CP_S_OK) {
        fprintf(stderr, "open_db_CB_read: failed to create table iterator\n");
        return OPSEC_SESSION_END;
    }

    /* 
     * iterate on all tables and print their names
     */
    my_table_tag = get_my_table(db, &my_table, NULL); 
    fprintf(stdout, "------------Tables--------------\n");
    
    while (CPMIIterTblIsDone(TblIter) == CP_S_FALSE) {
        const char *table_name = NULL;
        

        CPMIIterTblGetNext(TblIter, &Tbl);
        CPMITblGetName (Tbl, &table_name);
        fprintf(stdout, "%s\n", table_name);

        switch (my_table_tag) {
        case TblSpecific:
            if (strcmp(table_name, my_table) != 0) 
                break;
            /* else, fall through */
            
        case TblAll:
            end_session = 0;
            rc = CPMITblQueryObjects (Tbl, NULL, query_object_CB, NULL, &id);
            break;
            
        case TblNo:
            /* no more quesries on table */
            break;
        }

        CPMIHandleRelease(Tbl);
        
        if (rc != CP_S_OK) {
            end_session = 1;
            fprintf(stderr, "open_db_CB_read: Failed to query table %s.\n", table_name);
            break;
        }
        
    }    

    CPMIHandleRelease(TblIter);

    if (end_session && my_table_tag == TblSpecific)
        fprintf(stderr, "open_db_CB_read: table %s does not exists\n", my_table);
    
    return (end_session == 0 ? OPSEC_SESSION_OK : OPSEC_SESSION_END);
}


/* 
 * Query Object CB
 */
static eOpsecHandlerRC
query_object_CB(HCPMIDB db, HCPMIRSLT ResIr, cpresult stat, cpmiopid id, void *info)
{
    HCPMIITEROBJ ObjIter;
    HCPMIOBJ     Obj;
    HCPMITBL     Tbl;
    const char *table_name = NULL;
    
    /*
     * check the Call Back status.
     */
    if (CP_FAILED(stat)) {
        fprintf(stderr, "query_object_CB: failed to query - %s.\n", CPGetErrorMessage(stat));
        return OPSEC_SESSION_END;
    }

    /* geting object Iteration handle */
    if ( (stat = CPMIResultIterObj(ResIr,&ObjIter)) != CP_S_OK)	{
        fprintf(stderr, "query_object_CB: Cannot get Object iteration handle - %s\n", 
                CPGetErrorMessage(stat));
        return OPSEC_SESSION_END;
    }

    /* Is this table empty ? (meaning with no objects) */
    if (CPMIIterObjIsEmpty(ObjIter) == CP_S_OK) 	{
        fprintf(stderr, "query_object_CB: No Objects were found\n");
        CPMIHandleRelease(ObjIter);
        return OPSEC_SESSION_END;
    }
	
    while ( (CPMIIterObjIsDone(ObjIter)) != CP_S_OK ) {
        CPMIIterObjGetNext (ObjIter,&Obj);
        if (!Obj) {
            fprintf(stderr, "query_object_CB: Cannot Get Object\n");
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


/**************************************************
 *
 * Internal Functions Implementation
 *
 **************************************************/

static eTblTag get_my_table(HCPMIDB db, const char **my_table, const **my_query)
{
    OpsecSession *session = NULL;
    OpsecEnv     *env     = NULL;
    const char *conf_var = NULL;

    if (my_table == NULL)
        return TblNo;

    if (CPMIDbGetSession(db, &session) != CP_S_OK) {
        fprintf(stderr, "get_my_table: failed to get session from DB\n");
        return TblNo;
    }

    if ( (env = opsec_get_session_env(session)) == NULL) {
        fprintf(stderr, "get_my_table: failed to get env from session\n");
        return TblNo;
    }

    conf_var = opsec_get_conf(env, "table", NULL);
    if (conf_var == NULL) {
        *my_table = NULL;
        return TblNo;
    } 

    if (strcmp(conf_var, "All") == 0) {
        *my_table = NULL;
        return TblAll;
    } 

    *my_table = conf_var;
    return TblSpecific;
        
}


