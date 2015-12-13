
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "opsec/opsec.h"
#include "cpmi/CPMIClient/CPMIClientAPIs.h"

#include "cpmi_client.h"

/*******************************************
 *
 * CPMI Client Call-Back Functions
 *
 *******************************************/
static eOpsecHandlerRC
notify_CB(HCPMIDB db, HCPMINOTIFYMSG msg, cpresult stat, cpmiopid opid, void *info);

static eOpsecHandlerRC 
open_db_CB_notification(HCPMIDB db, cpresult stat, cpmiopid opid, void *info);

/*************************************************************************************/
eOpsecHandlerRC get_notification(OpsecSession *session)
{
    cpresult res;
    cpmiopid id;

    res = CPMIDbOpen(session, "", eCPMI_DB_OM_READ, open_db_CB_notification, NULL, &id);
    
    if(res != CP_S_OK) {
        fprintf(stderr, "get_notification: failed to open database. Exiting ...\n");
        return OPSEC_SESSION_END;
    }

    return OPSEC_SESSION_OK;
}

/* 
 * Open DB CB
 */
static eOpsecHandlerRC 
open_db_CB_notification(HCPMIDB db, cpresult stat, cpmiopid opid, void *info)
{
    HCPMITBL        Tbl=NULL;
    cpmiopid        id;
    cpresult rc = CP_S_OK;
    unsigned int events = 0, flags = 0;
	
    fprintf(stderr, "open_db_CB_notification: db %x, status %d, opid %d, info %x\n", db, stat, opid, info);

    /*
     * check the Call Back status.
     */
    if (CP_FAILED(stat)) {
        fprintf(stderr, "open_db_CB_notification: failed to open DataBase - %s.\n", CPGetErrorMessage(stat));
        return OPSEC_SESSION_END;
    }

    /* register on all events */
    events = 
        eCPMI_NOTIFY_DELETE | 
        eCPMI_NOTIFY_UPDATE |
        eCPMI_NOTIFY_RENAME |
        eCPMI_NOTIFY_CREATE ;

    rc = CPMIDbRegisterEvent(db, NULL, NULL, events, flags, notify_CB, info, &id);
    
    return (rc == CP_S_OK ? OPSEC_SESSION_OK : OPSEC_SESSION_END);
}


struct event2str {
    tCPMI_NOTIFY_EVENT event;
    const char *str;
} event2str_tbl [] = {
        {eCPMI_NOTIFY_DELETE,   "DELETE" },
        {eCPMI_NOTIFY_UPDATE,   "UPDATE" }, 
        {eCPMI_NOTIFY_RENAME,   "RENAME" },
        {eCPMI_NOTIFY_CREATE,   "CREATE" },
        {eCPMI_NOTIFY_STATUS_CHANGE, "STATUS CHANGE"},
        { 0, "<NULL>"}
};
static const char *get_event_str(tCPMI_NOTIFY_EVENT event)
{
    int i;

    for (i = 0; event2str_tbl[i].event != 0; i++)
        if (event2str_tbl[i].event == event)
            return event2str_tbl[i].str;

    return event2str_tbl[i].str;    
}


/* 
 * Query Object CB
 */
static eOpsecHandlerRC
notify_CB(HCPMIDB db, HCPMINOTIFYMSG msg, cpresult stat, cpmiopid opid, void *info)  
{
    tCPMI_NOTIFY_EVENT event;
    const char *host = NULL;
    const char *user = NULL;
    const char *tbl_name = NULL;
    const char *obj_name = NULL;    
    time_t time;
    static int registration_ack = 0;
    
    /*
     * check the Call Back status.
     */
    if (CP_FAILED(stat)) {
        fprintf(stderr, "notify_CB: failed to get notification - %s.\n", CPGetErrorMessage(stat));
        return OPSEC_SESSION_END;
    }

    /*
     * the first time the callback is called is Acknowledge on the registration
     */
    if (msg == NULL && !registration_ack) {
        fprintf(stderr, "notify_CB: Registration Acknowledged\n");  
        registration_ack++;
        return OPSEC_SESSION_OK;
    }
            
    if (CPMINotifyGetEvent(msg, &event)         != CP_S_OK ||
        CPMINotifyGetModifierHost(msg, &host)   != CP_S_OK ||
        CPMINotifyGetModifierUser(msg, &user)   != CP_S_OK ||
        CPMINotifyGetTime(msg, &time)           != CP_S_OK ||
        CPMINotifyGetTblName(msg, &tbl_name)     != CP_S_OK ||
        CPMINotifyGetObjName(msg, &obj_name)     != CP_S_OK) {

        fprintf(stderr, "notify_CB: Failed to get notification data\n");
        return OPSEC_SESSION_END;
    } 

    fprintf(stdout, "\a\a\a\a\a\a\a\a\a\a\n");
    fprintf(stdout, "\nTable: %s  Object: %s was Modified:\n", 
            tbl_name ? tbl_name : "<NULL>", obj_name ? obj_name : "<NULL>");
	// added for ctime_s
	char str[26];
    fprintf(stdout, "    Time: %s", ctime_s(str,sizeof str, &time)); 
    fprintf(stdout, "    Event: %s\n", get_event_str(event));
    fprintf(stdout, "    Host: %s, User: %s\n", host ? host : "<NULL>", user ? user : "<NULL>");
    
    return OPSEC_SESSION_OK;
}



