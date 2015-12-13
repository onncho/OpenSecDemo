/***************************************************************************
 *                                                                         *
 * sam_client.c : A Sample OPSEC SAM Client                                *
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

 Note that this SAM Client communicates with SAM Server in clear. The FW-1/VPN-1
 SAM Server listens on authenticated port by default. For the SAM Client to
 communicate with the SAM Server replace the following lines from 
 FWDIR/conf/fwopsec.conf (note that this setting is only for testing and debugging)

 # sam_server auth_port 18183
 # sam_server      port     0

 with the lines

 sam_server auth_port     0
 sam_server      port 18183

 and restart the firewall.

 This SAM client get its parameter through the command line.
 When the session established it perform the action or monitor request
 with its parameters.
 
 **************************************************************************/

#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#ifdef WIN32
#include <winsock.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#include "opsec/sam.h"
#include "opsec/opsec.h"
#include "opsec/opsec_error.h"

#define SAM_SERVER_IP	"127.0.0.1"
#define SAM_PORT 	18183

typedef enum {HandlerType_MonitorAck, HandlerType_Ack } eHandlerType;

char *ALL = "All";
char msg[4096] = {0};

/*****************************************************************
 * SAM Command
 *****************************************************************/
struct SamCommand {
    int action;
    int log;
    char *fw_object;
    int expiration;
    int mode;
    int src, src_mask, dst, dst_mask, service, ip_proto;
    int is_monitor;
};

struct SamCommand g_command;

static void SamCommandInit(struct SamCommand *command)
{
    command->action     = 0;
    command->log        = SAM_LONG_NOALERT;
    command->fw_object  = ALL;
    command->expiration = SAM_EXPIRE_NEVER;
    command->mode       = -1;

    command->src        = 0;
    command->src_mask   = 0;
    command->dst        = 0;
    command->dst_mask   = 0;
    command->service    = 0;
    command->ip_proto   = 0;
    command->is_monitor = 0;
}

/*****************************************************************
 * SAM Modes
 *****************************************************************/
struct _SamMode {
    char *name;
    int   n_args;
    int   designator;
} SamModeTable [] = {
    "src",      1, SAM_SRC_IP,
    "dst",      1, SAM_DST_IP,
    "any",      1, SAM_ANY_IP,
    "subsrc",   2, SAM_SUB_SRC_IP,
    "subdst",   2, SAM_SUB_DST_IP,
    "subany",   2, SAM_SUB_ANY_IP,    
    "srv",      4, SAM_SERV,
    "subsrv",   6, SAM_SUB_SERV,
    "subsrvs",  5, SAM_SUB_SERV_SRC,
    "subsrvd",  5, SAM_SUB_SERV_DST,
    "dstsrv",   3, SAM_DST_SERV,
    "subdstsrv",4, SAM_SUB_DST_SERV,
    "srcpr",    2, SAM_SRC_IP_PROTO,
    "dstpr",    2, SAM_DST_IP_PROTO,
    "subsrcpr", 3, SAM_SUB_SRC_IP_PROTO,
    "subdstpr", 3, SAM_SUB_DST_IP_PROTO,
    "all",      0, SAM_ALL,
    NULL,       0, 0 
};


static int SamModeByStr(char *arg)
{
    int i;
    
    for (i = 0; SamModeTable[i].name != NULL; i++)
        if (strcmp(arg, SamModeTable[i].name) == 0)
            return i;

    return -1;    
}

static int SamModeByInt(int arg)
{
    int i;
    
    for (i = 0; SamModeTable[i].name != NULL; i++)
        if (arg == SamModeTable[i].designator)
            return i;

    return -1;    
}

/*****************************************************************
 * SAM Actions
 *****************************************************************/
struct _SamAction {
    char *action_str;
    int  action ;
} SamActionsTable [] = {
    "reject",               SAM_REJECT | SAM_INHIBIT,
    "notify",               SAM_NOTIFY,
    "inhibit",              SAM_INHIBIT,
    "inhibit_close",        SAM_INHIBIT_AND_CLOSE,
    "inhibit_drop",         SAM_INHIBIT_DROP,
    "drop",                 SAM_INHIBIT_DROP,
    "inhibit_drop_close",   SAM_INHIBIT_DROP_AND_CLOSE,
    NULL,                   -1
};

static int SamActionsByStr(char *str)
{
    int i;
    
    for (i = 0; SamActionsTable[i].action_str != NULL; i++)
        if (strcmp(str, SamActionsTable[i].action_str) == 0)
            return SamActionsTable[i].action;

    return -1;    
}

static char *SamActionsByInt(int action)
{
    int i;
    
    for (i = 0; SamActionsTable[i].action_str != NULL; i++)
        if (action == SamActionsTable[i].action)
            return SamActionsTable[i].action_str;

    return NULL;    
}

static int SamMonitorAction(char *action_str)
{
    int action = 0, rc = 0;
    char *tok = NULL;

    for( tok = strtok(action_str, ",") ; tok != NULL; tok = strtok(NULL, ",") ) {
        if ( (action = SamActionsByStr(tok)) < 0) 
            return -1;
        rc |= action;
    }
    return rc;
}

/*****************************************************************
 * SAM Log
 *****************************************************************/
struct _SamLog {
    char *log_str;
    int   log;
} SamLogsTable [] = {
    "nolog",           SAM_NOLOG,
    "log_noalert",     SAM_LONG_NOALERT,
    "log_alert",       SAM_LONG_ALERT,
    NULL,               -1
};
    

static int SamLogbByStr(char *log_str)
{
    int i;
    
    for (i = 0; SamLogsTable[i].log_str != NULL; i++)
        if (strcmp(log_str, SamLogsTable[i].log_str) == 0)
            return SamLogsTable[i].log;

    return -1;    
}

static char *SamLogbByInt(int log)
{
    int i;
    
    for (i = 0; SamLogsTable[i].log_str != NULL; i++)
        if (log == SamLogsTable[i].log)
            return SamLogsTable[i].log_str;

    return NULL;    
}

/*****************************************************************/
static void
Usage()
{
    fprintf(stderr,	"Usage:\n");

    fprintf(stderr, "\t[-t timeout] [-l log] [-f fw-object] [-C] <-A action> <criteria>\n\n"); 
    fprintf(stderr, "\t[-f fw-host] -M < All | <<<reject>,drop>,notify> > <criteria>\n\n"); 
    /* for example: -M "reject,drop,notify", or -M "drop,notify" */
    fprintf(stderr,	"\t[-f fw-host] -D\n");

    fprintf(stderr, "\t[-t timeout] - timeout for the command in seconds\n");
    fprintf(stderr, "\t[-l log] - where log is one of: nolog, log_noalert, log_alert\n");    
    fprintf(stderr, "\t[-f fw-object] - where fw-object is firewalled object\n");
        
    fprintf(stderr,	"-C -  cancel\n");
    fprintf(stderr,	"-D -  delete all\n");

    fprintf(stderr,	"\n-A - Action(one of):\n");
    fprintf(stderr,	"notify | inhibit | inhibit_close | inhibit_drop | inhibit_drop_close\n");

    fprintf(stderr,	"\n-M - Monitor\n");
    fprintf(stderr,	"\"all\" or one or more (comma separated list ) of notify,reject,drop\n");
    	
    fprintf(stderr, "\ncriteria may be one of:\n");
    fprintf(stderr, "src <ip>\n");
    fprintf(stderr, "dst <ip>\n");
    fprintf(stderr, "any <ip>\n");

    fprintf(stderr, "subsrc <src-ip> <net mask>\n");
    fprintf(stderr, "subdst <dst-ip> <net-mask>\n");
    fprintf(stderr, "subany <ip> <net-mask>\n");

    fprintf(stderr, "srv <src-ip> <dst-ip> <service> <protocol>\n");

    fprintf(stderr, "subsrv <src-ip> <net-mask> <dst-ip> <net-mask> <service> <protocol>\n"); 

    fprintf(stderr, "subsrvs <src-ip> <net-mask> <dst-ip> <service> <protocol>\n");

    fprintf(stderr, "subsrvd <src-ip> <dst-ip> <net-mask> <service> <protocol>\n");

    fprintf(stderr, "dstsrv <dst-ip> <service> <protocol>\n");

    fprintf(stderr, "subdstsrv <dst-ip> <net-mask> <service> <protocol>\n");

    fprintf(stderr, "srcpr <src-ip> <protocol>\n");
    fprintf(stderr, "dstpr <dst-ip> <protocol>\n");

    fprintf(stderr, "subsrcpr <src-ip> <net mask> <protocol>\n");
    fprintf(stderr, "subdstpr <dst-ip> <net mask> <protocol>\n");
    exit(1);
}


/*****************************************************************
 * Some utilites fuctions
 *****************************************************************/

static char *ip2str(int ip)
{
    char *ip_str = NULL;
    struct in_addr ipaddr;

    ipaddr.s_addr = ip;
    ip_str = inet_ntoa(ipaddr);
    if (ip_str)
        return strdup(ip_str);

    return "NULL";
}

static char *time2str(time_t time)
{
    char *time_str = NULL; 
    int len; 

    if (time == 0) 
        time_str = strdup("NEVER");
	else {
        time_str = strdup(ctime(&time));
        len = strlen(time_str);
        time_str[len - 1] = '\0';	/* avoid printing a new line */
    }
	
    return time_str;
}

static void 
print_info_table(opsec_table info_data)
{
    opsec_table_iterator iter;
    opsec_vtype vtype;
    void *elem = NULL;

    unsigned short service, proto;
    char *src = NULL, *src_mask = NULL, *dst = NULL, *dst_mask = NULL;
    char *log = NULL, *action = NULL, *time = NULL;

    int i, nentries;

    nentries = sam_table_get_nrows( info_data);

    if (!nentries){
        fprintf(stderr, "no corresponding SAM requests\n");
        return;
    }
    
    else { /* prepare a table header */
        fprintf(stdout, "\n%-16s %-16s %-16s %-16s %-10s %-10s %-15s %-12s %-25s\n",
                "source ip", "netmask", "destination ip", "netmask", "service", "protocol", "log", 
                "action", "expiration");
    }
    /* create iterator on table */
    iter = sam_table_iterator_create( info_data);

    for (i = 0; i < nentries ; i++ ) {

        elem = sam_table_iterator_next(iter, &vtype);
        src = ip2str(*((unsigned int*)elem));
        
        elem = sam_table_iterator_next(iter, &vtype);
        src_mask= ip2str(*((unsigned int*)elem));

        elem = sam_table_iterator_next(iter, &vtype);
        dst = ip2str(*((unsigned int*)elem));
        
        elem = sam_table_iterator_next(iter, &vtype);
        dst_mask= ip2str(*((unsigned int*)elem));

        elem = sam_table_iterator_next(iter, &vtype);
        service = (*((unsigned short*)elem));

        elem = sam_table_iterator_next(iter, &vtype);
        proto = *((unsigned short*)elem);

        elem = sam_table_iterator_next(iter, &vtype);
        log = SamLogbByInt(*((int*)elem));

        elem = sam_table_iterator_next(iter, &vtype);
        action = SamActionsByInt(*((int*)elem));

        elem = sam_table_iterator_next(iter, &vtype);
        time = time2str(*((time_t*)elem)); 

        fprintf(stdout, "%-16s %-16s %-16s %-16s %-10d %-10d %-15s %-12s %-25s\n",
            src, src_mask, dst, dst_mask, service, proto, log, action, time);

#define FREE(_x) if (_x) free(_x)

        FREE(src);
        FREE(src_mask);
        FREE(dst);
        FREE(dst_mask);
        FREE(time);
    }
        
	sam_table_iterator_destroy(iter);
	fprintf(stdout, "\n");		
}


static eOpsecHandlerRC
print_status_message(eHandlerType type, int closed, int status, int fw_index, 
                     int fw_total, char *fw_host, void *cb_data)
{

    switch (status) {
    case SAM_REQUEST_RECEIVED:
        fprintf(stderr, "request for '%s' acknowledged\n", (char *)cb_data);
        break;

    case SAM_MODULE_DONE:
        fprintf(stderr, "%s (%d/%d) successfully completed '%s' processing. (closed %d)\n",
                fw_host, fw_index+1, fw_total, (char *)cb_data, closed);
        break;					

    case SAM_MODULE_FAILED:
        fprintf(stderr, "%s (%d/%d) failed '%s' processing\n",
                fw_host, fw_index+1, fw_total, (char *)cb_data);
        break;

    case SAM_REQUEST_DONE:
        fprintf(stderr, "request for '%s' done\n", (char *)cb_data);
        return OPSEC_SESSION_END;

    case SAM_RESOLVE_ERR:
        if (fw_index==-1) /* resolve error for the whole request */
            fprintf(stderr, "Could not resolve firewalled object name in '%s'. The entire SAM request was not enforced.\n", 
        (char *)cb_data);
        else /* resolve error for a single target */
            fprintf(stderr, "%s (%d/%d)  failed to resolve firewalled object name for '%s'. The SAM request was not processed on this module.\n",
                    fw_host, fw_index+1, fw_total, (char *)cb_data);
            free(cb_data);

        return OPSEC_SESSION_END;

    case SAM_UNEXPECTED_END_OF_SESSION:
        fprintf(stderr, "Unexpected end of session. It is possible that the SAM monitoring request for '%s' was not performed.\n",
                (char *)cb_data);
        free(cb_data);
        return OPSEC_SESSION_END;

    default:
        fprintf(stderr, "unexpected status '%d'\n",	status);
        return OPSEC_SESSION_ERR;
    }
    
    return OPSEC_SESSION_OK;
}


static void parse_criteria(struct SamCommand *command, int *_index, int ac, char *av[])
{
#define STRCAT(_buf, _msg1, _msg2) \
    strcat(_buf, _msg1); \
    strcat(_buf, _msg2)

    int mode_index;
    int args;
    int index = *_index;

    if (index >= ac)
        Usage();
    
    if ( (mode_index = SamModeByStr(av[index++])) < 0 )
        Usage();

    command->mode = SamModeTable[mode_index].designator;
    strcat(msg, SamModeTable[mode_index].name);
    
    if ( ((args = SamModeTable[mode_index].n_args) + index) != ac) {       /* number of arguments is wrong*/
        fprintf(stderr, "parse_criteria: arguments mismatch for filter %s\n", SamModeTable[mode_index].name);
        Usage();
    }
/* might consider argument validity checks here - for example if the argument order is incorrect or invalid subnet mask, invalid ip etc. */
    if (command->mode == SAM_ALL && !command->is_monitor) {
        fprintf(stderr, "parse_criteria: can not use SAM_ALL when the command is not monitor\n");
        Usage();
    }
    
    if (command->mode & SAM_SRC_IP || command->mode & SAM_ANY_IP) {
        command->src = inet_addr(av[index]);
        STRCAT(msg, " src-ip ", av[index++]);  

        if (command->mode & SAM_SMASK) {
            command->src_mask = inet_addr(av[index]);
            STRCAT(msg, " src-mask ", av[index++]);  
        }
    }
    
    if (command->mode & SAM_DST_IP) {
        command->dst = inet_addr(av[index]);
        STRCAT(msg, " dst-ip ", av[index++]);  
        
        if (command->mode & SAM_DMASK) {
            command->dst_mask = inet_addr(av[index]);
            STRCAT(msg, " dst-mask ", av[index++]);  
        }
    }
    
    if (command->mode & SAM_DPORT) {
        command->service = atoi(av[index]);
        STRCAT(msg, " service ", av[index++]);  
    }

    if (command->mode & SAM_PROTO) {
        command->ip_proto = atoi(av[index]);
        STRCAT(msg, " ip-proto ", av[index++]);  
    }

    *_index = index;
}

        
static void parse_command_line(struct SamCommand *command, int ac, char *av[])
{			
    int i;

    if (ac < 2)
        Usage();

    for (i = 1; i < ac; i++) {
        if (av[i][0] != '-')
            break;
            
        switch (av[i][1]) {
		
    	case 't':
            if ( i+1 >= ac) Usage(); else i++;
		    command->expiration = (int)atoi( av[i] );
		    break;

        case 'l':
            if ( i+1 >= ac) Usage(); else i++;
            if ( (command->log = SamLogbByStr(av[i]) ) < 0)
                Usage();
            break;

        case 'f':
            if ( i+1 >= ac) Usage(); else i++;
            command->fw_object = av[i];
        	break;

        case 'A':
            if ( i+1 >= ac) Usage(); else i++;
            if ( (command->action |= SamActionsByStr(av[i++])) < 0) {
                fprintf(stderr, "parse_command_line: Invalid action (%s)\n", av[i-1] ); 
                Usage();
            }
            strcat(msg, av[i-1]);
            strcat(msg, " ");
            parse_criteria(command, &i, ac, av);
            break;

        case 'C':
            command->action |= SAM_CANCEL;
            strcat(msg, "Cancel: ");  
            break;


        case 'D':
            if (command->action || ac > 4) 
                Usage();
            command->action = SAM_DELETE_ALL;
            strcat(msg, "Delete All ");
            break;
			
        case 'M':
            strcat(msg, "Monitoring: ");
            command->is_monitor = 1;
            if ( i+1 >= ac) Usage(); else i++;
            if (strcmp("all", av[i])) {
                strcat(msg, av[i]); strcat(msg, " ");
                if ( (command->action = SamMonitorAction(av[i++])) < 0) {
                    fprintf(stderr, "parse_command_line: Invalid monitor action (%s)\n", av[i-1] ); 
                    Usage();
                }
            }           
            parse_criteria(command, &i, ac, av);
            break;

        default:
            Usage();
        }
    }

    strcat(msg, " On ");
    strcat(msg, command->fw_object);

    if (!command->action && !command->is_monitor)
        Usage();
}

/******************************************************************
 * we give here two options to build sam command:
 * 1. execute_sam_command
 * 2. alternate_execute_sam_command
 *
 * both alternatives are valid.
 ******************************************************************/   


static eOpsecHandlerRC execute_sam_command(OpsecSession *session)
{
    eOpsecHandlerRC rc = OPSEC_SESSION_OK;
    struct SamCommand *cmd = &g_command;

    if (cmd->mode == SAM_ALL && cmd->is_monitor) 
        return sam_client_monitor(session, cmd->action, cmd->fw_object, msg, SAM_REQ_TYPE, SAM_ALL, NULL);

    if (cmd->action == SAM_DELETE_ALL)
        sam_client_action(session, cmd->action, cmd->log, cmd->fw_object, msg, NULL);
    
    switch (cmd->mode) {
    case SAM_DST_IP:
        cmd->src = cmd->dst;
    case SAM_SRC_IP:    
    case SAM_ANY_IP:
        if (cmd->is_monitor) 
            rc = sam_client_monitor(session, cmd->action, cmd->fw_object, msg, 
                                    SAM_REQ_TYPE, cmd->mode, cmd->src, NULL);
        else
            rc = sam_client_action(session, cmd->action, cmd->log, cmd->fw_object, msg, 
                                   SAM_EXPIRE, cmd->expiration, 
                                   SAM_REQ_TYPE, cmd->mode, 
                                   cmd->src, NULL);
        break;

    case SAM_SUB_DST_IP:    
        cmd->src = cmd->dst;
        cmd->src_mask = cmd->dst_mask;
    case SAM_SUB_SRC_IP:
    case SAM_SUB_ANY_IP: 
        if (cmd->is_monitor) 
            rc = sam_client_monitor(session, cmd->action, cmd->fw_object, msg, 
                                    SAM_REQ_TYPE, cmd->mode, 
                                    cmd->src, cmd->src_mask,
                                    NULL);
        else
            rc = sam_client_action(session, cmd->action, cmd->log, cmd->fw_object, msg, 
                                   SAM_EXPIRE, cmd->expiration, 
                                   SAM_REQ_TYPE, cmd->mode, 
                                   cmd->src, cmd->src_mask,
                                   NULL);
        break;
        
    case SAM_SERV:
        if (cmd->is_monitor) 
            rc = sam_client_monitor(session, cmd->action, cmd->fw_object, msg, 
                                    SAM_REQ_TYPE, cmd->mode, 
                                    cmd->src, 
                                    cmd->dst, 
                                    cmd->service, cmd->ip_proto, 
                                    NULL);
        else
            rc = sam_client_action(session, cmd->action, cmd->log, cmd->fw_object, msg, 
                                   SAM_EXPIRE, cmd->expiration, 
                                   SAM_REQ_TYPE, cmd->mode, 
                                   cmd->src, 
                                   cmd->dst, 
                                   cmd->service, cmd->ip_proto, 
                                   NULL);
        break;
        
    case SAM_SUB_SERV:
        if (cmd->is_monitor) 
            rc = sam_client_monitor(session, cmd->action, cmd->fw_object, msg, 
                                    SAM_REQ_TYPE, cmd->mode, 
                                    cmd->src, cmd->src_mask,
                                    cmd->dst, cmd->dst_mask,
                                    cmd->service, cmd->ip_proto, 
                                    NULL);
        else
            rc = sam_client_action(session, cmd->action, cmd->log, cmd->fw_object, msg, 
                                   SAM_EXPIRE, cmd->expiration, 
                                   SAM_REQ_TYPE, cmd->mode, 
                                   cmd->src, cmd->src_mask,
                                   cmd->dst, cmd->dst_mask,
                                   cmd->service, cmd->ip_proto, 
                                   NULL);
        break;
        
    case SAM_SUB_SERV_SRC:
        if (cmd->is_monitor) 
            rc = sam_client_monitor(session, cmd->action, cmd->fw_object, msg, 
                                    SAM_REQ_TYPE, cmd->mode, 
                                    cmd->src, cmd->src_mask,
                                    cmd->dst, 
                                    cmd->service, cmd->ip_proto, 
                                    NULL);
        else
            rc = sam_client_action(session, cmd->action, cmd->log, cmd->fw_object, msg, 
                                   SAM_EXPIRE, cmd->expiration, 
                                   SAM_REQ_TYPE, cmd->mode, 
                                   cmd->src, cmd->src_mask,
                                   cmd->dst, 
                                   cmd->service, cmd->ip_proto, 
                                   NULL);
        break;
        
    case SAM_SUB_SERV_DST:
        if (cmd->is_monitor) 
            rc = sam_client_monitor(session, cmd->action, cmd->fw_object, msg, 
                                    SAM_REQ_TYPE, cmd->mode, 
                                    cmd->src, 
                                    cmd->dst, cmd->dst_mask,
                                    cmd->service, cmd->ip_proto, 
                                    NULL);
        else
            rc = sam_client_action(session, cmd->action, cmd->log, cmd->fw_object, msg, 
                                   SAM_EXPIRE, cmd->expiration, 
                                   SAM_REQ_TYPE, cmd->mode, 
                                   cmd->src, 
                                   cmd->dst, cmd->dst_mask,
                                   cmd->service, cmd->ip_proto, 
                                   NULL);
        break;
        
    case SAM_DST_SERV:
        if (cmd->is_monitor) 
            rc = sam_client_monitor(session, cmd->action, cmd->fw_object, msg, 
                                    SAM_REQ_TYPE, cmd->mode, 
                                    cmd->dst,
                                    cmd->service, cmd->ip_proto, 
                                    NULL);
        else
            rc = sam_client_action(session, cmd->action, cmd->log, cmd->fw_object, msg, 
                                   SAM_EXPIRE, cmd->expiration, 
                                   SAM_REQ_TYPE, cmd->mode, 
                                   cmd->dst, 
                                   cmd->service, cmd->ip_proto, 
                                   NULL);
        break;
    case SAM_SUB_DST_SERV:
        if (cmd->is_monitor) 
            rc = sam_client_monitor(session, cmd->action, cmd->fw_object, msg, 
                                    SAM_REQ_TYPE, cmd->mode, 
                                    cmd->dst, cmd->dst_mask,
                                    cmd->service, cmd->ip_proto, 
                                    NULL);
        else
            rc = sam_client_action(session, cmd->action, cmd->log, cmd->fw_object, msg, 
                                   SAM_EXPIRE, cmd->expiration, 
                                   SAM_REQ_TYPE, cmd->mode, 
                                   cmd->dst, cmd->dst_mask,
                                   cmd->service, cmd->ip_proto, 
                                   NULL);
        break;
    case SAM_DST_IP_PROTO:
        cmd->src = cmd->dst;
    case SAM_SRC_IP_PROTO:
        if (cmd->is_monitor) 
            rc = sam_client_monitor(session, cmd->action, cmd->fw_object, msg, 
                                    SAM_REQ_TYPE, cmd->mode, 
                                    cmd->src, 
                                    cmd->ip_proto, 
                                    NULL);
        else
            rc = sam_client_action(session, cmd->action, cmd->log, cmd->fw_object, msg, 
                                   SAM_EXPIRE, cmd->expiration, 
                                   SAM_REQ_TYPE, cmd->mode, 
                                   cmd->src, 
                                   cmd->ip_proto, 
                                   NULL);
        break;
        
    case SAM_SUB_DST_IP_PROTO:
        cmd->src = cmd->dst;
        cmd->src_mask = cmd->dst_mask;
    case SAM_SUB_SRC_IP_PROTO:
        if (cmd->is_monitor) 
            rc = sam_client_monitor(session, cmd->action, cmd->fw_object, msg, 
                                    SAM_REQ_TYPE, cmd->mode, 
                                    cmd->src, cmd->src_mask,
                                    cmd->ip_proto, 
                                    NULL);
        else
            rc = sam_client_action(session, cmd->action, cmd->log, cmd->fw_object, msg, 
                                   SAM_EXPIRE, cmd->expiration, 
                                   SAM_REQ_TYPE, cmd->mode, 
                                   cmd->src, cmd->src_mask,
                                   cmd->ip_proto, 
                                   NULL);
        break;
        
    default:
        fprintf(stderr, "Can not execute command : mode %d is unknown\n", cmd->mode);
        rc = OPSEC_SESSION_OK;
        break;
    }

    return rc;        
}


static eOpsecHandlerRC alternate_execute_sam_command(OpsecSession *session)
{
    eOpsecHandlerRC rc = OPSEC_SESSION_OK;
    struct SamCommand *cmd = &g_command;
    int arg1 = 0,
        arg2 = 0,
        arg3 = 0,
        arg4 = 0,
        arg5 = 0,
        arg6 = 0;

    int req_typ = SAM_REQ_TYPE;

    if (cmd->action == SAM_DELETE_ALL)
    	req_typ = 0;
    
    switch (cmd->mode) {
    case SAM_DST_IP:
        arg1 = cmd->dst; 
        break;
    case SAM_SRC_IP:    
    case SAM_ANY_IP:
    	 arg1 = cmd->src;
        break;
    case SAM_SUB_DST_IP:    
        arg1 = cmd->dst;
        arg2 = cmd->dst_mask;
        break;
    case SAM_SUB_SRC_IP:
    case SAM_SUB_ANY_IP: 
        arg1 = cmd->src;
        arg2 = cmd->src_mask;
        break;
    case SAM_SERV:
        arg1 = cmd->src;
        arg2 = cmd->dst; 
        arg3 = cmd->service;
        arg4 = cmd->ip_proto; 
        break;
    case SAM_SUB_SERV:
        arg1 = cmd->src;
        arg2 = cmd->src_mask;
        arg3 = cmd->dst;
        arg4 = cmd->dst_mask;
        arg5 = cmd->service;
        arg6 = cmd->ip_proto;
        break;
    case SAM_SUB_SERV_SRC:
        arg1 = cmd->src;
        arg2 = cmd->src_mask;
        arg3 = cmd->dst;
        arg4 = cmd->service;
        arg5 = cmd->ip_proto;
        break;
    case SAM_SUB_SERV_DST:
        arg1 = cmd->src;
        arg2 = cmd->dst;
        arg3 = cmd->dst_mask;
        arg4 = cmd->service;
        arg5 = cmd->ip_proto;
        break;
    case SAM_DST_SERV:
        arg1 = cmd->dst;
	 arg2 = cmd->service;
	 arg3 = cmd->ip_proto;
        break;
    case SAM_SUB_DST_SERV:
        arg1 = cmd->dst;
        arg2 = cmd->dst_mask;
	 arg3 = cmd->service;
	 arg4 = cmd->ip_proto;
        break;
    case SAM_DST_IP_PROTO:
        arg1 = cmd->dst;
        arg2 = cmd->ip_proto;
        break;
    case SAM_SRC_IP_PROTO:
    	 arg1 = cmd->src;
    	 arg2 = cmd->ip_proto;
        break;
    case SAM_SUB_DST_IP_PROTO:
        arg1 = cmd->dst;
        arg2 = cmd->dst_mask;
        arg3 = cmd->ip_proto;
        break;
    case SAM_SUB_SRC_IP_PROTO:
        arg1 = cmd->src;
        arg2 = cmd->src_mask;
        arg3 = cmd->ip_proto;
        break;
    default:
        fprintf(stderr, "Can not execute command : mode %d is unknown\n", cmd->mode);
        rc = OPSEC_SESSION_OK;
        return rc;
    }
    if (cmd->is_monitor) 
            rc = sam_client_monitor(session, cmd->action, cmd->fw_object, msg, 
                                    req_typ, cmd->mode, 
                                    arg1, arg2, arg3, arg4, arg5, arg6, 
                                    NULL);
    else
            rc = sam_client_action(session, cmd->action, cmd->log, cmd->fw_object, msg, 
                                   SAM_EXPIRE, cmd->expiration, 
                                    req_typ, cmd->mode, 
                                    arg1, arg2, arg3, arg4, arg5, arg6, 
                                   NULL);

    return rc;        
}

/**********************************************
 *
 * OPSEC Handlers
 *
 **********************************************/

static eOpsecHandlerRC
SamClientStartHandler( OpsecSession *session )
{
    fprintf(stderr, "Start Handler ...\n");
    return OPSEC_SESSION_OK;
}


static void
SamClientEndHandler( OpsecSession *session )
{
    fprintf(stderr, "End Handler ...\n");
}


static eOpsecHandlerRC 
SamClientEstablishedHandler(OpsecSession *session)
{
    fprintf(stderr, "Established Handler ...\n");
    
    return execute_sam_command(session);
}


static eOpsecHandlerRC
AckEventHandler(OpsecSession *session, int closed, int status,
                int fw_index, int fw_total, char *fw_host, void *data)
{
    fprintf(stderr, "Ack Handler ...\n");
    
    return print_status_message(HandlerType_Ack, closed, status, fw_index, fw_total, fw_host, (char *)data);
}


static eOpsecHandlerRC
MonitorAckEventHandler(OpsecSession *session, int status, int fw_index, int fw_total, 
                       char *fw_host, void *cb_data, opsec_table info_data)
{
    eOpsecHandlerRC rc;
    
    fprintf(stderr, "Monitor Ack Handler ...\n");
    
    rc = print_status_message(HandlerType_MonitorAck, 0, status, fw_index, fw_total, fw_host, (char *)cb_data);

    if (rc == OPSEC_SESSION_OK && status == SAM_MODULE_DONE)
        print_info_table(info_data);

    return rc;
}

/**********************************************
 *
 * Main
 *
 **********************************************/
int main(int argc, char *argv[])
{
	OpsecEnv *env;
	OpsecEntity *server;
	OpsecEntity *client;
	OpsecSession *session;
	

	SamCommandInit(&g_command);

	parse_command_line(&g_command, argc, argv);

	env = opsec_init(/* OPSEC_CONF_FILE, "sam.conf", */ 
	                 OPSEC_CONF_ARGV, &argc, argv, 
	                 OPSEC_EOL);

	if (env == NULL) {
		fprintf(stderr, "Opsec init failed.\n");
		exit(1);
	}

	client = opsec_init_entity(
	            env, SAM_CLIENT,
				OPSEC_SESSION_START_HANDLER,       SamClientStartHandler,
				OPSEC_SESSION_END_HANDLER,         SamClientEndHandler,
				OPSEC_SESSION_ESTABLISHED_HANDLER, SamClientEstablishedHandler,
				SAM_ACK_HANDLER,                   AckEventHandler,
				SAM_MONITOR_ACK_HANDLER,           MonitorAckEventHandler,
				OPSEC_EOL);
	
	if (client == NULL) {
		fprintf(stderr, "Client entity initialization failed.\n");
		exit(1);
	}

	server = opsec_init_entity(
	            env, SAM_SERVER,
				OPSEC_ENTITY_NAME, "sam_server",
				OPSEC_SERVER_IP, inet_addr(SAM_SERVER_IP), 
				OPSEC_SERVER_PORT, htons(SAM_PORT),
				OPSEC_EOL);
	
	if (server == NULL) {
		fprintf(stderr, "Server entity initialization failed.\n");
		exit(1);
	}

	session = sam_new_session(client, server);

	if (session == NULL) {
		fprintf(stderr, "SAM session initialization failed: %s\n", opsec_errno_str( opsec_errno ));
		exit(1);
	}

	opsec_mainloop(env);

	opsec_destroy_entity(client);
	opsec_destroy_entity(server);
	opsec_env_destroy(env);

	return 0;
}


