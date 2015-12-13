
#ifndef CPMI_CLIENT_UTIL_H
#define CPMI_CLIENT_UTIL_H

#include "../include/cpmi/CPMIClient/CPMIClientAPIs.h"
#include "../include/opsec/opsec.h"

eOpsecHandlerRC print_table(OpsecSession *session);

eOpsecHandlerRC get_status(OpsecSession *session);

eOpsecHandlerRC get_notification(OpsecSession *session);

eOpsecHandlerRC create_plain_host(OpsecSession *session);

eOpsecHandlerRC delete_plain_host(OpsecSession *session);

void print_obj(HCPMIOBJ Obj, long width);



#endif /* CPMI_CLIENT_UTIL_H */
