/***************************************************************************
 *                                                                        
 * csa_sample.c : A Sample OPSEC CSA application
 *                                                                        
 * This is a part of the Check Point OPSEC SDK       
 * Copyright (c) 1994-2005 Check Point Software Technologies, Ltd.         
 * All rights reserved.                                                    
 *                                                                         
 * This source code is only intended as a supplement to the                
 * Check Point OPSEC SDK and related documentation provided with the SDK   
 * and shall be used in accordance with the standard                       
 * End-User License Agreement.                                             
 * See related documentation for detailed information                      
 * regarding the Check Point OPSEC SDK.                    
 *                                                                         
 ***************************************************************************/
/***************************************************************************

 This CSA sample demonstrated basic use of CSA APIs.
 It perfroms the following operations:
 - Gets cluster configuration and state of the local member
 - Registers for notifications on changes of the cluster configuration and state
 - Registers a device for influencing the cluster state

 Note:
 - This CSA application can run only on ClusterXL module
 - The reg_stat command does not work on Windows
 
 **************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifndef WIN32
#include <signal.h>
#endif

#include "opsec/opsec.h"
#include "opsec/csa.h"

#define CSA_SAMPLE_NAME "csa_sample"
#define CSA_SAMPLE_DEV_NAME "csa_dev"

static int csa_sample_register_dev()
{
    if (csa_pnote_register(CSA_SAMPLE_DEV_NAME, 0 /* indefinite timeout*/, CSA_PNOTE_OK) != 0) {
        printf("csa_sample_register_dev: failed to register device\n");
        return -1;
    }
    return 0;
}

static int csa_sample_set_dev_stat(int stat)
{
    if (csa_pnote_report(CSA_SAMPLE_DEV_NAME, stat) != 0) {
        printf("csa_sample_set_dev_stat: failed to set state\n");
        return -1;
    }
    return 0;
}

static int csa_sample_unregister_dev()
{
    if (csa_pnote_unregister(CSA_SAMPLE_DEV_NAME) != 0){
        printf("csa_sample_unregister_dev: failed to unregister device\n");
        return -1;
    }
    return 0;
}

static int csa_sample_get()
{
	csa_member_info_ptr_t member_inf_ptr; 
	unsigned int member_inf_size;
	unsigned int number_members;
	unsigned int id,local_id;
	unsigned int i;
	unsigned int status;
	
	if (csa_get_member_info_size(&member_inf_size) !=0) {
		printf("csa_sample_get: failed to get member info size\n");
		return -1;
	}
	member_inf_ptr = (csa_member_info_ptr_t) calloc(member_inf_size,1);
	if (!member_inf_ptr) {
		printf("csa_sample_get: failed to allocate memory\n");
		return -1;
	}
	if (csa_get_cluster_size(&number_members) != 0) {
		printf("csa_sample_get: failed to get number of members\n");
		free(member_inf_ptr);
		return -1;
	}
	printf("The number of members is: %d\n",number_members);
	if (csa_get_my_id( &local_id ) != 0) {
		printf("csa_sample_get: failed to get my id\n");
		free(member_inf_ptr);
		return -1;
	}
	for (i=1 ; i <= number_members ; i++) {
		if (csa_get_member_info(i, member_inf_ptr) != 0) {
			printf("csa_sample_get: cxl_get_member_info failed\n");
			free(member_inf_ptr);
			return -1;
		}
		if (csa_get_id_from_member_info(member_inf_ptr ,&id ) != 0) {
			printf("csa_sample_get: failed to get id from member info\n");
			free(member_inf_ptr);
			return -1;
	        }
		if(id!=local_id){
			continue;
		}
	        if (csa_get_status_from_member_info(member_inf_ptr, &status) != 0) {
			printf("csa_sample_get: failed to get member status\n");
			free(member_inf_ptr);
			return -1;
	        }
	        printf("The status of the local member is: ");
	        switch (status){
	            case CSA_MEMBER_STOPPED:
	                printf("Stopped\n");
	                break;
	            case CSA_MEMBER_DOWN:
	                printf("Down\n");
	                break;
	            case CSA_MEMBER_STANDBY:
	                printf("Standby\n");
	                break;
	            case CSA_MEMBER_ACTIVE:
	                printf("Active\n");
	                break;
	            default:
	                printf("Unknown (%d)\n", status);
	        }
	}
	free(member_inf_ptr);
	return 0;
}




#ifndef WIN32

void csa_sample_signal_handler(int sig)
{
	fprintf(stdout,"csa_sample_signal_handler: called\n");
	csa_sample_get();
	fprintf(stdout,"Waiting for status updates\n"
	                      "Press enter to exit\n");
}

static int csa_sample_register_stat()
{
	int 	pid;
	int 	counter = 0;
	char c;	
	
	pid = (int)getpid();

	signal(SIGUSR1, csa_sample_signal_handler);

	/* First unregister to make sure there are no left-overs from a previous run */ 
	if (csa_unregister_status_updates(CSA_SAMPLE_NAME) != 0) {
		printf("Process is not registered for status yet\n");
	}
	if (csa_register_status_updates(CSA_SAMPLE_NAME, pid, SIGUSR1) != 0) {
		printf("csa_sample_register_stat: failed to register\n");
		return -1;
	}
	printf("Process is now registered\n");
	fprintf(stdout,"Waiting for status updates\n"
	                      "Press enter to exit\n");
	getchar();

	if (csa_unregister_status_updates(CSA_SAMPLE_NAME) != 0) {
		printf("csa_sample_register_stat: failed to unregister\n");
		return -1;
	}

	return 0;
}

#endif

static void set_stat_usage()
{
	fprintf(stdout,"\n"
				"USAGE:\n"
	                     "set_stat <ok|nok>\n"
	                     "ARGUMENTS:\n"
	                     "ok - device is OK\n"
	                     "nok - device has problem\n"
	                     "\n\n");
}

static void usage()
{
	fprintf(stdout,"\n"
				"USAGE:\n"
	                     "csa_client <subcommand>\n"
	                     "SUBCOMMANDS:\n"
	                     "get_stat - get cluster information\n"
#ifndef WIN32
	                     "reg_stat - register for status updates\n"
#endif
	                     "reg_dev - register device\n"
	                     "set_stat - set device state\n"
	                     "unreg_dev - unregister device\n"
	                     "\n\n");
}

int 
main(int argc, char *argv[])
{
	/* Initialize OPSEC 
	 * This will enable OPSEC debug output (and use of other OPSEC APIs)
	*/
	OpsecEnv *env = opsec_init(OPSEC_EOL); 

	if(!env){
		fprintf(stderr,"csa_sample: failed to create OPSEC environment\n");
		opsec_env_destroy(env);
		exit(1);
	}
	if(argc<2) {
		usage();
		opsec_env_destroy(env);
		exit(1);
	}
	if(!strcmp(argv[1],"get_stat")) {
		csa_sample_get();
	}
#ifndef WIN32
	else if (!strcmp(argv[1],"reg_stat")) {
		csa_sample_register_stat();	
	}
#endif
	else if (!strcmp(argv[1],"reg_dev")) {
		csa_sample_register_dev();	
	}
	else if (!strcmp(argv[1],"set_stat")) {
		int stat;
		if(argc<3){
			set_stat_usage();
			opsec_env_destroy(env);
			exit(1);
		}
		if(!strcmp(argv[2],"ok")) {
			stat = CSA_PNOTE_OK;
		}
		else if (!strcmp(argv[2],"nok")) {
			stat = CSA_PNOTE_PROBLEM;
		}
		else {
			fprintf(stderr,"csa_sample: invalid argument %s\n",argv[2]);
			set_stat_usage();
			opsec_env_destroy(env);
			exit(1);
		}
		csa_sample_set_dev_stat(stat);	
	}
	else if (!strcmp(argv[1],"unreg_dev")) {
		csa_sample_unregister_dev();	
	}
	else {
		fprintf(stderr,"csa_sample: invalid subcommand %s\n",argv[1]);
		usage();
		opsec_env_destroy(env);
		exit(1);
	}
	opsec_env_destroy(env);
	return 0;
}
