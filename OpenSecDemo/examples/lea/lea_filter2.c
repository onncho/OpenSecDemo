/***************************************************************************
 *                                                                         *
 * This example program configures a LEA Client. It shows how to use the   *
 * filtering ability of the LEA protocol. Records received by the          *
 * application are printed to the output.                                  *
 *                                                                         *
 * The program works in online mode.                                       *
 * It receives logs from the fw.log and creates a filtering rulebase       *
 * so that it'll receive only relevant records. The information needed for *
 * for the rulebase definition will arrive in the dictionary handler.      *
 * After it arrives, the sample constructs the rulebase in a hierarchical  *
 * way.                                                                    *
 *																		   *
 * The communication is the simplest that can be configured.               *
 *                                                                         *
 * NOTE: this sample does not necessarily cause filtering of all log       *
 *       records in the file.                                              *
 *                                                                         *
 * The rulebase applied by this example is as follows:                     *
 * Rule 1: service belongs to {nbdatagram, nbsession} and dest belongs to  *
 *         subnet mask with network address 0.0.0.255 and subnet mask of   *
 *         0.0.0.255 (LAN broadcast) ==> drop                              *
 * Rule 2: service equals to nbname ==> pass fields "time", "i/f_name",    *
 *         "orig", "has_accounting"                                        *
 * Rule 3: proto equals to udp ==> pass                                    *
 * Rule 4: sys_msgs exists ==> pass fields "time", "i/f_name", "orig"      *
 *         "sys_msgs"                                                      *
 * Rule 5 (implied): unconditionally drop                                  *
 *                                                                         *
 ***************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "opsec/lea.h"
#include "opsec/lea_filter.h"
#include "opsec/lea_filter_ext.h"
#include "opsec/opsec.h"

#ifdef WIN32
#	include <winsock.h>
#else
#	include <netinet/in.h>
#	include <arpa/inet.h>
#endif 


/*
 * Function prototypes
 */
void                 CleanUpEnvironment(OpsecEnv *env, OpsecEntity *client, OpsecEntity *server);
int                  LeaStartHandler(OpsecSession *);
int                  LeaEndHandler(OpsecSession *);
int                  LeaRecordHandler(OpsecSession *, lea_record *, int []);
int                  LeaDictionaryHandler(OpsecSession *, int, LEA_VT, int);
int                  LeaEofHandler(OpsecSession *);
int                  LeaSwitchHandler(OpsecSession *);
int                  LeaFilterQueryAckHandler(OpsecSession *, int, eLeaFilterAction, int);
LeaFilterRulebase  * CreateOnlineRulebase();
LeaFilterRule      * CreateRule(int nRuleNum);
LeaFilterPredicate * CreateRule1Pred1();
LeaFilterPredicate * CreateRule1Pred2();
LeaFilterPredicate * CreateRule2Pred();
LeaFilterPredicate * CreateRule3Pred();
LeaFilterPredicate * CreateRule4Pred();
void                 Usage(char *szProgName);

/*
 *	Global definitions 
 */
LeaFilterRulebase *  g_pRbase           = NULL; /* global rulebase */
unsigned short       g_nSvcNbdatagram   = 0;
unsigned short       g_nSvcNbsession    = 0;
unsigned short       g_nSvcNbname       = 0;
int                  g_bFilterApplied   = 0;    /* flags if the filter has been applied already or not */
int                  g_nId;                     /* rulebase ID */
int                  g_bFilterOnServer	= 0;    /* is the filter on the server or on the client? */

/*
 * MAIN
 *
 * In this example, the LEA Client receives log records from 
 * fw.log in ONLINE mode, starting with the first record in the file.
 */
int 
main(int argc, char *argv[])
{
	OpsecEntity       *pClient    = NULL;
	OpsecEntity       *pServer    = NULL;
	OpsecSession      *pSession   = NULL;
	OpsecEnv          *pEnv       = NULL;
	int                nId        = 0;

	if (argc==1)
	{
		Usage(argv[0]);
		exit(-1);
	}

	if (!strcmp(argv[1], "client"))
	{
		g_bFilterOnServer = 0;
	}
	else if (!strcmp(argv[1], "server"))
	{
		g_bFilterOnServer = 1;
	}
	else
	{
		Usage(argv[0]);
		exit(-1);
	}

	if ((pEnv = opsec_init(OPSEC_EOL))==NULL)
	{
		printf("%s: unable to create environment\n", argv[0]);
		exit(-1);
	}

	/*
	 *  Initialize entities
	 */
	pClient = opsec_init_entity(pEnv, LEA_CLIENT,
	                            OPSEC_SESSION_START_HANDLER, LeaStartHandler,
	                            LEA_RECORD_HANDLER, LeaRecordHandler,
	                            LEA_DICT_HANDLER, LeaDictionaryHandler,
	                            LEA_EOF_HANDLER, LeaEofHandler,
	                            LEA_SWITCH_HANDLER, LeaSwitchHandler,
	                            LEA_FILTER_QUERY_ACK, (g_bFilterOnServer ? LeaFilterQueryAckHandler : NULL ), /* this handler is only needed for server filtering */
	                            OPSEC_SESSION_END_HANDLER, LeaEndHandler,
	                            OPSEC_EOL);
								
	pServer = opsec_init_entity(pEnv, LEA_SERVER, 
	                            OPSEC_ENTITY_NAME, "lea_server", 
	                            OPSEC_SERVER_IP,   inet_addr("127.0.0.1"),
	                            OPSEC_SERVER_PORT, (int)htons(18184),
	                            OPSEC_EOL);

	if ((!pClient) || (!pServer))
	{
		fprintf(stderr, "%s: failed to initialize client-server pair\n", argv[0]);
		CleanUpEnvironment(pEnv, pClient, pServer);
		exit(-1);
	}

	/*
	 *  Create session
	 */
	if(!(pSession = lea_new_session(pClient, pServer, LEA_ONLINE, LEA_FILENAME, LEA_NORMAL, LEA_AT_START)))
	{
		fprintf(stderr, "%s: failed to start reading log file\n", argv[0]);
		CleanUpEnvironment(pEnv, pClient, pServer);
		exit(-1);
	}

	opsec_mainloop(pEnv);

	/*
	 *  Free the OPSEC entities and the environment before exiting.
	 */
	CleanUpEnvironment(pEnv, pClient, pServer);

	return 0;
}

void
CleanUpEnvironment(OpsecEnv *env, OpsecEntity *client, OpsecEntity *server)
{
	if (client) opsec_destroy_entity(client);
	if (server) opsec_destroy_entity(server);
	if (env)    opsec_env_destroy(env);
}

/*
 * This event handles the start session event.
 * The start handler should be used for 
 * initializing global session parameters, etc.
 */
int LeaStartHandler(OpsecSession *pSession)
{
	printf("LeaStartHandler: start handler has been called\n");
	return OPSEC_SESSION_OK;
}

/*
 * This event handles the end session event.
 */
int LeaEndHandler(OpsecSession *pSession)
{
	printf("LeaEndHandler: end handler has been called\n");
	return OPSEC_SESSION_OK;
}

/*
 * This event handles the log record event.
 * Each log record is printed in a single line.
 * Each log field has the "field=value" format, separated by spaces.
 */
int
LeaRecordHandler(OpsecSession *pSession, lea_record *pRec, int pnAttribPerm[])
{
	int          i;
	char        *szResValue;
	char        *szAttrib; 
	lea_logdesc *pLogDesc    = lea_get_logfile_desc(pSession);

	/*
	 * Print general log record information
	 */
	printf("loc=%d filename=%s fileid=%d", 
	       lea_get_record_pos(pSession)-1,
	       (pLogDesc->filename ? pLogDesc->filename : "(null)"),
	       pLogDesc->fileid);

	/*
	 * Loop over all records fields
	 */
	for (i=0; i<pRec->n_fields; i++)
	{
		/*
		 * Print each field
		 */
		szAttrib = lea_attr_name(pSession, pRec->fields[i].lea_attr_id);		
		szResValue = lea_resolve_field(pSession, pRec->fields[i]);
		printf(" %s=%s", szAttrib, szResValue);
	}

	/*
	 * End of line
	 */
	printf("\n");	
	return OPSEC_SESSION_OK;
}

/*
 * This event handles the dictionary event.
 *
 * This function looks for all the information required in order to construct the
 * filtering rulebase is found in the dictionaries. When all the information is found,
 * the filtering rulebase is sent to the LEA server.
 *
 * The information the function looks for, is these services:
 * nbsession (TCP)
 * nbdatagram (UDP)
 * nbname (UDP)
 * 
 * Once the information is found, CreateOnlineRulebase() is called.
 */
int LeaDictionaryHandler(OpsecSession *pSession, int nDictId, LEA_VT nValType, int nEntries)
{
	lea_dict_iter *pIter;
	lea_dict_entry *pEntry;
	LeaFilterRulebase *pRbase;
	
	printf("LeaDictionaryHandler: dictionary handler has been called\n");

	/* if the filter is alrady applied, bail out now */
	if (g_bFilterApplied)
		return OPSEC_SESSION_OK;
		
	switch (nValType)
	{
	case LEA_VT_TCP_PORT:
		/* look for "nbsession" */

		/* do we have the port already? */
		if (g_nSvcNbsession!=0)
			return OPSEC_SESSION_OK;

		/* create iterator */
		if ((pIter = lea_dict_iter_create(pSession, nDictId, 0))==NULL)
		{
			fprintf(stderr, "LeaDictionaryHandler: failed to create dictionary iterator\n");
			return OPSEC_SESSION_ERR;
		}

		/* loop over all entries */
		while (pEntry = lea_dict_iter_next(pIter))
		{
			/* compare entry to "nbsession" */
			if (!strcmp(pEntry->lea_d_name, "nbsession"))
			{
				/* save port number */
				g_nSvcNbsession = pEntry->lea_d_value.ush_value;
				printf("LeaDictionaryHandler: found entry for nbsession: port # is %d", g_nSvcNbsession);
				lea_dict_iter_destroy(pIter);
				pIter = NULL;
				break;
			}
		}
		
		lea_dict_iter_destroy(pIter);
		break;
		
	case LEA_VT_UDP_PORT:
		/* look for "nbdatagram" and "nbname" */

		/* do we have the ports already? */
		if ((g_nSvcNbdatagram!=0) && (g_nSvcNbname!=0))
			return OPSEC_SESSION_OK;

		/* create iterator */
		if ((pIter = lea_dict_iter_create(pSession, nDictId, 0))==NULL)		
		{
			fprintf(stderr, "LeaDictionaryHandler: failed to create dictionary iterator\n");
			return OPSEC_SESSION_ERR;
		}

		/* loop over all entries */
		while (pEntry = lea_dict_iter_next(pIter))
		{
			/* compare entry to "nbdatagram" and "nbname" */

			/* nbdatagram */
			if (g_nSvcNbdatagram==0)
			{
				if (!strcmp(pEntry->lea_d_name, "nbdatagram"))
				{
					/* save port number */
					g_nSvcNbdatagram = pEntry->lea_d_value.ush_value;
					printf("LeaDictionaryHandler: found entry for nbdatagram: port # is %d", g_nSvcNbdatagram);
					lea_dict_iter_destroy(pIter);
					pIter = NULL;
					continue;
				}
			}

			/* nbname */
			if (g_nSvcNbname==0)
			{
				if (!strcmp(pEntry->lea_d_name, "nbname"))
				{
					/* save port number */
					g_nSvcNbname = pEntry->lea_d_value.ush_value;
					printf("LeaDictionaryHandler: found entry for nbname: port # is %d", g_nSvcNbname);
					lea_dict_iter_destroy(pIter);
					pIter = NULL;
					break;
				}
			}
		}

		if (pIter) lea_dict_iter_destroy(pIter);

		/* do we have all information for the rulebase? */
		if ((g_nSvcNbsession!=0) && (g_nSvcNbdatagram!=0) && (g_nSvcNbname!=0))
		{
			/* suspend session */
			lea_session_suspend(pSession);

			/* mark as filter applied */
			g_bFilterApplied = 1;
			
			/* build rulebae */
			if ((pRbase = CreateOnlineRulebase())==NULL)
			{
				fprintf(stderr, "LeaDictionaryHandler: online rulebase created is invalid\n");
				return OPSEC_SESSION_ERR;
			}

			return (g_bFilterOnServer ? lea_filter_rulebase_register(pSession, pRbase, &g_nId) : lea_filter_rulebase_register_local(pSession, pRbase));
		}
		
		break;
	}
	
	return OPSEC_SESSION_OK;
}


/*
 * This event handles the End Of File event.
 */
int
LeaEofHandler(OpsecSession *pSession)
{
	printf("The log file has ended\n");
	return OPSEC_SESSION_OK;
}

/*
 * This event handles the log switch event.
 */
int
LeaSwitchHandler(OpsecSession *pSession)
{
	printf("The log file has been switched\n");
	return OPSEC_SESSION_OK;
}

/*
 * This event handles the Filter Query Acknowledge event.
 * The handler is called upon the server receiving the rulebase.
 * The nResult parameter represents the status the server returned
 * for the rulebase.
 */
int
LeaFilterQueryAckHandler(OpsecSession *pSession, int nFilterId, eLeaFilterAction nAction, int nResult)
{
	printf("LeaFilterQueryAckHandler: filter id %d request of %s has returned result of %s\n",
	       nFilterId,
	       (nAction==LEA_FILTER_REGISTER ? "registration" : "unregistration"),
	       (nResult==OPSEC_SESSION_OK ? "OPSEC_SESSION_OK" : "OPSEC_SESSION_ERR") );

	lea_session_resume(pSession);

	return OPSEC_SESSION_OK;
}

/*
 * This function constructs the LEA filter rulebase,
 * then creates the rules, and adds them to the rulebase.
 */
LeaFilterRulebase *
CreateOnlineRulebase()
{
	LeaFilterRulebase *pRbase;
	LeaFilterRule *pRule;
	int i;

	/* create rulebase object */
	if ((pRbase = lea_filter_rulebase_create())==NULL)
	{
		fprintf(stderr, "CreateOnlineRulebase: failed to create rulebase object\n");
		return NULL;
	}

	/* all the rules will be created in a loop */
	for (i=0; i<4; i++)
	{
		/* create rule object */
		if ((pRule = CreateRule(i))==NULL)
		{
			fprintf(stderr, "CreateOnlineRulebase: failed to create rule %d\n", i);
			lea_filter_rulebase_destroy(pRbase);
			return NULL;
		}

		/* insert rule object into rulebase object */
		if (lea_filter_rulebase_add_rule(pRbase, pRule)!=OPSEC_SESSION_OK)
		{
			fprintf(stderr, "CreateOnlineRulebase: failed to add rule %d to rulebase\n", i);
			lea_filter_rulebase_destroy(pRbase);
			lea_filter_rule_destroy(pRule);
			return NULL;
		}

		/* decrease rules reference count */
		lea_filter_rule_destroy(pRule);
	}

	return pRbase;
}

/*
 * This function creates the rules, according to the nRuleNum parameter.
 *
 * Rule 1: service belongs to {nbdatagram, nbsession} and dest belongs to
 *         subnet mask with network address 0.0.0.255 and subnet mask of
 *         0.0.0.255 (LAN broadcast) ==> drop
 * Rule 2: service equals to nbname ==> pass fields "date", "time",
 *         "interface", "origin", "has_accounting"
 * Rule 3: proto equals to udp ==> pass
 * Rule 4: sys_msgs exists ==> pass fields "date", "time", "interface",
 *         "origin", "sys_msgs"
 * Rule 5 (implied): unconditionally drop
 */
LeaFilterRule *
CreateRule(int nRuleNum)
{
	LeaFilterRule *pRule;
	LeaFilterPredicate *pPred;
	char *pszAttrs2[] = {
		"time",
		"i/f_name",
		"orig",
		"has_accounting"
	};
	char *pszAttrs4[] = {
		"time",
		"i/f_name",
		"orig",
		"sys_msgs"
	};

	switch (nRuleNum)
	{
	case 0:
		/* rule 1 */

		/* create rule object */
		if ((pRule = lea_filter_rule_create(LEA_FILTER_ACTION_DROP))==NULL)
		{
			fprintf(stderr, "CreateRule for rule 1: failed to create rule object\n");
			return NULL;
		}

		/* create predicate 1 object */
		if ((pPred = CreateRule1Pred1())==NULL)
		{
			fprintf(stderr, "CreateRule for rule 1: failed to create predicate 1 object\n");
			lea_filter_rule_destroy(pRule);
			return NULL;
		}

		/* add predicate object to rule object */
		if (lea_filter_rule_add_predicate(pRule, pPred)!=OPSEC_SESSION_OK)
		{
			fprintf(stderr, "CreateRule for rule 1: failed to add predicate 1 to rule\n");
			lea_filter_rule_destroy(pRule);
			lea_filter_predicate_destroy(pPred);
			return NULL;
		}

		/* decrease predicate object reference count */
		lea_filter_predicate_destroy(pPred);

		/* create predicate 2 object */
		if ((pPred = CreateRule1Pred2())==NULL)
		{
			fprintf(stderr, "CreateRule for rule 1: failed to create predicate 2 object\n");
			lea_filter_rule_destroy(pRule);
			return NULL;
		}

		/* add predicate object to rule object */
		if (lea_filter_rule_add_predicate(pRule, pPred)!=OPSEC_SESSION_OK)
		{
			fprintf(stderr, "CreateRule for rule 1: failed to add predicate 2 to rule\n");
			lea_filter_rule_destroy(pRule);
			lea_filter_predicate_destroy(pPred);
			return NULL;
		}

		/* decrease predicate object reference count */
		lea_filter_predicate_destroy(pPred);

		break;

	case 1:
	case 3:
		/* rules 2, 4 */
		if ((pRule = lea_filter_rule_create(LEA_FILTER_ACTION_PASS_FIELDS, 4,
			(nRuleNum==1 ? pszAttrs2 : pszAttrs4)))==NULL)
		{
			fprintf(stderr, "CreateRule for rule %d: failed to create rule object\n", nRuleNum+1);
			return NULL;
		}
		
		/* create predicate object */
		if ((pPred = ( nRuleNum==1 ? CreateRule2Pred() : CreateRule4Pred() ))==NULL)
		{
			fprintf(stderr, "CreateRule for rule %d: failed to create predicate object\n", nRuleNum+1);
			lea_filter_rule_destroy(pRule);
			return NULL;
		}

		/* add predicate object to rule object */
		if (lea_filter_rule_add_predicate(pRule, pPred)!=OPSEC_SESSION_OK)
		{
			fprintf(stderr, "CreateRule for rule %d: failed to add predicate to rule\n", nRuleNum+1);
			lea_filter_rule_destroy(pRule);
			lea_filter_predicate_destroy(pPred);
			return NULL;
		}

		/* decrease predicate object reference count */
		lea_filter_predicate_destroy(pPred);

		break;

	case 2:
		/* rule 3 */
		if ((pRule = lea_filter_rule_create(LEA_FILTER_ACTION_PASS))==NULL)
		{
			fprintf(stderr, "CreateRUle for rule 3: failed to create rule object\n");
			return NULL;
		}

		/* create predicate object */
		if ((pPred = CreateRule3Pred())==NULL)
		{
			fprintf(stderr, "CreateRule for rule 3: failed to create predicate object\n");
			lea_filter_rule_destroy(pRule);
			return NULL;
		}

		/* add predicate object to rule object */
		if (lea_filter_rule_add_predicate(pRule, pPred)!=OPSEC_SESSION_OK)
		{
			fprintf(stderr, "CreateRule for rule 3: failed to add predicate to rule\n");
			lea_filter_rule_destroy(pRule);
			lea_filter_predicate_destroy(pPred);
			return NULL;
		}

		/* decrease predicate object reference count */
		lea_filter_predicate_destroy(pPred);

		break;
		
	default:
		fprintf(stderr, "CreateRule: invalid rule number %d specified\n", nRuleNum);
		return NULL;
	}

	return pRule;
}

/*
 * This function creates the first predicate in rule 1.
 *
 * The predicate created here, is LEA_FILTER_PRED_BELONGS_TO.
 */
LeaFilterPredicate *
CreateRule1Pred1()
{
	LeaFilterPredicate *pPred;
	lea_value_ex_t *pVal1;
	lea_value_ex_t *pVal2;
	lea_value_ex_t *ppValArr[2];

	/* create first value */
	if ((pVal1 = lea_value_ex_create())==NULL)
	{
		fprintf(stderr, "CreateRule1Pred1: failed to create first value\n");
		return NULL;
	}

	/* create second value */
	if ((pVal2 = lea_value_ex_create())==NULL)
	{
		fprintf(stderr, "CreateRule1Pred1: failed to create second value\n");
		lea_value_ex_destroy(pVal1);
		return NULL;
	}

	/* set first value */
	if (lea_value_ex_set(pVal1, LEA_VT_UDP_PORT, g_nSvcNbdatagram)!=OPSEC_SESSION_OK)
	{
		fprintf(stderr, "CreateRule1Pred1: failed to set first value\n");
		lea_value_ex_destroy(pVal1);
		lea_value_ex_destroy(pVal2);
		return NULL;
	}

	/* set second value */
	if (lea_value_ex_set(pVal2, LEA_VT_TCP_PORT, g_nSvcNbsession)!=OPSEC_SESSION_OK)
	{
		fprintf(stderr, "CreateRule1Pred1: failed to set first value\n");
		lea_value_ex_destroy(pVal1);
		lea_value_ex_destroy(pVal2);
		return NULL;
	}

	/* set value array */
	ppValArr[0] = pVal1;
	ppValArr[1] = pVal2;

	/* create predicate object */
	if ((pPred = lea_filter_predicate_create("service", -1, 0, LEA_FILTER_PRED_BELONGS_TO, 2, ppValArr))==NULL)
	{
		fprintf(stderr, "CreateRule1Pred1: failed to create predicate object\n");
		return NULL;
	}

	/* clear used data structures */
	lea_value_ex_destroy(pVal1);
	lea_value_ex_destroy(pVal2);

	return pPred;
}

/*
 * This function creates the second predicate in rule 1.
 *
 * The predicate created here, is LEA_FILTER_PRED_BELONGS_TO_MASK.
 */
LeaFilterPredicate *
CreateRule1Pred2()
{
 	return lea_filter_predicate_create("dest", -1, 0, LEA_FILTER_PRED_BELONGS_TO_MASK, inet_addr("0.0.0.255"), inet_addr("0.0.0.255"));
}

/*
 * This function creates the predicate in rule 2.
 *
 * The predicate created here, is LEA_FILTER_PRED_EQUALS.
 */
LeaFilterPredicate *
CreateRule2Pred()
{
	LeaFilterPredicate *pPred;
	lea_value_ex_t *pVal;

	/* create value */
	if ((pVal = lea_value_ex_create())==NULL)
	{
		fprintf(stderr, "CreateRule2Pred: failed to create value\n");
		return NULL;
	}

	/* set value */
	if (lea_value_ex_set(pVal, LEA_VT_UDP_PORT, g_nSvcNbname)!=OPSEC_SESSION_OK)
	{
		fprintf(stderr, "CreateRule2Pred: failed to set value\n");
		lea_value_ex_destroy(pVal);
		return NULL;
	}

	/* create predicate object */
	if ((pPred = lea_filter_predicate_create("service", -1, 0, LEA_FILTER_PRED_EQUALS, pVal))==NULL)
	{
		fprintf(stderr, "createRule2Pred: failed to create predicate object\n");
		lea_value_ex_destroy(pVal);
		return NULL;
	}

	/* free used data structures */
	lea_value_ex_destroy(pVal);
	
	return pPred;
}

/*
 * This function creates the predicate in rule 3.
 *
 * The predicate created here, is LEA_FILTER_PRED_EQUALS.
 */
LeaFilterPredicate *
CreateRule3Pred()
{
	LeaFilterPredicate *pPred;
	lea_value_ex_t *pVal;

	/* create value */
	if ((pVal = lea_value_ex_create())==NULL)
	{
		fprintf(stderr, "CreateRule3Pred: failed to create value\n");
		return NULL;
	}

	/* set value */
	if (lea_value_ex_set(pVal, LEA_VT_IP_PROTO, IPPROTO_UDP)!=OPSEC_SESSION_OK)
	{
		fprintf(stderr, "CreateRule3Pred: failed to set value\n");
		lea_value_ex_destroy(pVal);
		return NULL;
	}

	/* create predicate object */
	if ((pPred = lea_filter_predicate_create("proto", -1, 0, LEA_FILTER_PRED_EQUALS, pVal))==NULL)
	{
		fprintf(stderr, "createRule2Pred: failed to create predicate object\n");
		lea_value_ex_destroy(pVal);
		return NULL;
	}

	/* free used data structures */
	lea_value_ex_destroy(pVal);

	return pPred;
}

/*
 * This function creates the predicate in rule 4.
 *
 * The predicate created here, is LEA_FILTER_PRED_EXISTS.
 */
LeaFilterPredicate *
CreateRule4Pred()
{
	/* create predicate object */
	return lea_filter_predicate_create("sys_msgs", -1, 0, LEA_FILTER_PRED_EXISTS);
}

void
Usage(char *szProgName)
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "\t%s client|server\n");
	fprintf(stderr, "\t\"client\" specifies client-side filtering\n");
	fprintf(stderr, "\t\"server\" specifies server-side filtering\n");
}
