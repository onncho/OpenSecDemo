
#include <stdio.h>
#include <time.h>

#include "cpmi/CPMIClient/CPMIClientAPIs.h"
#include "cpmi_client.h"


static void print_field(HCPMIOBJ Obj, HCPMIFLD Fld, long width);

static void print_field_value(tCPMI_FIELD_VALUE *Val, long width);

static void print_elements(HCPMICNTR hCntr, long width);

static void print_ordered_elements(HCPMIORDERCNTR OrdCntr, long width);



#define PRINT_SPACE(_n) \
{ \
    int _x; \
    for (_x = 0; _x < _n; _x++) \
        fprintf(stdout, " "); \
}

enum { INT64_SIGNED, INT64_UNSIGNED };

static char *
print_int64(opsec_int64 int64, int type)
{
    static char buf[128];
    buf[0] = '\0';
    
#ifdef WIN32
#define INT64_FORMAT "%I64"
#else
#define INT64_FORMAT "%ll"
#endif

    switch (type) {
    case INT64_SIGNED:
        sprintf_s(buf, INT64_FORMAT"d", int64);
        break;
    case INT64_UNSIGNED:
        sprintf_s(buf, INT64_FORMAT"u", int64);
        break;  
    default:
        break;
    }
    return buf;
}


void print_obj(HCPMIOBJ Obj, long width)
{
    HCPMIITERFLD  FldIter;
    HCPMIFLD      Fld;
    HCPMICLASS    Class;
    const char   *str = NULL; 
    const char   *str2 = NULL;
    time_t        Time;
    
    CPMIObjGetName (Obj, &str);

    PRINT_SPACE(width);
    fprintf(stdout, "%s\n", str && *str ? str : "Empty Object Name");

    CPMIObjGetLastModifier(Obj, &str);
    CPMIObjGetLastModificationTime(Obj, &Time);
    CPMIObjGetLastModifierHost(Obj, &str2);

    PRINT_SPACE(width);
	char str3[26];
    fprintf(stdout, "Last Modifier:%s ; Last Modifier Host:%s ; Last Modification Time:%s\n",
            str, str2, Time ? ctime_s(str3, sizeof str3, &Time) : "<No Time>");

    /*
     * parse the object schema, get object's fields and print them
     */
    if (CPMIObjGetClass (Obj, &Class) != CP_S_OK) {
        fprintf(stderr, "print_obj: Cannot get object class");
        return;
    }

    /* retrieving Field iteration handle from the Class handle */
    if (CPMIClassIterFields (Class,&FldIter) != CP_S_OK) {
        fprintf(stderr, "print_obj: Cannot get field iteratation handle\n");
        CPMIHandleRelease(Class);
        return;
    }

    /* iteration loop over the fields */
    while (CPMIIterFldIsDone(FldIter) != CP_S_OK ) {
        CPMIIterFldGetNext (FldIter,&Fld);

	    if (!Fld) {
            fprintf(stderr, "print_obj: Cannot get Field handle\n.");
            break;
        }

        print_field(Obj,Fld, width+2);

        CPMIHandleRelease(Fld);
	}

	CPMIHandleRelease(FldIter);
	CPMIHandleRelease(Class);
}
	
    
static void print_field(HCPMIOBJ Obj, HCPMIFLD Fld, long width)
{
    cpresult                res;
    tCPMI_FIELD_VALUE       Val;
    const char             *FldName = NULL;
    const char             *FldValidValues = NULL;

    CPMIFldGetName (Fld, &FldName);

    PRINT_SPACE(width);
    fprintf(stdout, "%s = ", FldName);

    res = CPMIObjGetFieldValue (Obj, Fld, &Val);

    if( CP_FAILED(res) || (Val.fvt == eCPMI_FVT_UNDEFINED)) {
        fprintf(stdout, "< no value >\n");
    } else 
        print_field_value(&Val, width+2);
    
    CPMIReleaseFieldValue(&Val);
}



static void print_field_value(tCPMI_FIELD_VALUE *Val, long width)
{
    switch (Val->fvt)	{
	case eCPMI_FVT_OBJ:     /* owned object */

        if (!(Val->objFv)) 	{	
            fprintf(stdout, "<Empty owned Object>\n");
            break;
        }

        fprintf(stdout, "owned Object\n");
        print_obj(Val->objFv, width+2);
        break;


    case eCPMI_FVT_CNTR:    /* container of elements */        
        fprintf(stdout, "<Container>\n");

        /* get elements iteration handle  */	
        print_elements(Val->cntrFv, width+2);
        break;

    /* container of ordered elements */
    case eCPMI_FVT_ORDERED_CNTR:
        printf("<Ordered Container>\n");

        print_ordered_elements(Val->ordcntrFv, width+2);
        break;

    /* reference to another object - print its name */
    case eCPMI_FVT_REF:
    {
        const char *ObjName=NULL;
        
        if (Val->refFv) {
            if (CPMIRefGetObjectName (Val->refFv, &ObjName) != CP_S_OK) {
                fprintf(stderr, "print_field_value: Cannot get the reference object name for this field\n");
                break;
            }

            PRINT_SPACE(width);
            fprintf(stdout, "%s  (Referenced object)\n", ObjName ? ObjName : "(no name)");
        } else {
            PRINT_SPACE(width);
            fprintf(stdout, "empty  (ref object)\n");
        }
		break;
    }
    
    /* string */
    case eCPMI_FVT_CTSTR:
        fprintf(stdout, "%s\n",(Val->ctstrFv) ? (Val->ctstrFv) : "no value found\n");
        break;

    /* number  */
    case eCPMI_FVT_NUM:
        fprintf(stdout, "%d\n", Val->nFv);
        break;

    /* unsigned number  */
    case eCPMI_FVT_U_NUM:
        fprintf(stdout, "%u\n", Val->unFv);
        break;

    /* boolean */
    case eCPMI_FVT_BOOL:
        fprintf(stdout, "%s\n", (Val->bFv) ? "True" : "False");
        break;

   /* int 64 */  
    case eCPMI_FVT_NUM64:
        fprintf(stdout, "%s\n", print_int64(Val->n64Fv, INT64_SIGNED));
        break;
        
   /* int 64 */  
    case eCPMI_FVT_U_NUM64:
        fprintf(stdout, "%s\n", print_int64(Val->un64Fv, INT64_UNSIGNED));
        break;
        
	default:
        fprintf(stdout, "Unknown Type\n");
    }

}


static void print_elements(HCPMICNTR hCntr, long width)
{
    tCPMI_FIELD_VALUE     Val;
    HCPMIITERCNTR         ElmIter;

    if (CPMICntrIterElements (hCntr,&ElmIter) != CP_S_OK) {
        fprintf(stderr, "print_elements: Cannot get elements Iteration handle\n");
        return;
    }

    /* is this container empty ? */
    if (CPMIIterCntrIsEmpty(ElmIter) == CP_S_OK) {

        PRINT_SPACE(width);
        fprintf(stdout, "No elements available\n");
        CPMIHandleRelease(ElmIter);
        return;
    }

    /* Elements iteration main-loop */
    while ( (CPMIIterCntrIsDone(ElmIter)) != CP_S_OK ) {	
        if (CPMIIterCntrGetNext(ElmIter, &Val) != CP_S_OK) {
            fprintf(stderr, "print_elements: Cannot get the next element of the container .\n");
            CPMIHandleRelease(ElmIter);
            return;
        }
        
        print_field_value(&Val, width+2);
        CPMIReleaseFieldValue(&Val);
    }
    
    CPMIHandleRelease(ElmIter);	
}


static void print_ordered_elements(HCPMIORDERCNTR OrdCntr, long width)
{
    tCPMI_FIELD_VALUE    Val;
    HCPMIITERORDCNTR     OrdElmIter;   

    if (CPMIOrderCntrIterElements (OrdCntr,&OrdElmIter) != CP_S_OK) {
        fprintf(stderr, "print_ordered_elements: Cannot get ordederd elements Iteration handle\n");
        return;
    }		

    if (CPMIIterOrdCntrIsEmpty(OrdElmIter) == CP_S_OK) {
        PRINT_SPACE(width);
        fprintf(stdout, "No elements available\n");
        CPMIHandleRelease(OrdElmIter);
        return;
    }

    /* Elements iteration main-loop */
    while ( (CPMIIterOrdCntrIsDone(OrdElmIter)) != CP_S_OK ) {
        if (CPMIIterOrdCntrGetNext(OrdElmIter,&Val) != CP_S_OK) {
            fprintf(stderr, "print_ordered_elements: Cannot get the next element of an ordered container .\n");
            CPMIHandleRelease(OrdElmIter);
            break;
        }

        print_field_value(&Val, width+2);
        CPMIReleaseFieldValue(&Val);		
    }
    
    CPMIHandleRelease(OrdElmIter);
}



