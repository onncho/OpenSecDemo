
##################################################################
# AMON Server Private Schema File
#
# This file is the private schema definition for the amon_server 
# sample code.
#
# This schema will be supported only after it will be imported into 
# Check Point management station.
##################################################################


START-FILE-HEADER
    FILE-TYPE, MIB-DEFINITION
    VERSION, 5.0
END-FILE-HEADER


START-BLOCK
    BLOCK-NAME,myStatus,"My Status"
    
        START-BRANCH,myFirstBranch,"My First Branch",1.7

            SIMPLE-OID,myName,"My Name",1,STRING
            SIMPLE-OID,myNumber,"My Number",2,UINT32

        END-BRANCH
END-BLOCK

