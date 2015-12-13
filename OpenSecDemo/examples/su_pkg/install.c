/***************************************************************************
 *              
 * install.c : Package Install Sample
 *                                                                         
 * This is a part of the Check Point OPSEC SDK                             
 * Copyright (c) 1994-2003 Check Point Software Technologies, Ltd.         
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
 *
 * This installation sample does the following:
 * 1) Installs the package.
 * 2) Updates the CP registry.
 * 3) Inserts status into install.log.
 *
 **************************************************************************/
#include <stdio.h>

#include "pkg_lib.h"

static int install_the_application(); 

int main(int argc, char * argv[])
{
	char cpprod_util[PKG_MAX_PATH];
	char cpprod_cmd[512];
	int status = PKG_STAT_OK;

	/* init debug */
	pkg_dbg_init();
	
	/* prepare install.log */
	if (!pkg_install_log_open()) {
		pkg_printf(stderr,"%s: Failed to open install log\n",argv[0]);
		return PKG_STAT_FILE_ERR;
	}

	if ((status = install_the_application()) != PKG_STAT_OK) {
		pkg_printf(stderr,"%s: Failed to install the application\n",argv[0]);
		return status;
	}

	/* 
	  * update the CP registry 
	  */

	/* get full path to cpprod utility for updating the CP registry */
	if (!pkg_get_cpprod_util(cpprod_util)) {
		pkg_printf(stderr,"%s: Failed to get path to cpprod_util\n",argv[0]);
		EXIT_INSTALL(PKG_STAT_GEN_ERR);
	}

	/* create the full cpprod command */
	sprintf(cpprod_cmd,"\"%s\" CPPROD_SetOPSECProd %s %s %s %s Sample",
	           cpprod_util, VENDOR, PRODUCT, VERSION, SP);

	if (!execute_command(cpprod_cmd)) {
		pkg_printf(stderr,"%s: Failed to update CP registry\n",argv[0]);
		EXIT_INSTALL(PKG_STAT_GEN_ERR);
	}

	pkg_printf(stderr,"%s: Installation succeeded\n",argv[0]);

	EXIT_INSTALL(PKG_STAT_OK);
}


/*****************************************************************
  * Installation:
  * In this sample the installation includes creating the installation directory
  * and copying the product file (SampleApplicationPackage.tgz) to that directory. 
  *****************************************************************/
static int install_the_application() 
{
	char install_dir[PKG_MAX_PATH];
	
	/* get path of the product installation directory */
	if (!pkg_get_install_dir(install_dir)) {
		pkg_printf(stderr,"install_the_application: Failed to get path to installation directory\n");
		return PKG_STAT_GEN_ERR;
	}

	/* create the product installation directory.
	     it is assumed that pkg_verify already checked that  this directory does not exist */
	
	if (!dir_create(install_dir)) {
		pkg_printf(stderr,"install_the_application: Failed to create %s\n",  install_dir);
		return PKG_STAT_FILE_ERR;
	}

	/* copy application to the product directory 
	     it is assumed that install_dir is a directory*/
	     
	if (!copy_file_to_dir(PRODUCT_FILE_NAME, install_dir)) {
		pkg_printf(stderr,"install_the_application: Failed to copy product to installation directory\n");
		return PKG_STAT_FILE_ERR;
	}
	return PKG_STAT_OK;
}


