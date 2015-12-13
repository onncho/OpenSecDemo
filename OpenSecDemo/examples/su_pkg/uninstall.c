/***************************************************************************
 *              
 * uninstall.c : Package Uninstall Sample
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
 * This uninstall sample does the following:
 * 1) Uninstalls the package.
 * 2) Updates the CP registry.
 * 3) Inserts status into install.log.
 *
 **************************************************************************/

#include <stdio.h>

#include "pkg_lib.h"

static int uninstall_the_application();

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
	if ((status = uninstall_the_application()) != PKG_STAT_OK) {
		pkg_printf(stderr,"%s: Failed to uninstall the application\n",argv[0]);
		return status;
	}

	if (!pkg_get_cpprod_util(cpprod_util)) {
		pkg_printf(stderr,"%s: Failed to get path to cpprod_util\n",argv[0]);
		EXIT_INSTALL(PKG_STAT_GEN_ERR);
	}

	sprintf(cpprod_cmd,"\"%s\" CPPROD_DelOPSECProd %s %s",
	           cpprod_util, VENDOR, PRODUCT);

	if (!execute_command(cpprod_cmd)) {
		pkg_printf(stderr,"%s: Failed to update CP registry\n",argv[0]);
		EXIT_INSTALL(PKG_STAT_GEN_ERR);
	}

	pkg_printf(stderr,"%s: Uninstall succeeded.\n Thank you for using this sample product :-)\n",argv[0]);
	
	EXIT_INSTALL(PKG_STAT_OK);
}


/*********************************************************************************
  * Uninstall:
  * In this sample the uninstall process includes removing the product file and installation directory
  *********************************************************************************/

static int uninstall_the_application()
{
	char install_dir[PKG_MAX_PATH];
	char product_full_path[PKG_MAX_PATH];

	/* get path of the product installation directory */
	if (!pkg_get_install_dir(install_dir)) {
		pkg_printf(stderr,"uninstall_the_application: Failed to get path to installation directory\n");
		return PKG_STAT_GEN_ERR;
	}
	
	/* create full path to the product file */
	sprintf(product_full_path,"%s%c%s", install_dir, SLASH_CHAR, PRODUCT_FILE_NAME);

	/* remove the product. 
	    this means (in this sample) removing the product file and installation directory  */
	if (!file_remove(product_full_path)) {
		pkg_printf(stderr,"uninstall_the_application: Failed to remove product\n");
		return PKG_STAT_FILE_ERR;
	}

	/* remove product directory */
	if (!dir_remove(install_dir)){
		pkg_printf(stderr,"uninstall_the_application: Failed to remove product directory %s\n", install_dir	);
		return PKG_STAT_FILE_ERR;
	}
	return PKG_STAT_OK;
}



