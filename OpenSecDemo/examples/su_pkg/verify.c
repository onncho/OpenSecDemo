/***************************************************************************
 *              
 * verify.c : Package Verification Sample
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
 * This verification sample checks if the application package is already installed.
 *
 **************************************************************************/
 #include <stdio.h>

#include "pkg_lib.h"

int main(int argc, char * argv[])
{
	char install_dir[PKG_MAX_PATH];
	
	/* init debug */
	pkg_dbg_init();

	if (!	pkg_get_install_dir(install_dir)){
		pkg_printf(stderr, "%s: Failed to get path to installation directory.\n", argv[0]);
		return PKG_STAT_GEN_ERR;
	}
	/* Check if the product directory already exists 
	     this indicates (in this sample) that the product is already installed */
	if (file_exist(install_dir)) {
		pkg_printf(stderr, "%s: Verification failed. Product already exists.\n", argv[0]);
		return PKG_STAT_PRODUCT_INSTALLED;
	}
	pkg_printf(stderr, "%s: Verification succeeded. Ready for installation.\n", argv[0] );
	return PKG_STAT_OK;
}
