/***************************************************************************
 *              
 * pkg_lib.h : Header of the Package Sample Library
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

/* ***************************************************************************
 * This header file includes prototypes and definitions used by the different package files: 
 * verify.c install.c uninstall.c
 ****************************************************************************/



#ifndef PKG_LIB_H
#define PKG_LIB_H

#include <stdio.h>

/********************************************************
  * Product Definitions
  ********************************************************/
  
#define VENDOR "SampleCompany"
#define PRODUCT "SampleApplication"
#define VERSION "1.0"
#define SP "SP0"
#define PRODUCT_FILE_NAME "SampleApplicationPackage.tgz"


/* status definitions (duplicate of opsec.conf) */

#define PKG_STAT_OK 0
#define PKG_STAT_GEN_ERR 1
#define PKG_STAT_MEM_ERR 2
#define PKG_STAT_FILE_ERR 3
#define PKG_STAT_PRODUCT_INSTALLED 4
#define PKG_STAT_PRODUCT_NOT_INSTALLED 5

/* add boolean type */

typedef enum {PKG_FALSE , PKG_TRUE} pkg_boolean_t;

/********************************************************
  * PKG Lib APIs 
  ********************************************************/
pkg_boolean_t pkg_get_install_dir(char * path) ;
pkg_boolean_t pkg_get_cp_dir(char * path) ;
pkg_boolean_t pkg_get_cpprod_util(char * path);

/* debugging */
extern pkg_boolean_t pkg_dbg_on;
void pkg_dbg_init() ;
#define pkg_printf  if (!pkg_dbg_on); else fprintf

/* logging */
pkg_boolean_t pkg_install_log_open();
pkg_boolean_t pkg_install_log_close();
pkg_boolean_t pkg_install_log_set_status(int status);

#define EXIT_INSTALL(status) \
	pkg_install_log_set_status(status); \
	pkg_install_log_close(); \
	return status;

/********************************************************
  * OS Wrappers
  ********************************************************/

#ifdef WIN32
#define SLASH_CHAR '\\'
#else 
#define SLASH_CHAR '/'
#endif

#define PKG_MAX_PATH 512

pkg_boolean_t dir_create(const char *path);
pkg_boolean_t dir_remove(const char *path);
pkg_boolean_t file_exist(const char *path);
pkg_boolean_t copy_file_to_dir(const char *source, const char *target);
pkg_boolean_t file_remove(const char *path);

pkg_boolean_t execute_command(const char * cmd);

#endif /* PKG_LIB_H */
