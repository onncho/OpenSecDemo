/***************************************************************************
 *              
 * pkg_lib.c : Implementation of the Package Sample Library
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
 * This file includes package utilities and OS wrappers
 ****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkg_lib.h"


#ifdef WIN32
/* Syncronize with Unix standards. */
#include <io.h> /* for _access */
#include <direct.h> /* for _mkdir */
#include <windows.h> /* for RemoveDirectory */

#define access _access
#define unlink _unlink

#define popen  _popen
#define pclose _pclose
#else
#include <sys/stat.h> /* for S_IRWXU */
#endif

#ifdef WIN32
#define ROOT_DIR "c:"
#define EXE_SUFFIX  ".exe"
#else 
#define ROOT_DIR "/opt"
#define EXE_SUFFIX  ""
#endif


/********************************************************
  * PKG Lib APIs 
  ********************************************************/

pkg_boolean_t pkg_get_install_dir(char * path) 
{
	if(!path) {
		pkg_printf(stderr,"pkg_get_install_dir: NULL path\n");
		return PKG_FALSE;
	}
	sprintf(path,"%s%c%s",ROOT_DIR,SLASH_CHAR,PRODUCT);
	return PKG_TRUE;
}

pkg_boolean_t pkg_get_cp_dir(char * path) 
{
	static char* cp_dir = NULL;
	if(!path) {
		pkg_printf(stderr,"pkg_get_cp_dir: NULL path\n");
		return PKG_FALSE;
	}

	if (!cp_dir) {
		if (!(cp_dir = getenv("CPDIR"))) {
			pkg_printf(stderr,"pkg_get_cp_dir: failed to get CPDIR environment variable\n");
			return PKG_FALSE;
		}
	}

	sprintf(path,"%s",cp_dir);
	return PKG_TRUE;
}

pkg_boolean_t pkg_get_cpprod_util(char * path) {
	char cp_dir[PKG_MAX_PATH];
	if(!path) {
		pkg_printf(stderr,"pkg_get_cpprod_util: NULL path\n");
		return PKG_FALSE;
	}
	if (!pkg_get_cp_dir(cp_dir)) {
		pkg_printf(stderr,"pkg_get_cpprod_util: failed to get CPDIR\n");
		return PKG_FALSE;
	}
	sprintf(path,"%s%cbin%ccpprod_util%s", cp_dir, SLASH_CHAR, SLASH_CHAR,EXE_SUFFIX);
	return PKG_TRUE;
}

/* debugging */

pkg_boolean_t pkg_dbg_on = PKG_FALSE;

void pkg_dbg_init() {
	char * dbg_level = NULL;
	if (dbg_level = getenv("SU_DEBUG_LEVEL")) {
		if (!strcmp(dbg_level,"2")) {
			pkg_dbg_on = PKG_TRUE;	
		}
	}
}

/* logging with install.log */

static FILE * install_log_fp = NULL;

pkg_boolean_t pkg_install_log_open() {
	char cp_dir[PKG_MAX_PATH];
	char install_log_path[PKG_MAX_PATH];
	
	if (!pkg_get_cp_dir(cp_dir)) {
		pkg_printf(stderr,"pkg_install_log_open: failed to get CPDIR path\n");
		return PKG_FALSE;
	}

	sprintf(install_log_path,"%s%ctmp%cinstall.log",cp_dir,SLASH_CHAR,SLASH_CHAR);
	
	if( (install_log_fp = fopen( install_log_path, "w" )) == NULL ) {
		pkg_printf(stderr,"pkg_install_log_open: failed to open %s for writing\n",install_log_path);
		return PKG_FALSE;
	}
	return PKG_TRUE;
}

pkg_boolean_t pkg_install_log_close() {

	if (!install_log_fp) {
		return PKG_TRUE;
	}
	if (fclose(install_log_fp)) {
		pkg_printf(stderr,"Failed to close install log\n");		
		return PKG_FALSE;
	}
	install_log_fp = NULL;
	return PKG_TRUE;
}

pkg_boolean_t pkg_install_log_set_status(int status) {
	char status_str[32];
	sprintf(status_str,"status=%d\n",status);
	if (fputs( status_str, install_log_fp ) == EOF) {
		pkg_printf(stderr,"Failed to write to install log\n");				
		return PKG_FALSE;
	}
	return PKG_TRUE;
}


/********************************************************
  * OS Wrappers
  ********************************************************/

pkg_boolean_t file_exist(const char *path)
{
	if (path == NULL)
		return PKG_FALSE;
	if (access(path, 0))
		return PKG_FALSE;
	return PKG_TRUE;
}

pkg_boolean_t dir_create(const char *path)
{
#ifndef WIN32
	mode_t mode = S_IRWXU;
#endif

	if (path == NULL)
		return PKG_FALSE;

#ifdef WIN32
	if (_mkdir(path))
#else
	if (mkdir(path, mode))
#endif
		return PKG_FALSE;

	return PKG_TRUE;
}

pkg_boolean_t dir_remove(const char *path)
{
	if (path == NULL)
		return PKG_FALSE;

#ifdef WIN32
	if(!RemoveDirectory(path))
#else
	if (rmdir(path))
#endif
		return PKG_FALSE;

	return PKG_TRUE;
}

pkg_boolean_t copy_file_to_dir(const char *source_file_name, const char *target_path)
{
#define IO_BLOCK_SIZE  4096

	unsigned int n_read = 0;
	char block[IO_BLOCK_SIZE];
	char full_target[PKG_MAX_PATH];
	pkg_boolean_t result = PKG_TRUE;
	FILE *source_fp=NULL;
	FILE *target_fp=NULL;

	if (source_file_name == NULL || target_path == NULL)
		return PKG_FALSE;

	/* file_name is assumed to be without path 
	    target_path is assumed to be a directory */

	/* Open the source file for reading. */
	if ((source_fp = fopen(source_file_name, "rb")) == NULL) {
		pkg_printf(stderr,"copy_file_to_dir: failed to open %s for reading\n", source_file_name);
		return PKG_FALSE;
	}

	/* Calculate the exact target path.  */
	sprintf(full_target, "%s%c%s", target_path, SLASH_CHAR, source_file_name);

	/* Create the target file. */
	if ((target_fp = fopen(full_target, "wb+")) == NULL) {
		pkg_printf(stderr,"copy_file_to_dir: failed to open %s for writing\n",full_target);
		fclose(source_fp);
		return PKG_FALSE;
	}

	/* Read and write one block at a time */
	while ((n_read = fread(block, 1, IO_BLOCK_SIZE, source_fp)) > 0) {
		if((fwrite(block, 1, n_read, target_fp)) < n_read) {
			pkg_printf(stderr,"copy_file_to_dir: failed to write to %s\n",full_target);
			result = PKG_FALSE;
		}
	}
	
	fclose(source_fp);
	fclose(target_fp);
	
	return result;
}

pkg_boolean_t file_remove(const char *path)
{
  if (path == NULL)
    return PKG_FALSE;

  if (unlink(path))
    return PKG_FALSE;

  return PKG_TRUE;
}

pkg_boolean_t execute_command(const char * cmd)
{
    FILE * pout = popen((char *) cmd, "r");
    int result;

    if (pout == NULL) {
    	pkg_printf(stderr,"execute_command: popen failed\n");
	return PKG_FALSE;
    }

    result = pclose(pout);
    if(result == -1)
    	pkg_printf(stderr, "execute_command: pclose failed\n");
    
    return PKG_TRUE;
}


