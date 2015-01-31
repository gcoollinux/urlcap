/*
 * =====================================================================================
 *
 *       Filename:  urlcap.h
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2014年11月16日 12时29分54秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#ifndef URLCAP_H
#define URLCAP_H

#define ERROR_CHECK_GOTO(cond,err) \
do{ \
    if(cond) \
    { \
        fprintf(stdout,"[%s:%d]ERROR %s",__FUNCTION__,__LINE__,strerror((err))); \
        goto error; \
    } \
}while(0); \

#define ERROR_CHECK_EXIT(cond,err) \
do{ \
    if(cond) \
    { \
        fprintf(stdout,"[%s:%d]ERROR %s",__FUNCTION__,__LINE__,strerror((err))); \
        goto error; \
    } \
}while(0); \



#define M_CHECK_GOTO(cond,err) \
do{ \
    if(cond) \
    { \
        fprintf(stdout,"[%s:%d]ERROR",__FUNCTION__,__LINE__); \
        err = -1; \
        goto error; \
    } \
}while(0); \

#define M_CHECK_RETURN(cond,err) \
do{ \
    if(cond) \
    { \
        fprintf(stdout,"[%s:%d]ERROR",__FUNCTION__,__LINE__); \
        err = -1; \
        return err; \
    } \
}while(0); \

#ifdef DEBUG
#define LOG(format,...) fprintf(stdout,format,##__VA_ARGS__)
#else
#define LOG(format,...)
#endif


#define MAX_DEV_NAME_LEN 512
#define MAX_FILE_NAME_LEN 512
#define MAX_FTP_FIELD_LEN 512

#define MAX_HOSTS_LEN  2048

#define MAX_BUFFER_LEN 5120
#define CONFIG_FILENAME  "/etc/urlcap.conf"
//#define CONFIG_FILENAME  "urlcap.conf"
#define CACHE_DIR        "/tmp"
#define MAX_CACHE_FILE   6
#define MAX_CACHE_FILE_SIZE 10*1024
#define DEFAULT_DEV_NAME   "br-lan"

struct UrlcapConfig{
    char enable[MAX_FILE_NAME_LEN];
    char ftp_host[MAX_FTP_FIELD_LEN];
    char ftp_pwd[MAX_FTP_FIELD_LEN];
    char ftp_user[MAX_FTP_FIELD_LEN];
    char ftp_password[MAX_FTP_FIELD_LEN];
    char hosts[MAX_HOSTS_LEN];
    
    char city[MAX_FILE_NAME_LEN];
    char company[MAX_FILE_NAME_LEN];
    char userdefine[MAX_FILE_NAME_LEN];

    char dev[MAX_DEV_NAME_LEN];   
    long max_cache_file;
    long max_cache_file_size;
    char tmp_dir[MAX_FILE_NAME_LEN];

    char config_filename[MAX_FILE_NAME_LEN];

};

typedef enum{
    http_get = 0,
    http_post,
    http_data,
}HttpType;

#endif //URLCAP_H
