/*
 * =====================================================================================
 *
 *       Filename:  config.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2014年11月17日 20时07分30秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "config.h"
#include "urlcap.h"

typedef enum{
    oBadOption,
    oEnable,
    oFtpHost,
    oFtpPwd,
    oFtpUser,
    oFtpPassword,
    oHosts,
    oInterface,
    oCity,
    oCompany,
    oUserDefine
}OpCodes;

struct{
    char *name;
    OpCodes opcode;
}urlcap_keywords[]={
    {"enable",oEnable},
    {"ftp_host",oFtpHost},
    {"ftp_pwd",oFtpPwd},
    {"ftp_user",oFtpUser},
    {"ftp_password",oFtpPassword},
    {"hosts",oHosts},
    {"interface",oInterface},
    {"city",oCity},
    {"company",oCompany },
    {"userdefine",oUserDefine},
    {NULL,oBadOption},
};

extern struct UrlcapConfig urlcap_config;

static OpCodes parse_token(char *key)
{
   int i = 0;
   int ret = 0;
   for(i=0;urlcap_keywords[i].name;i++)
   {
       ret = strcasecmp(urlcap_keywords[i].name,key);
       if(0 == ret)
       {
            return urlcap_keywords[i].opcode;
       }
   }
   return oBadOption;
   
}

void init_config(void)
{
    strncpy(urlcap_config.config_filename,CONFIG_FILENAME,MAX_FILE_NAME_LEN);
    urlcap_config.max_cache_file = MAX_CACHE_FILE;
    urlcap_config.max_cache_file_size = MAX_CACHE_FILE_SIZE;
    strncpy(urlcap_config.tmp_dir,CACHE_DIR,MAX_FILE_NAME_LEN);
    strcpy(urlcap_config.ftp_host,"127.0.0.1");
    strcpy(urlcap_config.ftp_pwd,"/");
    strcpy(urlcap_config.ftp_user,"admin");
    strcpy(urlcap_config.ftp_password,"admin");
    strcpy(urlcap_config.dev,DEFAULT_DEV_NAME); 
}

int read_config(void)
{
   int err = 0;
   char *filename = NULL;
   char *buffer = NULL;
   FILE *fd = NULL;
   char *p1;
   char *p2;
   int len;
   OpCodes opcode;

   buffer = (char*)malloc(MAX_BUFFER_LEN);
   if(!buffer)
   {
        fprintf(stderr,"alloc failed\n");
        err = -1;
        goto error;
   }
   filename = urlcap_config.config_filename;
   fd =  fopen(filename,"r");
   if(fd==NULL)
   {
       err = -1;
       goto error;
   }
   while(!feof(fd)&&fgets(buffer,MAX_BUFFER_LEN-1,fd))
   {
       p1 = strchr(buffer,'=');
       if(!p1)
       {
           continue;
       }
       p1[0] = '\0';
       p2 = p1+1; //value
       len = strlen(p2);
       if(len>=1&&(p2[len-1] == '\r'||p2[len-1] == '\n'))
       {
           p2[len-1] = '\0';
       }
       if(len>=2&&(p2[len-2] == '\r'||p2[len-2] == '\n'))
       {
           p2[len-1] = '\0';
       }
       len = strlen(p2);
       if(len == 0)
       {
           continue;
       }
       opcode = parse_token(buffer);
       if(opcode == oBadOption)
       {
           continue;
       }
       switch(opcode)
       {
            case oEnable:
                strcpy(urlcap_config.enable,p2);
                break;
            case oFtpHost:
                strcpy(urlcap_config.ftp_host,p2);
                break;
            case oFtpPwd:
                strcpy(urlcap_config.ftp_pwd,p2);
                break;
            case oFtpUser:
                strcpy(urlcap_config.ftp_user,p2);
                break;
            case oFtpPassword:
                strcpy(urlcap_config.ftp_password,p2);
                break;
            case oHosts:
                strcpy(urlcap_config.hosts,p2);
                break;
            case oInterface:
                strcpy(urlcap_config.dev,p2);
                break;
            case oCity:
                strcpy(urlcap_config.city,p2);
                break;
            case oCompany:
                strcpy(urlcap_config.company,p2);
                break;
            case oUserDefine:
                strcpy(urlcap_config.userdefine,p2);
                break;
            default:
                break;
       }
   }
   
   err = 0;
error:
   if(fd)
   {
       fclose(fd);
   }
   if(err)
   {
       return -1;
   }
   return 0;
}
