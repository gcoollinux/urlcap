/*
 * =====================================================================================
 *
 *       Filename:  urlcap.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2014年11月15日 11时43分01秒
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
#include <strings.h>
#include <curl/curl.h>
#include <pcap.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <pthread.h>
#include <unistd.h>

#include <signal.h>
/* for unix socket communication */
#include <sys/types.h>
#include <sys/un.h>

/* for wait() */
#include <sys/wait.h>

#include <sys/stat.h>
#include "list.h"
#include "config.h"
#include "urlcap.h"






/******************** GLOBAL START ****************************/
struct UrlcapConfig urlcap_config;
struct Queue file_queue;
pthread_mutex_t file_mutex =  PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  file_cond  =  PTHREAD_COND_INITIALIZER;
long get_packet_count = 0;
long post_packet_count  = 0;
long data_packet_count = 0;
long other_packet_count = 0;
pthread_t cap_tid;
pthread_t save_tid;
/******************** GLOBAL END ******************************/

void time_filename(char *filename,int len,HttpType http_type)
{
    time_t timep;
    struct tm *tmp;

    if(filename == NULL||len <= 1)
    {
        return;
    }

    switch(http_type)
    {
        case http_get:
            get_packet_count++;
            break;
        case http_post:
            post_packet_count++;
            break;
        case http_data:
            data_packet_count++;
            break;
        default:
            other_packet_count++;
            break;
    }
    time(&timep);
    tmp = localtime(&timep);
    switch(http_type)
    {
        case http_get:
            snprintf(filename,len-1,"%s_%s_%s_GET_%d_%d_%d_%d:%d:%d_%ld.pcap",
                    urlcap_config.city,urlcap_config.company,urlcap_config.userdefine,
                    (1900+tmp->tm_year),(1+tmp->tm_mon),
                    tmp->tm_mday,tmp->tm_hour,tmp->tm_min,tmp->tm_sec,get_packet_count);
            break;
        case http_post:
            snprintf(filename,len-1,"%s_%s_%s_POST_%d_%d_%d_%d:%d:%d_%ld.pcap",
                    urlcap_config.city,urlcap_config.company,urlcap_config.userdefine,
                    (1900+tmp->tm_year),(1+tmp->tm_mon),
                    tmp->tm_mday,tmp->tm_hour,tmp->tm_min,tmp->tm_sec,post_packet_count);
            break;
        case http_data:
            snprintf(filename,len-1,"%s_%s_%s_DATA_%d_%d_%d_%d:%d:%d_%ld.pcap",
                    urlcap_config.city,urlcap_config.company,urlcap_config.userdefine,
                    (1900+tmp->tm_year),(1+tmp->tm_mon),
                    tmp->tm_mday,tmp->tm_hour,tmp->tm_min,tmp->tm_sec,data_packet_count);
            break;
         default:
            snprintf(filename,len-1,"%s_%s_%s_%d_%d_%d_%d:%d:%d_%ld.pcap",
                    urlcap_config.city,urlcap_config.company,urlcap_config.userdefine,
                    (1900+tmp->tm_year),(1+tmp->tm_mon),
                    tmp->tm_mday,tmp->tm_hour,tmp->tm_min,tmp->tm_sec,other_packet_count);
            break;
    }
}

static void convert_hosts_filter(char *filter,int len)
{
    int slen = 0;
    char *p1 = NULL;
    char *host = NULL;
    char *port = NULL;
    char *hosts = NULL;
    char *hostfilter = NULL;
    char *hostfilter1 = NULL;
    char *p2 = NULL; //host
    char *p3 = NULL; //port
    
    hostfilter = (char*)malloc(MAX_BUFFER_LEN);
    if(!hostfilter)
        return;
    memset(hostfilter,0x00,MAX_BUFFER_LEN);
    hostfilter1 = (char*)malloc(MAX_BUFFER_LEN);
    if(!hostfilter1)
        return;
    memset(hostfilter1,0x00,MAX_BUFFER_LEN);
    hosts = strdup(urlcap_config.hosts);
    p1 = strtok_r(hosts,",",&host);
    while(p1)
    {
        slen = strlen(hostfilter); 
        if(slen)
        {
            strcat(hostfilter," or ");
        }
            
        p2 = strtok_r(p1,":",&port);
        if(p2)
        {
           p3 = strtok_r(NULL,":",&port); 
           if(p3) //host
           {
              sprintf(hostfilter1,"( host %s and port %s )",p2,p3); 
           }
           else
           {
              sprintf(hostfilter1,"( host %s )",p2); 
           }
        }
        else
        {
            sprintf(hostfilter1,"( host %s )",p1); 
        }
        strcat(hostfilter,hostfilter1);
        p1 = strtok_r(NULL,",",&host);
    }
    sprintf(filter,"tcp and ( %s )", hostfilter);

    free(hosts);
    free(hostfilter);
    free(hostfilter1);
}
void* cap_thread(void *args)
{
    int err;
    int ret;

    pcap_t *handle = NULL;         /* Session handle */
    char dev[MAX_FILE_NAME_LEN];          /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
    struct bpf_program fp;      /* The compiled filter */
    char *filter_exp = NULL;
    bpf_u_int32 mask;       /* Our netmask */
    bpf_u_int32 net;        /* Our IP */
    struct pcap_pkthdr *header;  /* The header that pcap gives us */
    const u_char *packet;       /* The actual packet */
    int mstimeout = 1000;

    struct ether_header *ethptr; //以太网帧
    struct iphdr *ipptr;    //ip数据报
    struct in_addr addr;
    struct tcphdr *tcpptr;//tcp
    char *data;
    char hostbuf[500];
    char getbuf[100];
    char url[100];

    long file_size  = 0;
    char *cap_filename = NULL;
    char cap_filepath[MAX_FILE_NAME_LEN];
    time_t timep;
    HttpType http_type;
    pcap_dumper_t *cap_dumper       = NULL;
    pcap_dumper_t *cap_dumper_get   = NULL;
    pcap_dumper_t *cap_dumper_post  = NULL;
    pcap_dumper_t *cap_dumper_data  = NULL;


    filter_exp = (char*)malloc(MAX_BUFFER_LEN);
    ERROR_CHECK_GOTO(filter_exp == NULL,errno);
    convert_hosts_filter(filter_exp,MAX_BUFFER_LEN-1);
    if(strlen(filter_exp) == 0)
    {
        goto error;
    }
    /* convert hosts to filter expression */
    strncpy(dev,urlcap_config.dev,MAX_FILE_NAME_LEN-1);
    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
        goto error;
    }
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, mstimeout, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        goto error;
    }
    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        goto error;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        goto error;
    }
    while(1)
    {
        ret = pcap_next_ex(handle,&header,&packet);
        if(!ret)
        {
            continue;
        }
        ethptr = (struct ether_header*)packet;
        tcpptr = (struct tcphdr*)(packet+sizeof(struct ether_header)+sizeof(struct iphdr));
        data = (char*)tcpptr+sizeof(struct tcphdr);
        ret = strncasecmp(data,"GET",3);
        if(!ret)
        {
            http_type = http_get;
            goto cap_write;
        }
        ret = strncasecmp(data,"POST",4);
        if(!ret)
        {
            http_type = http_post;
            goto cap_write;
        }
        ret = strncasecmp(data,"HTTP",4);
        if(!ret)
        {
            http_type = http_data;
        }
cap_write:
        if(!ret)
        {
            switch(http_type)
            {
                case http_get:
                    cap_dumper = cap_dumper_get;
                    break;
                case http_post:
                    cap_dumper = cap_dumper_post;
                    break;
                case http_data:
                    cap_dumper = cap_dumper_data;
                    break;
                default:
                    cap_dumper = NULL;
                    break;
            }
            
            /* check file list,if full,skip this packet*/
            if(!cap_dumper)
            {
                if(file_queue.count < urlcap_config.max_cache_file)
                {
                    cap_filename = (char*)malloc(MAX_FILE_NAME_LEN);
                    if(cap_filename)
                    {
                        time_filename(cap_filename,MAX_FILE_NAME_LEN,http_type);
                        snprintf(cap_filepath,MAX_FILE_NAME_LEN-1,"%s/%s",urlcap_config.tmp_dir,cap_filename);
                        switch(http_type)
                        {
                            case http_get:
                                cap_dumper_get = pcap_dump_open( handle,cap_filepath);
                                cap_dumper = cap_dumper_get;
                                break;
                            case http_post:
                                cap_dumper_post = pcap_dump_open( handle,cap_filepath);
                                cap_dumper = cap_dumper_post;
                                break;
                            case http_data:
                                cap_dumper_data = pcap_dump_open( handle,cap_filepath);
                                cap_dumper = cap_dumper_data;
                                break;
                            default:
                                cap_dumper = NULL;
                                break;
                        }
                    }
                }

            }
            else
            {
                file_size = pcap_dump_ftell(cap_dumper);
                if((file_size+header->len) >= urlcap_config.max_cache_file_size )
                {
                    pcap_dump_flush(cap_dumper);
                    pcap_dump_close(cap_dumper);
                    setQueue(&file_queue,cap_filename);
                    cap_dumper = NULL;
                    cap_filename = NULL;
                    switch(http_type)
                    {
                        case http_get:
                            cap_dumper_get = NULL;
                            break;
                        case http_post:
                            cap_dumper_post = NULL;
                            break;
                        case http_data:
                            cap_dumper_data = NULL;
                            break;
                        default:
                            break;
                    }
                    if(file_queue.count < urlcap_config.max_cache_file)
                    {
                        cap_filename = (char*)malloc(MAX_FILE_NAME_LEN);
                        if(cap_filename)
                        {
                            time_filename(cap_filename,MAX_FILE_NAME_LEN,http_type);
                            snprintf(cap_filepath,MAX_FILE_NAME_LEN-1,"%s/%s",urlcap_config.tmp_dir,cap_filename);
                            switch(http_type)
                            {
                                case http_get:
                                    cap_dumper_get = pcap_dump_open( handle,cap_filepath);
                                    cap_dumper = cap_dumper_get;
                                    break;
                                case http_post:
                                    cap_dumper_post = pcap_dump_open( handle,cap_filepath);
                                    cap_dumper = cap_dumper_post;
                                    break;
                                case http_data:
                                    cap_dumper_data = pcap_dump_open( handle,cap_filepath);
                                    cap_dumper = cap_dumper_data;
                                    break;
                                default:
                                    cap_dumper = NULL;
                                    break;
                            }
                        }
                    }
                }
            }
            if(cap_dumper)
            {
                pcap_dump((u_char *)cap_dumper,header,packet);
                pcap_dump_flush(cap_dumper);
            }
        }
    }
error:
    if(filter_exp)
    {
        free(filter_exp);
        filter_exp = NULL;
    }
    if(cap_dumper)
    {
        pcap_dump_close(cap_dumper);
    }
    if(handle)
    {
        pcap_close(handle);
    }
    return NULL;
}

void save_cap_ftp()
{
    int         ret;
    int         err;
    CURLcode    res;
    CURL       *curl = NULL;
    FILE       *resource_file_fp;
    int         resource_file_size = 0;
    char        login_str[255];
    char        *user_name = NULL;
    char        *password = NULL;
    char        ftp_url[1024];
    struct stat stat_buf;
    char filepath[MAX_FILE_NAME_LEN];
    char *filename = NULL;


    filename = getQueue(&file_queue);
    if(!filename)
    {
        return;
    }
    snprintf(filepath,MAX_FILE_NAME_LEN,"%s/%s",urlcap_config.tmp_dir,filename);
#ifdef DEBUG
    printf("ftp %s\n",filepath);
#endif
    snprintf(ftp_url,1024,"ftp://%s/%s/%s",urlcap_config.ftp_host,
            urlcap_config.ftp_pwd,filename);
    user_name = urlcap_config.ftp_user;
    password =  urlcap_config.ftp_password;
    ret = stat(filepath,&stat_buf); /* stat */
    ERROR_CHECK_GOTO(ret,errno);
    resource_file_size = stat_buf.st_size;
    resource_file_fp = fopen(filepath, "r");
    ERROR_CHECK_GOTO(resource_file_fp==NULL,errno);
    /* curl init */
    curl = curl_easy_init();
    ERROR_CHECK_GOTO(curl==NULL,errno);
    snprintf(login_str, 255, "%s:%s", user_name,password);
    curl_easy_setopt(curl, CURLOPT_URL, ftp_url);
    curl_easy_setopt(curl, CURLOPT_USERPWD, login_str);
#ifdef DEBUG
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
#endif
    curl_easy_setopt(curl, CURLOPT_READDATA, resource_file_fp);
    curl_easy_setopt(curl, CURLOPT_INFILESIZE, resource_file_size);
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1);
    curl_easy_setopt(curl, CURLOPT_FTP_CREATE_MISSING_DIRS, 0);
    res = curl_easy_perform(curl);
    ERROR_CHECK_GOTO(res,errno);
    ret = unlink(filepath);
    ERROR_CHECK_GOTO(ret,errno);
    ret = 0;
error:
    if(curl)
    {
        curl_easy_cleanup(curl);
    }
    if(filename)
    {
        free(filename);
        filename = NULL;
    }
    if(resource_file_fp)
    {
        fclose(resource_file_fp);
        resource_file_fp = NULL;
    }
    return;
}

void* save_thread(void *args)
{
    struct timespec timeout;
    CURLcode     res;

    res = curl_global_init(CURL_GLOBAL_ALL);
    ERROR_CHECK_GOTO(res,errno);

    timeout.tv_sec = time(NULL)+10;
    timeout.tv_nsec = 0;
    while(1)
    {
        save_cap_ftp();
        pthread_mutex_lock(&file_mutex);
        pthread_cond_timedwait(&file_cond,&file_mutex,&timeout);
        pthread_mutex_unlock(&file_mutex);
    }
error:
    curl_global_cleanup();
    return NULL;
}

void sig_term(int signo)
{
    if(signo == SIGTERM)
    {
        exit(0);
    }
}
static void init_signal(vid)
{
    signal(SIGTERM,sig_term);
}


int main(int argc,char *argv[])
{
    int err;
    int *ret;
    pid_t pid;


    /*********** DAEMON FORK ********************/
    pid = fork();
    if(pid < 0)
        exit(1);
    if(pid != 0)/*parent*/
        exit(0);
    setsid();
    /*  
    chdir("/");
    umask(0);
    close(0);
    close(1);
    close(2);
    */

    init_signal();

    initQueue(&file_queue);
    /*********** READ CONFIG START **********************/
    init_config();
    err = read_config();
    if(err)
    {
        fprintf(stderr,"Read config file failed.\n");
        goto error;
    }
    err = strncasecmp(urlcap_config.enable,"1",1);
    if(err)
    {
        printf("%s stoped manual .\n",argv[0]);
        goto error;
    }
    /*********** READ CONFIG END ************************/
    err = pthread_create(&cap_tid,NULL,cap_thread,NULL);
    ERROR_CHECK_GOTO(err,err);
    err = pthread_create(&save_tid,NULL,save_thread,NULL);
    ERROR_CHECK_GOTO(err,err);

    err = pthread_join(cap_tid,(void **)&ret);
    ERROR_CHECK_GOTO(err,err);
    err = pthread_join(save_tid,(void **)&ret);
    ERROR_CHECK_GOTO(err,err);

error:
    desQueue(&file_queue);
    return 0;
}
