#ifndef SYSLOG_H
#define SYSLOG_H

#include "lwip/sockets.h"


#define LOGBUF_LENGTH 128

typedef struct{
    char ip[16];
    int port;
    int socket;
    struct sockaddr_in servaddr;
}Syslog;


#define locprintf( fmt, args... ) \
            do {\
                            printf( "(%s:%d): "fmt, strrchr(__FILE__,'/') , __LINE__,##args);\
                        } while(0)

#define remoprintf( fmt, args... ) \
            do {\
                            char logbuf[LOGBUF_LENGTH];\
                            int size;\
                            size=snprintf( logbuf,sizeof(logbuf),"(%s:%d): "fmt, strrchr(__FILE__,'/') , __LINE__,##args);\
                            SyslogSend( logbuf , size ); \
                        } while(0)

#define logprintf( fmt, args... ) \
            do {\
                            char logbuf[LOGBUF_LENGTH];\
                            snprintf( logbuf,sizeof(logbuf),"(%s:%d): "fmt, strrchr(__FILE__,'/') , __LINE__,##args);\
                            SyslogSend( logbuf , strlen(logbuf) ); \
                            printf( "(%s:%d): "fmt ,strrchr(__FILE__,'/') , __LINE__, ##args ); \
                        } while(0)

#define halt( fmt , args... ) \
            do {\
                            char logbuf[LOGBUF_LENGTH];\
                            snprintf( logbuf,sizeof(logbuf),"(%s:%d): "fmt, strrchr(__FILE__,'/') , __LINE__,##args);\
                            SyslogSend( logbuf , strlen(logbuf) ); \
                            printf( "[HALT] (%s:%d): "fmt ,strrchr(__FILE__,'/') , __LINE__, ##args ); \
                            while(1);\
                        } while(0)

#define errnologprintf( fmt, args... ) \
    do {\
        int backuped_errno=errno;\
        char errstr[32];\
        char logbuf[LOGBUF_LENGTH];\
        strerror_r( backuped_errno , errstr, sizeof(errstr));\
        snprintf( logbuf,sizeof(logbuf),"ERROR (%s:%d): errno=%d,errmsg=%s "fmt, strrchr(__FILE__,'/') , __LINE__,backuped_errno , errstr ,##args);\
        SyslogSend( logbuf , strlen(logbuf) ); \
        printf("%s\n",logbuf); \
    } while(0)

Syslog *SyslogDial( char *ip , int port );
int SyslogSend( char *data , int size );

#endif

