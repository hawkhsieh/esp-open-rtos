/* http_get_mbedtls - HTTPS version of the http_get example, using mbed TLS.
 *
 * Retrieves a JSON response from the howsmyssl.com API via HTTPS over TLS v1.2.
 *
 * Validates the server's certificate using the root CA loaded (in PEM format) in cert.c.
 *
 * Adapted from the ssl_client1 example in mbedtls.
 *
 * Original Copyright (C) 2006-2015, ARM Limited, All Rights Reserved, Apache 2.0 License.
 * Additions Copyright (C) 2015 Angus Gratton, Apache 2.0 License.
 */
#include "espressif/esp_common.h"
#include "esp/uart.h"

#include <string.h>

#include "FreeRTOS.h"
#include "task.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"
#include "lwip/api.h"

#include "ssid_config.h"

/* mbedtls/config.h MUST appear before all other mbedtls headers, or
   you'll get the default config.

   (Although mostly that isn't a big problem, you just might get
   errors at link time if functions don't exist.) */
#include "mbedtls/config.h"

#include "mbedtls/net.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"


#include "syslog.h"
#include "start_link.h"
#include "memory.h"

//#include "asdJson.h"
#include "string_utility.h"
#include "fsm.h"

#define AES_BLOCK_SIZE 16


#define WEB_SERVER "api.dch.dlink.com"
#define WEB_PORT "443"

/* Root cert for howsmyssl.com, stored in cert.c */
extern const char *server_root_cert;

/* MBEDTLS_DEBUG_C disabled by default to save substantial bloating of
 * firmware, define it in
 * examples/http_get_mbedtls/include/mbedtls/config.h if you'd like
 * debugging output.
 */
#ifdef MBEDTLS_DEBUG_C


/* Increase this value to see more TLS debug details,
   0 prints nothing, 1 will print any errors, 4 will print _everything_
*/
#define DEBUG_LEVEL 4

static void my_debug(void *ctx, int level,
                     const char *file, int line,
                     const char *str)
{
    ((void) level);

    /* Shorten 'file' from the whole file path to just the filename

       This is a bit wasteful because the macros are compiled in with
       the full _FILE_ path in each case, so the firmware is bloated out
       by a few kb. But there's not a lot we can do about it...
    */
    char *file_sep = rindex(file, '/');
    if(file_sep)
        file = file_sep+1;

    logprintf("%s:%04d: %s", file, line, str);
}
#endif

xTaskHandle xHandle;

/*
    .domainname="dch.dlink.com:443",
    .country_code="WW",
    .agent_version="",
*/

typedef struct{

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_x509_crt cacert;
    mbedtls_ssl_config conf;

}TLSConnect;

void TLSConnect_Free( TLSConnect *conn , mbedtls_net_context *fd )
{
    mbedtls_ssl_session_reset(&conn->ssl);
    mbedtls_net_free( fd );
/*
    mbedtls_x509_crt_free( &conn->cacert );
    mbedtls_ssl_free( &conn->ssl );
    mbedtls_ssl_config_free( &conn->conf );
    mbedtls_ctr_drbg_free( &conn->ctr_drbg );
    mbedtls_entropy_free( &conn->entropy );*/
}

int TLSConnect_Init( TLSConnect *conn )
{
    const char *pers = "ssl_client1";
    int ret;
    /*
     * 0. Initialize the RNG and the session data
     */
    mbedtls_ssl_init(&conn->ssl);
    mbedtls_x509_crt_init(&conn->cacert);
    mbedtls_ctr_drbg_init(&conn->ctr_drbg);
    logprintf("\n  . Seeding the random number generator...");

    mbedtls_ssl_config_init(&conn->conf);

    mbedtls_entropy_init(&conn->entropy);
    if((ret = mbedtls_ctr_drbg_seed(&conn->ctr_drbg, mbedtls_entropy_func, &conn->entropy,
                                    (const unsigned char *) pers,
                                    strlen(pers))) != 0)
    {
        logprintf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        while(1) {} /* todo: replace with abort() */
    }

    logprintf(" ok\n");

    /*
     * 0. Initialize certificates
     */
    logprintf("  . Loading the CA root certificate ...");

    ret = mbedtls_x509_crt_parse(&conn->cacert, (uint8_t*)server_root_cert, strlen(server_root_cert)+1);
    if(ret < 0)
    {
        logprintf(" failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret);
        while(1) {} /* todo: replace with abort() */
    }

    logprintf(" ok (%d skipped)\n", ret);

    /* Hostname set here should match CN in server certificate */
    if((ret = mbedtls_ssl_set_hostname(&conn->ssl, WEB_SERVER)) != 0)
    {
        logprintf(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
        while(1) {} /* todo: replace with abort() */
    }

    /*
     * 2. Setup stuff
     */
    logprintf("  . Setting up the SSL/TLS structure...");

    if((ret = mbedtls_ssl_config_defaults(&conn->conf,
                                          MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        logprintf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit;
    }

    logprintf(" ok\n");

    /* OPTIONAL is not optimal for security, in this example it will print
       a warning if CA verification fails but it will continue to connect.
    */
    mbedtls_ssl_conf_authmode(&conn->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&conn->conf, &conn->cacert, NULL);
    mbedtls_ssl_conf_rng(&conn->conf, mbedtls_ctr_drbg_random, &conn->ctr_drbg);
#ifdef MBEDTLS_DEBUG_C
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
    mbedtls_ssl_conf_dbg(&conn->conf, my_debug, stdout);
#endif

    if((ret = mbedtls_ssl_setup(&conn->ssl, &conn->conf)) != 0)
    {
        logprintf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }

    /* Wait until we can resolve the DNS for the server, as an indication
       our network is probably working...
    */
    logprintf("Waiting for server DNS to resolve... ");
    err_t dns_err;
    ip_addr_t host_ip;
    do {
        vTaskDelay(500 / portTICK_RATE_MS);
        dns_err = netconn_gethostbyname(WEB_SERVER, &host_ip);
    } while(dns_err != ERR_OK);
    logprintf("Internet is ok!!\n");
    return 0;

exit:
    TLSConnect_Free( conn , 0 );
    return -1;
}

int TLSConnect_SendReq( TLSConnect *conn , char *request , int request_len , char *response , int response_len )
{
    int ret=0,len=0;
    logprintf("HTTP get task starting...\n");

    uint32_t flags;
    mbedtls_net_context server_fd;


        mbedtls_net_init(&server_fd);
        logprintf("heap=%u\n", xPortGetFreeHeapSize());
        /*
         * 1. Start the connection
         */
        logprintf("  . Connecting to %s:%s...\n", WEB_SERVER, WEB_PORT);

        if((ret = mbedtls_net_connect(&server_fd, "54.64.145.83",
                                      WEB_PORT, MBEDTLS_NET_PROTO_TCP)) != 0)
        {
            logprintf(" failed\n  ! mbedtls_net_connect returned %d\n\n", ret);
            goto exit;
        }

        logprintf(" ok\n");

        mbedtls_ssl_set_bio(&conn->ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

        /*
         * 4. Handshake
         */
        logprintf("  . Performing the SSL/TLS handshake...\n");

        while((ret = mbedtls_ssl_handshake(&conn->ssl)) != 0)
        {
            if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
            {
                logprintf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret);
                goto exit;
            }
        }
        logprintf("heap=%u\n", xPortGetFreeHeapSize());

        logprintf(" ok\n");

        /*
         * 5. Verify the server certificate
         */
        logprintf("  . Verifying peer X.509 certificate...\n");

        /* In real life, we probably want to bail out when ret != 0 */
        if((flags = mbedtls_ssl_get_verify_result(&conn->ssl)) != 0)
        {
            char vrfy_buf[512];

            logprintf(" failed\n");

            mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);

            logprintf("%s\n", vrfy_buf);
        }
        else
            logprintf(" ok\n");
        logprintf("heap=%u\n", xPortGetFreeHeapSize());

        /*
         * 3. Write the GET request
         */
        logprintf("  > Write to server:\n");
#if 0
        char ip[INET_ADDRSTRLEN];
        int port;
        Network_getInBoundIp( server_fd.fd , ip , &port);
        logprintf("connect to %s:%d\n",ip,port);
#endif
        while((ret = mbedtls_ssl_write(&conn->ssl, (const unsigned char *)request, request_len)) <= 0)
        {
            if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
            {
                logprintf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
                goto exit;
            }
        }
        logprintf("heap=%u\n", xPortGetFreeHeapSize());

//        logprintf("++++request(%d bytes written)++++\n",ret);
//        printHunk( (char*)request , ret , LOGBUF_LENGTH );

        /*
         * 7. Read the HTTP response
         */
        logprintf("  < Read from server:\n");

        do
        {
            ret = mbedtls_ssl_read(&conn->ssl, (unsigned char *)response, response_len );
            logprintf("heap=%u\n", xPortGetFreeHeapSize());

            if(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
                continue;

            if(ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                ret = 0;
                break;
            }

            if(ret < 0)
            {
                logprintf("failed\n  ! mbedtls_ssl_read returned %d\n\n", ret);
                break;
            }

            if(ret == 0)
            {
                logprintf("\n\nEOF\n\n");
                break;
            }

            len = ret;
            break;

        } while(1);

        mbedtls_ssl_close_notify(&conn->ssl);

    exit:

        TLSConnect_Free( conn , &server_fd );

        if ( ret < 0 ){
            char error_buf[100];
            mbedtls_strerror(ret, error_buf, 100);
            logprintf("\n\nLast error was: %d - %s\n\n", ret, error_buf);
        }else
            ret=len;

#if 0
        int countdown;
        for(countdown = successes ? 3 : 1; countdown >= 0; countdown--) {
            logprintf("%d... ", countdown);
            vTaskDelay(1000 / portTICK_RATE_MS);
        }
        logprintf("\nStarting again!\n");
#endif
    return ret;

}

void sleep( int second )
{
    vTaskDelay( second / portTICK_RATE_MS);
}



String getJson( void *data,size_t len )
{
    String json_string;
    bzero(&json_string,sizeof(String));
    char *json = strchr((char*)data,'{');
    char *end_json = strrchr((char*)data,'}');
    if ( end_json ) *(end_json+1)=0;
    else{
        goto ERROR;
    }
    STRING_LinkString(&json_string , json , strlen(json));
ERROR:
    return json_string;
}

typedef struct
{
    char http_buf[HTTP_REQUEST_MAXLEN];
    TLSConnect conn;
    FSM fsm;

}Linkd;
#if JSON
char *agent_bind_keys[] = { "p","status",0};

typedef struct{
    char *p;
    char *status;
}AgentBind;

int AgentBind_Assign(char **data, void *globol_context , void *local_context )
{
    KeyValue *key_value = (KeyValue *)globol_context;
    AgentBind *agent_bind = (AgentBind*)asdJsonFSM_GetData(data);

    if ( strcmp( key_value->key , "p") == 0 ){
        agent_bind->p=key_value->value;
    }else if( strcmp( key_value->key , "status") == 0 ){
        agent_bind->status = key_value->value;
    }

    return 0;
}
#endif


int agent_bind(char **data, void *globol_context , void *local_context )
{
    Linkd *linkd_inst=(Linkd *)*data;

    TLSConnect *conn = &linkd_inst->conn;
    char *http_buf=linkd_inst->http_buf;

    logprintf("heap=%u\n", xPortGetFreeHeapSize());

    logprintf( "linkd_inst=%x\n",linkd_inst);
    logprintf( "%u %u\n",linkd_inst->conn.entropy.accumulator.total[0] ,linkd_inst->conn.entropy.accumulator.total[1]);
    char *body = malloc(512);
    int body_len=getBingAgentBody(body,512);
    int http_buf_len=snprintf( http_buf , HTTP_REQUEST_MAXLEN ,
                               "POST /agent/bind HTTP/1.1\r\n"\
                               "Host: api.dch.dlink.com:443\r\n"\
                               "Content-Type: application/x-www-form-urlencoded\r\n"\
                               "Content-Length: %d\r\n\r\n%s" , body_len , body );
    free(body);
    int ret;
    ret = TLSConnect_SendReq( conn , http_buf , http_buf_len , (char *)http_buf , http_buf_len );

    if(ret <= 0){
        halt("agent/bind failed\n");
    }
    logprintf("++++request(%d bytes read)++++\n",ret);
    printHunk( (char*)http_buf , ret , LOGBUF_LENGTH );

#if 0
    AgentBind agent_bind_json;
    transition perform_trans={0, FUNCTION(AgentBind_Assign),   1,-1, ACCEPT };

    char *httu_buf_json = getJson( http_buf , ret );
    if ( httu_buf_json == 0 )
    asdJsonFSM_Parse( http_buf , &agent_bind_json , &perform_trans , agent_bind_keys );


    logprintf("p:%s\n",agent_bind_json.p);
    logprintf("status:%s\n",agent_bind_json.status);
#endif
    return 0;
}

int get_relay(char **data, void *globol_context , void *local_context )
{
    return 0;
}


int rs_connect(char **data, void *globol_context , void *local_context )
{
    return 0;
}

int supervisor(char **data, void *globol_context , void *local_context )
{
    return 0;
}


typedef enum{
    AGENT_BIND,
    SERIVCE_GET_RELAY,
    RS_CONNECT,
    RS_SUPERVISOR
}LinkdStatus;

transition linkd_transition[] = {
    {AGENT_BIND, FUNCTION(agent_bind),       AGENT_BIND,AGENT_BIND, ACCEPT },
    #if 0
    {AGENT_BIND, FUNCTION(agent_bind),       SERIVCE_GET_RELAY,AGENT_BIND, ACCEPT },
    {SERIVCE_GET_RELAY, FUNCTION(get_relay), RS_CONNECT       ,AGENT_BIND, ACCEPT },
    {RS_CONNECT, FUNCTION(rs_connect),       RS_CONNECT       ,SERIVCE_GET_RELAY, ACCEPT },
    {RS_SUPERVISOR, FUNCTION(supervisor),    RS_SUPERVISOR    ,SERIVCE_GET_RELAY, ACCEPT },
    #endif

    {-1}
};



void http_get_task(void *param)
{
    Linkd *linkd_inst;
    linkd_inst=malloc(sizeof(Linkd));
    bzero( linkd_inst , sizeof(Linkd) );

    if ( TLSConnect_Init( &linkd_inst->conn ) )
        halt("TLSConnect_Init\n");

//    linkd_inst->http_buf = malloc(HTTP_REQUEST_MAXLEN);
//    linkd_inst->conn=malloc(sizeof(TLSConnect));

    run_fsm( &linkd_inst->fsm  , linkd_transition , (char**)&linkd_inst , NULL , NULL, NULL);


#if defined TEST
    while(1){

#if 1
        int successes = 0, failures = 0;

        char *body = malloc(512);
        int body_len=getBingAgentBody(body,512);
        int http_buf_len=snprintf( http_buf , HTTP_REQUEST_MAXLEN ,
                                  "POST /agent/bind HTTP/1.1\r\n"\
                                  "Host: api.dch.dlink.com:443\r\n"\
                                  "Content-Type: application/x-www-form-urlencoded\r\n"\
                                  "Content-Length: %d\r\n\r\n%s" , body_len , body );
        free(body);

        logprintf("request_len=%d\n",http_buf_len);
#else
        strcpy(http_buf,"GET /ok.html HTTP/1.1\r\nHost: api.dch.dlink.com\r\n\r\n");
        int http_buf_len=strlen(http_buf);
#endif
        logprintf("heap=%u\n", xPortGetFreeHeapSize());

        int ret;
        ret = TLSConnect_SendReq( conn , http_buf , http_buf_len , (char *)http_buf , http_buf_len );

        logprintf("heap=%u\n", xPortGetFreeHeapSize());


        if(ret <= 0){
            failures++;
        } else {
            successes++;

            logprintf("++++request(%d bytes read)++++\n",ret);
            printHunk( (char*)http_buf , ret , LOGBUF_LENGTH );
        }

        logprintf("successes = %d failures = %d\n", successes, failures);
    }
#endif
}

void user_init(void)
{
    SyslogDial("54.169.15.38",514);

    uart_set_baud(0, 115200);
    logprintf("SDK version:%s\n", sdk_system_get_sdk_version());

    struct sdk_station_config config = {
        .ssid = WIFI_SSID,
        .password = WIFI_PASS,
    };

    /* required to call wifi_set_opmode before station_set_config */
    sdk_wifi_set_opmode(STATION_MODE);
    sdk_wifi_station_set_config(&config);

    xTaskCreate(&http_get_task, (signed char *)"get_task", 1500 ,  NULL , 2, &xHandle );
}
