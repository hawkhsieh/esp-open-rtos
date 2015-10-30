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


#include "log_control.h"
//#include "start_link.h"
//#include "rly_client.h"
#include "build_request.h"
#include "fetch_response.h"
#include "memory.h"
//#include "asdResponse.h"
//#include "asdUART.h"
#include "asdJson.h"
#include "string_utility.h"
#include "fsm.h"
#include <inttypes.h>


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


typedef struct{
    FSM fsm;
    transition *trans;
    char http_buf[HTTP_REQUEST_MAXLEN];
    TLSConnect conn;
    char *app_data;
}HTTPS;

typedef struct
{
    FSM fsm;
    char *relay_server;
    char *hash;
    HTTPS https;
}Linkd;


int TLSConnect_Write( TLSConnect *conn , char *data ,int data_len )
{
    int ret;
    while((ret = mbedtls_ssl_write( &conn->ssl, (const unsigned char *)data, data_len)) <= 0)
    {
        if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            logprintf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
            break;
        }
    }
    return ret;
}

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

int TLSConnect_SendReq( HTTPS *https , char *url , char *request , int request_len , char *response , int response_len )
{
    int ret=0,len=0;
    logprintf("HTTP get task starting...\n");

    uint32_t flags;
    mbedtls_net_context server_fd;


        mbedtls_net_init(&server_fd);
        /*
         * 1. Start the connection
         */
        logprintf("  . Connecting to %s:%s...\n", url , WEB_PORT);
        logprintf("heap=%u\n", xPortGetFreeHeapSize());

        if((ret = mbedtls_net_connect(&server_fd, url ,
                                      WEB_PORT, MBEDTLS_NET_PROTO_TCP)) != 0)
        {
            logprintf("[ERROR] mbedtls_net_connect returned %d\n\n", ret);
            goto exit;
        }

        logprintf(" ok\n");

        mbedtls_ssl_set_bio(&https->conn.ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

        /*
         * 4. Handshake
         */
        logprintf("  . Performing the SSL/TLS handshake...\n");
        logprintf("heap=%u\n", xPortGetFreeHeapSize());

        while((ret = mbedtls_ssl_handshake(&https->conn.ssl)) != 0)
        {
            if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
            {
                logprintf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret);
                sleep(1);
                continue;
            }
        }
        logprintf("heap=%u\n", xPortGetFreeHeapSize());

        logprintf(" ok\n");

        /*
         * 5. Verify the server certificate
         */
        logprintf("  . Verifying peer X.509 certificate...\n");

        /* In real life, we probably want to bail out when ret != 0 */
        if((flags = mbedtls_ssl_get_verify_result(&https->conn.ssl)) != 0)
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
        while((ret = mbedtls_ssl_write(&https->conn.ssl, (const unsigned char *)request, request_len)) <= 0)
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
            logprintf("heap=%u\n", xPortGetFreeHeapSize());

            ret = mbedtls_ssl_read(&https->conn.ssl, (unsigned char *)&response[len], response_len-len );

            logprintf("read=%d\n", ret );

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

            len += ret;

            logprintf("https->trans=%p\n",https->trans);

            if (https->trans){
                int fsm_ret =run_fsm( &https->fsm , https->trans , &response , https ,0,0);
                logprintf("fsm_ret=%d\n",fsm_ret);
                if ( fsm_ret == 0 )
                    break;
            }
            else
                break;

        } while(1);

        mbedtls_ssl_close_notify(&https->conn.ssl);

    exit:
        TLSConnect_Free( &https->conn , &server_fd );

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

unsigned int sleep( unsigned int second )
{
    vTaskDelay( second / portTICK_RATE_MS);
    return 0;
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


typedef struct{
    char *p;
    char *iv;
    char *status;
    char *errmsg;
    char *errno_json;

}EncryptResponse;

int EncryptResponse_Assign(char **data, void *globol_context , void *local_context )
{
    KeyValue *key_value = (KeyValue *)globol_context;
    EncryptResponse *agent_bind = (EncryptResponse*)asdJsonFSM_GetData(data);

    if ( strcmp( key_value->key , "p") == 0 ){
        agent_bind->p=key_value->value;
    }else if( strcmp( key_value->key , "status") == 0 ){
        agent_bind->status = key_value->value;
    }else if( strcmp( key_value->key , "iv") == 0 ){
        agent_bind->iv = key_value->value;
    }

    return 0;
}




int LinkdEncryptRequest( HTTPS *https , char *http_buf , int http_buf_len, EncryptResponse *response )
{
    logprintf("heap=%u\n", xPortGetFreeHeapSize());

    int ret;
    ret = TLSConnect_SendReq( https , "54.64.145.83" , http_buf , http_buf_len , (char *)http_buf , HTTP_REQUEST_MAXLEN );

    if(ret <= 0){
        halt("TLSConnect_SendReq failed\n");
    }
    logprintf("++++request(%d bytes read)++++\n",ret);
    printHunk( (char*)http_buf , ret , LOGBUF_LENGTH );
    transition perform_trans={0, FUNCTION(EncryptResponse_Assign),   1,-1, ACCEPT };
    String http_buf_json = getJson( http_buf , ret );
    if ( http_buf_json.point == 0 ){
        logprintf("[ERROR] json format is invalid\n" );
        return -1;
    }
    char *agent_bind_keys[] = { "p","status","iv",0};
    asdJsonFSM_Parse( &http_buf_json , response , &perform_trans , agent_bind_keys );

    return 0;
}


int agent_bind(char **data, void *globol_context , void *local_context )
{
    Linkd *linkd_inst=(Linkd *)*data;

    char *body = malloc(512);
    int body_len=getBingAgentBody(body,512);
    int http_buf_len=snprintf( linkd_inst->https.http_buf , HTTP_REQUEST_MAXLEN ,
                               "POST /agent/bind HTTP/1.1\r\n"\
                               "Host: api.dch.dlink.com\r\n"\
                               "Content-Type: application/x-www-form-urlencoded\r\n"\
                               "Content-Length: %d\r\n\r\n%s" , body_len , body );
    free(body);

    logprintf( "++++full request++++\n");
    printHunk( (char *)linkd_inst->https.http_buf , http_buf_len , LOGBUF_LENGTH );

    EncryptResponse agent_bind_json;
    bzero(&agent_bind_json,sizeof(EncryptResponse));


    LinkdEncryptRequest( &linkd_inst->https ,linkd_inst->https.http_buf , http_buf_len ,&agent_bind_json);

    logprintf("p:%s\n",agent_bind_json.p);
    logprintf("status:%s\n",agent_bind_json.status);

    return 0;
}




int get_relay(char **data, void *globol_context , void *local_context )
{

    Linkd *linkd_inst=(Linkd *)*data;
    logprintf("POST /agent/relay/get\n");
    logprintf("relay_server=%p,hash=%p\n",linkd_inst->relay_server,linkd_inst->hash);

    free( linkd_inst->relay_server );linkd_inst->relay_server=0;
    free( linkd_inst->hash );linkd_inst->hash=0;

    char *body = malloc(512);
    int body_len=getRelayBody(body,512);
    int http_buf_len=snprintf( linkd_inst->https.http_buf , HTTP_REQUEST_MAXLEN ,
                               "POST /agent/relay/get HTTP/1.1\r\n"\
                               "Host: api.dch.dlink.com\r\n"\
                               "Content-Type: application/x-www-form-urlencoded\r\n"\
                               "Content-Length: %d\r\n\r\n%s" , body_len , body );

    free(body);
    EncryptResponse response;
    bzero(&response,sizeof(EncryptResponse));

    if ( LinkdEncryptRequest( &linkd_inst->https ,linkd_inst->https.http_buf , http_buf_len ,&response) )
    {
        logprintf("errno:%s\n",response.errno_json );
        logprintf("errmsg:%s\n",response.errmsg);
        return -1;
    }

//    logprintf("p:%s\n",response.p);
//    logprintf("iv:%s\n",response.iv);
//    logprintf("status:%s\n",response.status);

    String p,iv;
    STRING_LinkString(&p,response.p,strlen(response.p));
    STRING_LinkString(&iv,response.iv,strlen(response.iv));

    String url,hash;
    decrypt_relay_url( &p , &iv , &url , &hash);

    linkd_inst->relay_server = url.point;
    linkd_inst->hash = hash.point;

    return 0;
}


#if 0

typedef struct {
    char *http_string;
    int http_string_len;
    int content_len;
    char *body;
}HttpContent;

/*
int HttpFirst(char **data, void *globol_context , void *local_context )
{
    logprintf( "+++++++ HttpFirst +++++++\n");
    HttpContent *content=(HttpContent *)globol_context;
    content->http_string_len = strlen(*data);
    content->http_string = *data;
    return 0;
}

int HttpContentLength(char **data, void *globol_context , void *local_context )
{
    logprintf( "+++++++ HttpContentLength +++++++\n");
#define CONTENT_LENGTH "ContentLength: "
    HttpContent *content=(HttpContent *)globol_context;
    char *content_length_str = strstr_bmh( *data , content->http_string_len ,CONTENT_LENGTH,sizeof(CONTENT_LENGTH)-1);
    if ( content->content_len == 0 )
        return -1;

    content_length_str += sizeof(CONTENT_LENGTH)-1;
    content->content_len = atoi( content_length_str);

    return 0;
}

int HttpNoBody(char **data, void *globol_context , void *local_context )
{
    HttpContent *content=(HttpContent *)globol_context;

    if ( content->body == 0 )
        return 0;
    else
        return -1;
}

int HttpGet(char **data, void *globol_context , void *local_context )
{
    logprintf( "+++++++ HttpGet +++++++\n");

    logprintf( "data=%s\n",*data);
    if ( memcmp( *data, "GET" , 3) == 0 )
    {
        return 0;
    }else
        return -1;
}

int HttpCompleteBody(char **data, void *globol_context , void *local_context )
{
    logprintf( "+++++++ HttpCompleteBody +++++++\n");
    HttpContent *content=(HttpContent *)globol_context;

    if ( content->body == 0 )
        return -1;

    if ( strlen( content->body ) == content->content_len )
        return 0;
    else
        return -1;

}


int HttpBody(char **data, void *globol_context , void *local_context )
{
    logprintf( "+++++++ HttpBody +++++++\n");
    HttpContent *content=(HttpContent *)globol_context;
#define CRLFCRLF "\r\n\r\n"
    char *crlfcrlf = strstr_bmh( *data , strlen(*data) , CRLFCRLF ,sizeof(CRLFCRLF)-1);
    if ( crlfcrlf == 0 )
        return -1;

    content->body = crlfcrlf + sizeof(CRLFCRLF)-1;
    return 0;
}
*/

#endif




int Response400Bad( HTTPS *https , char *msg )
{

#define http_header_400_bad              "HTTP/1.1 400 Bad Request\r\n"\
                                         "Content-Type: application/json\r\n"\
                                         "Transfer-Encoding: chunked\r\n"\
                                         "Connection: close\r\n\r\n"
    String response;
    STRING_CreateString(&response , sizeof(http_header_400_bad)+32 );
    response.length = snprintf( response.point , response.alloc_size , http_header_400_bad , strlen(msg), msg );
    TLSConnect_Write( &https->conn , response.point , response.length );
    STRING_FreeString(&response);

}
int Response200OK( HTTPS *https , char *body_fmt ,  char *msg )
{

#define http_header_200_ok               "HTTP/1.1 200 OK\r\n"\
                                         "Access-Control-Allow-Origin: *\r\n"\
                                         "Content-Type: application/json\r\n"\
                                         "Transfer-Encoding: chunked\r\n\r\n"\
                                         "%x\r\n%s\r\n0\r\n\r\n"

    int msg_len=strlen(msg);
    String body;
    STRING_CreateString(&body , strlen(body_fmt)+msg_len+10 );
    body.length = snprintf( body.point , body.alloc_size , body_fmt , msg );


    String response;
    STRING_CreateString(&response , sizeof(http_header_200_ok)+body.length+32 );
    response.length = snprintf( response.point , response.alloc_size , http_header_200_ok , body.length , body.point );
    STRING_FreeString(&body);
    logprintf("%d %s\n",response.length,response.point);
    TLSConnect_Write( &https->conn , response.point , response.length );
    STRING_FreeString(&response);
    return 0;
}

int ResponseData200OK( HTTPS *https , char *msg )
{

#define http_header_200_ok               "HTTP/1.1 200 OK\r\n"\
                                         "Access-Control-Allow-Origin: *\r\n"\
                                         "Content-Type: application/json\r\n"\
                                         "Transfer-Encoding: chunked\r\n\r\n"\
                                         "%x\r\n%s\r\n0\r\n\r\n"

    String response;
    STRING_CreateString(&response , sizeof(http_header_200_ok)+32 );
    response.length = snprintf( response.point , response.alloc_size , http_header_200_ok , strlen(msg), msg );
    TLSConnect_Write( &https->conn , response.point , response.length );
    STRING_FreeString(&response);
    return 0;
}




typedef struct{
    int port;      ///[In]
    int baud_rate; ///[In]
    int start_bit; ///[In]
    int end_bit;   ///[In]
    void *uart_session;        ///[Out]

}UARTConfig;



typedef enum{
    Encoding_json_hex,
    Encoding_base64,
    Encoding_ascii,
    Encoding_max
}Encoding;


typedef struct{
    void *session;        ///[In]

    int timeout;       ///[In]
    int read_size;     ///[In]
    Encoding encoding; ///[In]

    char *buf;     ///[Out]
    int size;      ///[Out]

}UARTData;


extern char *post_uart[];

static int asdUARTData_Response( HTTPS *https , UARTData *uart_data )
{
    String hex_string;
    STRING_CreateString( &hex_string , 128 );

    int i;
    for(i=0;i<uart_data->size;i++ )
    {
        char number[16];
        int num_size;
        num_size=snprintf(number,sizeof(number),"\\u%04x,",(unsigned char)uart_data->buf[i] & 0x00ff );
        STRING_AppendString( &hex_string , number , num_size );
    }

    hex_string.point[hex_string.length-1]=0;

    logprintf("%s\n",hex_string.point);

    Response200OK( https , "{\"data\":\"%s\",\"encoding\":\"json_hex\"}" , hex_string.point );
    STRING_FreeString(&hex_string);
    return 0;
}


static void *asdUART_ParseInteger( String *first_line , char *key , int key_len )
{
    char *key_head=strstr_bmh( first_line->point , first_line->length , key , key_len );
    if ( key_head == 0 )
        goto END;

    if ( *(key_head+key_len) != '=' )
        goto END;

    char *value_head=(key_head+key_len+1);

    unsigned int value;
    sscanf( value_head , "%" PRIuPTR , &value);

    return (void *)value;
END:
    return (void *)-1;

}


static int asdUART_ParseFirstLine( String *first_line , UARTData *uart_data )
{

    uart_data->session = asdUART_ParseInteger( first_line , "session" , sizeof("session")-1);
    if ( uart_data->session == (void*)-1 )
        return -1;

    uart_data->timeout = (int)asdUART_ParseInteger( first_line , "timeout" , sizeof("timeout")-1);
    if ( uart_data->timeout == -1 )
        uart_data->timeout=1;

    uart_data->read_size = (int)asdUART_ParseInteger( first_line , "read_size" , sizeof("read_size")-1);
    if ( uart_data->read_size == -1 )
        uart_data->read_size=1;

    return 0;
}

typedef void (*asdUART_ReadFunc)(int id,void *data,size_t len);

typedef struct{

    int client_session_id;      //Linkd SDK provides an id to identify a socket of SessionHandle_st
                                //The Initial value is -1 while asdUART_Config is calling.
    UARTData uart_data;         //A record for the infomation of long polling response

}asdUART_Session;

#define MAX_PORT 1
static asdUART_Session *uart_session[MAX_PORT];

static int asdUART_GetSession( UARTData *uart_data )
{

    int i;
    for( i=0;i<MAX_PORT;i++){
        if ( uart_data->session == uart_session[i]->uart_data.session && uart_data->session )
            break;
    }
    if ( i >= MAX_PORT ){
        miiiprintf(GROUP_API,LEVEL_ERR,"session %lu is not exist\n",(long unsigned int)uart_data->session);
        return -1;
    }

    return i;
}

static int asdUARTData_Assign(char **data, void *globol_context , void *local_context )
{
    KeyValue *key_value = (KeyValue *)globol_context;
    UARTData *uart_data = (UARTData*)asdJsonFSM_GetData(data);

    if ( strcmp( key_value->key , "data") == 0 ){

        char *json_hex_char=key_value->value;
        int put_pos=0;
        unsigned int hex;
        while( sscanf( json_hex_char , "\\u%x" , &hex ) == 1 )
        {
            key_value->value[put_pos] = hex;
            put_pos++;
            json_hex_char += 7;//  \u0000,
        }
        uart_data->buf = malloc(put_pos);
        memcpy( uart_data->buf , key_value->value , put_pos );
        uart_data->size = put_pos;
    }

    return 0;
}

static int asdUART_WriteAPI( HTTPS *https,String *json , String *first_line )
{
    String response;
    bzero(&response,sizeof(String));

    UARTData uart_data;
    bzero(&uart_data,sizeof(UARTData));

    if ( asdUART_ParseFirstLine( first_line , &uart_data ) )
        return -1;
//    int s=asdUART_GetSession( &uart_data );
//    if ( s == -1 )
//        return -1;
    transition write_transition[]={
        {0, FUNCTION(asdUARTData_Assign), -1,-1, ACCEPT },
        {-1}
    };
    asdJsonFSM_Parse( json , &uart_data , write_transition , post_uart );

    int len;
    for(len=0;len<uart_data.size;len++){
        putchar(uart_data.buf[len]);
    }

    logprintf("read_size=%d\n",uart_data.read_size);

    for(len=0;len<uart_data.read_size;len++)
    {
        uart_data.buf[len] = getchar();
    }

    uart_data.size=uart_data.read_size;

    asdUARTData_Response( https , &uart_data );

    free(uart_data.buf);
    return 0;

}


int HttpProcessData(char **data, void *globol_context , void *local_context )
{
    logprintf( "HttpProcessData\n");

    HTTPS *https=(HTTPS *)globol_context;
    char *request=*data;
    String output;
    bzero(&output,sizeof(String));
    int len=strlen(*data);
    String json_string=getJson(request,len);

    char *lf=strchr(request,'\n');
    if ( lf == 0 ){
        Response400Bad( https , "No first line" );
        return -1;
    }
    *(lf-1)=0; //Mark the first line

    if ( json_string.point == 0 ){
        logprintf("no json\n");
        return -1;
    }

    String first_line;
    STRING_LinkString(&first_line , request,strlen(request));

    if ( strstr_bmh(request,len,"POST /uart/config",sizeof("POST /uart/config")-1) )
    {
        if ( json_string.point ){
    //        output = asdUART_ConfigAPI( &json_string );
        }

        Response200OK( https , "{\"status\":\"%s\"}" , "success");
    }
    else if( strstr_bmh(request,len,"POST /uart",sizeof("POST /uart")-1) )
    {
        if ( json_string.point ){
            asdUART_WriteAPI( https , &json_string , &first_line  );
        }
    }
    else if( strstr_bmh(request,len,"GET /uart?",sizeof("GET /uart?")-1) )
    {
//        output = asdUART_ReadAPI( &first_line , 0 );
//        if( strstr_bmh(request,len,"GET /uart?wait=true",sizeof("GET /uart?wait=true")-1) == 0 )
//            Api_closeSession(id);
    }

    return 0;
}

int HttpResponse(char **data, void *globol_context , void *local_context )
{
    HTTPS *https = (HTTPS *)globol_context;
    TLSConnect_Write( &https->conn , https->http_buf , strlen(https->http_buf) );

    return 0;
}



int rs_connect(char **data, void *globol_context , void *local_context )
{
    Linkd *linkd_inst=(Linkd *)*data;
    logprintf("[%s] POST /connect\n",linkd_inst->relay_server);

    char *body = malloc(512);
    int body_len=getBingAgentBody(body,512);
    char *did = "b7e15a006ea42c4246486863a96a5589";
    char *http_buf=linkd_inst->https.http_buf;
    int http_buf_len=snprintf( http_buf , HTTP_REQUEST_MAXLEN ,
                               "POST /connect HTTP/1.1\r\n"\
                               "Host: %s\r\n"\
                               "Content-Type: text\r\n\r\n"\
                               "\"did\":\"%s\"\r\n"\
                               "\"hash\":\"%s\"\r\n\r\n", linkd_inst->relay_server , did , linkd_inst->hash );
    free(body);

    printHunk( (char *)http_buf , http_buf_len , LOGBUF_LENGTH );

    int ret;
    char *column = strchr(linkd_inst->relay_server,':');
    if (column) *column=0;

    bzero(&linkd_inst->https.fsm,sizeof(FSM));

    transition trans[]={
        {0, FUNCTION(HttpProcessData),    1,-1, ACCEPT },
        {-1}
    };

    bzero(&linkd_inst->https.fsm,sizeof(FSM));
    linkd_inst->https.trans = trans;

//    HttpContent relay;
//    bzero(&relay,sizeof(HttpContent));
//    linkd_inst->https.app_data = (void*)&relay;

    ret = TLSConnect_SendReq( &linkd_inst->https ,
                              linkd_inst->relay_server ,
                              http_buf ,
                              http_buf_len ,
                              (char *)http_buf ,
                              HTTP_REQUEST_MAXLEN );

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




void http_get_task(void *param)
{
    Linkd *linkd_inst;
    linkd_inst=malloc(sizeof(Linkd));
    bzero( linkd_inst , sizeof(Linkd) );

    if ( TLSConnect_Init( &linkd_inst->https.conn ) )
        halt("TLSConnect_Init\n");

//    linkd_inst->http_buf = malloc(HTTP_REQUEST_MAXLEN);
//    linkd_inst->conn=malloc(sizeof(TLSConnect));


const transition linkd_transition[] = {
//    {AGENT_BIND, FUNCTION(agent_bind),       AGENT_BIND,AGENT_BIND, ACCEPT },

    {AGENT_BIND, FUNCTION(agent_bind),       SERIVCE_GET_RELAY,AGENT_BIND, ACCEPT },
    {SERIVCE_GET_RELAY, FUNCTION(get_relay), RS_CONNECT       ,AGENT_BIND, ACCEPT },
    {RS_CONNECT, FUNCTION(rs_connect),       RS_CONNECT       ,SERIVCE_GET_RELAY, ACCEPT },
   // {RS_SUPERVISOR, FUNCTION(supervisor),    RS_SUPERVISOR    ,SERIVCE_GET_RELAY, ACCEPT },
    {-1}
};

    run_fsm( &linkd_inst->fsm  , (transition*)linkd_transition , (char**)&linkd_inst , NULL , NULL, NULL);


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
